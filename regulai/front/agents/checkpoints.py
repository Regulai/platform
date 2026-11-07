"""Safe-boundary recovery. A checkpoint is data, never execution authority."""
import base64
from datetime import timedelta
import hmac
import io
import json
from pathlib import PurePosixPath
import stat
import time
import uuid
import zipfile

from django.db import transaction
from django.utils import timezone
from front.models import AgentEvent, AgentExecution, AgentInference, AgentInput, AgentOperation
from front.policy import digest
from .service import AgentDenied, _context, _validate_tool_history
from .protocol import InferenceRequest
from .checkpoint_runner import runtime_link_target
from .runtime_contract import summary_content


def watermark(run):
    return {'inferences': list(AgentInference.objects.filter(execution=run).order_by('id').values_list('id', 'status')),
        'operations': list(AgentOperation.objects.filter(execution=run).order_by('id').values_list('id', 'status'))}


def _volume(raw):
    if raw is None:
        return {'archive_bytes': 0, 'file_count': 0, 'expanded_bytes': 0}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        items = archive.infolist()
        return {'archive_bytes': len(raw), 'file_count': sum(not item.is_dir() for item in items),
            'expanded_bytes': sum(item.file_size for item in items)}


def _interval(run, row, phase, started_at, started, value, raw):
    # Server validation/read/write only. Capture and network-transfer time are
    # deliberately not inferred from adjacent UI events or called server time.
    from .event_store import append_event
    append_event(run, 'interval', **{
        'category': 'checkpoint', 'phase': phase, 'execution_id': str(run.pk),
        'attempt': str(run.attempt), 'checkpoint_id': str(row.pk),
        'started_at': started_at.isoformat(), 'completed_at': timezone.now().isoformat(),
        'duration_ms': round((time.monotonic() - started) * 1000),
        'serialized_bytes': len(row.original.encode('utf-8')),
        'message_count': len(value['messages']), **_volume(raw)})


def validate_archive(raw, budget):
    if len(raw) > budget['file_bytes']:
        raise ValueError('checkpoint_size_limit')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        items = archive.infolist()
        if len(items) > 20000 or sum(item.file_size for item in items) > budget['workspace_bytes']:
            raise ValueError('checkpoint_workspace_limit')
        if len({item.filename for item in items}) != len(items):
            raise ValueError('checkpoint_duplicate_path')
        runtime_links = set()
        for item in items:
            path = PurePosixPath(item.filename)
            mode = item.external_attr >> 16
            if (path.is_absolute() or '..' in path.parts or '\\' in item.filename or not path.parts
                    or len(item.filename) > 4096 or path.parts[0] not in ('work', 'output') or item.flag_bits & 1
                    or item.file_size > budget['file_bytes']):
                raise ValueError('checkpoint_path_denied')
            if stat.S_ISLNK(mode):
                if item.file_size > 4096:
                    raise ValueError('checkpoint_runtime_link_limit')
                runtime_link_target(archive.read(item).decode('utf-8'))
                runtime_links.add(str(path))
        if any(str(parent) in runtime_links for item in items for parent in PurePosixPath(item.filename).parents):
            raise ValueError('checkpoint_symlink_ancestor_denied')
        if archive.testzip() is not None:
            raise ValueError('checkpoint_corrupt')


def _summary(run, value):
    reference = value.get('summarization')
    completed = AgentInference.objects.filter(execution=run, status='completed',
        response__inference__purpose='compaction')
    if reference is None:
        if completed.exists():
            raise AgentDenied('checkpoint_compaction_missing')
        return None
    if (not isinstance(reference, dict) or set(reference) != {
            'cutoff_index', 'compaction_call_id', 'summary_digest'}):
        raise ValueError('Invalid checkpoint summarization')
    cutoff = reference['cutoff_index']
    if type(cutoff) is not int or not 0 < cutoff <= len(value['wire_messages']):
        raise ValueError('Invalid checkpoint summary cutoff')
    # A cut may not separate a tool request from any of its result messages.
    pending = set()
    for message in value['wire_messages'][:cutoff]:
        pending.update(call['id'] for call in message.get('tool_calls', []))
        if message['role'] == 'tool':
            pending.discard(message['tool_call_id'])
    if pending:
        raise ValueError('Checkpoint splits tool results')
    try:
        record = completed.filter(call_id=uuid.UUID(reference['compaction_call_id'])).first()
    except (ValueError, TypeError, AttributeError):
        raise ValueError('Invalid compaction identity') from None
    if not record or digest(record.response['content'].strip()) != reference['summary_digest']:
        raise AgentDenied('checkpoint_compaction_unavailable')
    # The worker may supply only an opaque receipt. The summary itself comes
    # from the completed governed inference, with the pinned SDK's wrapper.
    return {'cutoff_index': cutoff, 'summary_message': {'type': 'human', 'data': {
        'content': summary_content(record.response['content']),
        'additional_kwargs': {'lc_source': 'summarization'}}}, 'file_path': None}


def _validate_messages(payload):
    messages = payload['messages']
    if not isinstance(messages, list) or len(messages) > 1000:
        raise ValueError('Checkpoint messages limit')
    wire = []
    for message in messages:
        if not isinstance(message, dict) or message.get('type') not in ('human', 'ai', 'tool', 'system'):
            raise ValueError('Checkpoint message type')
        data = message.get('data', {})
        if not isinstance(data, dict):
            raise ValueError('Checkpoint message data')
        if data.get('additional_kwargs', {}) not in ({}, {'lc_source': 'summarization'}, {'regulay_context': 'bootstrap'}):
            raise ValueError('Checkpoint message metadata')
        if data.get('artifact') is not None or data.get('invalid_tool_calls'):
            raise ValueError('Checkpoint message payload')
        item = {'role': {'human': 'user', 'ai': 'assistant', 'tool': 'tool', 'system': 'system'}[message['type']],
            'content': data.get('content')}
        if data.get('additional_kwargs') == {'regulay_context': 'bootstrap'}:
            item['reference_context'] = 'bootstrap'
        if message['type'] == 'ai':
            item['tool_calls'] = [{key: call[key] for key in ('id', 'name', 'args')} for call in data.get('tool_calls', [])]
        if message['type'] == 'tool':
            item.update(name=data.get('name'), tool_call_id=data.get('tool_call_id'))
        wire.append(item)
    expected = InferenceRequest(call_id=str(uuid.uuid4()), messages=payload['wire_messages'])
    actual = InferenceRequest(call_id=str(uuid.uuid4()), messages=wire)
    if digest([m.model_dump() for m in actual.messages]) != digest([m.model_dump() for m in expected.messages]):
        raise ValueError('Checkpoint wire messages changed')
    return expected


def save(token, attempt, payload):
    from . import jobs
    started_at, started = timezone.now(), time.monotonic()
    version = payload.get('version', 1)
    fields = {'messages', 'wire_messages', 'archive', 'runtime_sha256'}
    if version == 2:
        fields |= {'version', 'summarization', 'workspace_runtime_sha256'}
        if 'skills' in payload:
            fields.add('skills')
    if version not in (1, 2) or set(payload) != fields:
        raise ValueError('Invalid checkpoint')
    request = _validate_messages(payload)
    if payload['archive'] is None and version != 2:
        raise ValueError('Legacy checkpoint archive required')
    raw = base64.b64decode(payload['archive'], validate=True) if payload['archive'] is not None else None
    with jobs.locked(token, attempt) as (run, _):
        if run.job.get('kind') != 'professional' or run.active_call:
            raise AgentDenied('checkpoint_requires_idle_boundary')
        _validate_tool_history(run, request)
        if run.job.get('skills') or 'skills' in payload:
            from .skill_context import validate_checkpoint_reference
            validate_checkpoint_reference(run, payload.get('skills'))
        _summary(run, payload)
        if raw is not None:
            validate_archive(raw, run.job['limits'])
        else:
            reservation = run.job.get('sandbox_reservation') or {}
            previous = AgentInput.objects.filter(execution=run, kind='checkpoint',
                pk=run.job.get('checkpoint')).first()
            if reservation.get('sandbox_id') or (previous and json.loads(previous.original).get('archive') is not None):
                raise AgentDenied('checkpoint_workspace_missing')
        mark = watermark(run)
        if any(status != 'completed' for _, status in mark['operations']) or any(
                status not in ('completed', 'rejected') for _, status in mark['inferences']):
            raise AgentDenied('checkpoint_outcome_uncertain')
        packed = json.dumps({**payload, 'watermark': mark}, ensure_ascii=False)
        row, _ = AgentInput.objects.update_or_create(execution=run, path='checkpoint/latest',
            defaults={'kind': 'checkpoint', 'original': packed, 'digest': digest(packed)})
        run.job['checkpoint'] = str(row.pk)
        run.job['checkpoint_at'] = timezone.now().isoformat()
        run.save(update_fields=['job'])
        if raw is not None:
            from .file_continuity import capture_checkpoint_files
            capture_checkpoint_files(run, raw, mark, _context(run.prompt, run.profile_id))
        _interval(run, row, 'save_server', started_at, started, payload, raw)
    return {'status': 'completed'}


def load(run):
    started_at, started = timezone.now(), time.monotonic()
    row = AgentInput.objects.filter(execution=run, kind='checkpoint', pk=run.job.get('checkpoint')).first()
    if not row or not hmac.compare_digest(digest(row.original), row.digest):
        raise AgentDenied('checkpoint_unavailable')
    value = json.loads(row.original)
    # JSON normalizes watermark tuples to lists.
    if digest(value['watermark']) != digest(watermark(run)) or run.active_call:
        raise AgentDenied('checkpoint_has_later_or_uncertain_operations')
    if value.get('version', 1) not in (1, 2):
        raise AgentDenied('checkpoint_version_unavailable')
    if run.job.get('skills') or 'skills' in value:
        from .skill_context import validate_checkpoint_reference
        validate_checkpoint_reference(run, value.get('skills'))
    summary = _summary(run, value)
    if summary:
        value['_summarization_event'] = summary
    # `resumable` also reads checkpoints for terminal-state snapshots. Those
    # capability checks must remain read-only; log only an active recovery.
    if run.status == 'active' and run.job.get('restore_checkpoint'):
        raw = base64.b64decode(value['archive'], validate=True) if value.get('archive') is not None else None
        _interval(run, row, 'restore_server', started_at, started, value, raw)
    return value


def resumable(run):
    if run.job.get('kind') != 'professional' or run.job.get('expired') or run.status not in ('interrupted', 'failed', 'cancelled'):
        return False
    try:
        load(run)
        return True
    except AgentDenied:
        return completed_final(run) is not None


def completed_final(run):
    """Reconcile only the final, protected inference after a safe checkpoint."""
    row = AgentInput.objects.filter(execution=run, kind='checkpoint', pk=run.job.get('checkpoint')).first()
    if not row or run.active_call or not hmac.compare_digest(digest(row.original), row.digest):
        return None
    value = json.loads(row.original)
    before, after = value.get('watermark', {}), watermark(run)
    earlier = before.get('inferences', [])
    if (digest(before.get('operations')) != digest(after['operations'])
            or len(after['inferences']) != len(earlier) + 1
            or digest(earlier) != digest(after['inferences'][:-1])):
        return None
    identity, status = after['inferences'][-1]
    if status != 'completed':
        return None
    record = AgentInference.objects.get(pk=identity, execution=run)
    response = record.response
    if (response.get('status') != 'completed' or response.get('tool_calls')
            or response.get('inference', {}).get('purpose') != 'generation'
            or not isinstance(response.get('content'), str)):
        return None
    return str(record.call_id)


def resume(actor, run_id):
    from . import jobs
    jobs.authorized_run(actor, run_id)
    with transaction.atomic():
        run = AgentExecution.objects.select_for_update().get(pk=run_id)
        if not resumable(run) or run.job.get('resumes', 0) >= 3:
            raise AgentDenied('checkpoint_resume_unavailable')
        if not hmac.compare_digest(_context(run.prompt, run.profile_id)[-1], run.authorization_digest):
            raise AgentDenied('authorization_changed')
        if AgentExecution.objects.filter(conversation=run.conversation, status__in=jobs.LIVE).exclude(pk=run.pk).exists():
            raise AgentDenied('agent_conversation_busy')
        # Keep the original deadline and all usage. Resume adds no free budget.
        final_call = completed_final(run)
        if not final_call and run.started_at and (timezone.now() - run.started_at).total_seconds() >= run.job['limits']['run_seconds']:
            raise AgentDenied('execution_deadline')
        run.status, run.claim_id, run.worker_id = 'queued', None, None
        run.job['resumes'] = run.job.get('resumes', 0) + 1
        run.job['restore_checkpoint'] = not bool(final_call)
        run.job.pop('reconcile_final_call_id', None)
        if final_call:
            run.job['reconcile_final_call_id'] = final_call
        run.expires_at = timezone.now() + timedelta(seconds=jobs.LEASE_SECONDS)
        run.finished_at = None
        run.save()
        jobs.event(run, 'recovered')
    return {'run': jobs.run_data(run)}
