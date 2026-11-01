"""A single approved creation. Short DB claims; never a transaction over Drive."""
import base64
from datetime import timedelta
import json
import re

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from front.models import AgentArtifact, AgentExport, Message, Response
from front.policy import digest
from . import document_mcp as mcp
from .aliases import alias_text
from .data_views import authorize_tool
from .jobs import _base, _bytes, authorized_run, event, locked, _terminal
from .service import AgentDenied, authenticate

MIMES = {'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'pdf': 'application/pdf', 'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation'}


def export_name(name, format):
    if (not isinstance(name, str) or not 1 <= len(name) <= 120 or name in ('.', '..')
            or re.search(r'[\\/\x00-\x1f\x7f]', name) or not name.endswith('.' + format)):
        raise AgentDenied('export_name_invalid')
    return name


def writable(actor):
    if not getattr(settings, 'REGULAY_AGENT_MCP_WRITES_ENABLED', False):
        raise AgentDenied('export_disabled')
    connection, private, binding = mcp.account(actor)
    if (not connection.write_enabled or set(private) !=
            {'token', 'identity', 'folders', 'write_folder', 'account_label', 'folder_label'}
            or not isinstance(private['write_folder'], str) or not mcp.ID.fullmatch(private['write_folder'])
            or any(not isinstance(private[k], str) or not 1 <= len(private[k]) <= 160 for k in ('account_label', 'folder_label'))):
        raise AgentDenied('export_grant_required')
    return connection, private, binding


def bound(run, call):
    connection, private, permissions = writable(run.prompt.user)
    artifact = _base(run.conversation, run.job['logical_id'], run.job['base'])
    name = export_name(run.job['export_name'], artifact.format)
    expected = {'artifact_reference': str(artifact.pk), 'sha256': artifact.sha256, 'name': alias_text(run, name)}
    if call['name'] != 'save_revision' or call['args'] != expected or run.job.get('kind') != 'export':
        raise AgentDenied('export_arguments_changed')
    proposal = {'account': private['account_label'], 'folder': private['folder_label'],
        'account_reference': str(connection.pk), 'name': name, 'artifact_reference': str(artifact.pk),
        'revision': artifact.revision, 'sha256': artifact.sha256, 'bytes': len(_bytes(artifact)),
        'effect': 'create', 'preview_url': f'/chat/agent/artifacts/{artifact.pk}/download/'}
    binding = digest([run.prompt.user_id, run.prompt.company_id, str(run.pk), run.authorization_digest,
        permissions, call, proposal])
    return connection, private, artifact, proposal, binding


def propose(token, attempt, payload):
    run, _, call = authorize_tool(token, attempt, payload)
    connection, _, artifact, proposal, binding = bound(run, call.model_dump())
    with locked(token, attempt) as (run, _):
        row, created = AgentExport.objects.get_or_create(execution=run,
            defaults={'connection': connection, 'artifact': artifact, 'call': call.model_dump(),
                'proposal': json.dumps(proposal, ensure_ascii=False), 'binding': binding,
                'expires_at': timezone.now() + timedelta(minutes=10)})
        if row.binding != binding or row.expires_at <= timezone.now():
            raise AgentDenied('export_proposal_changed')
        # This flag is written ONLY after the official graph checkpoint exists.
        run.job['checkpoint_ready'] = True
        run.save(update_fields=['job'])
        if created:
            event(run, 'approval_pending', reference=str(row.pk))
    return {'status': 'authorized', 'reference': str(row.pk)}


def decide(actor, reference, payload):
    row = AgentExport.objects.get(pk=reference)
    authorized_run(actor, row.execution_id)
    run = row.execution
    if run.status != 'active' or set(payload) != {'binding', 'decision'} or payload['decision'] not in ('approve', 'reject'):
        raise AgentDenied('export_approval_invalid')
    binding = bound(run, row.call)[-1]
    if binding != row.binding or payload['binding'] != binding or row.expires_at <= timezone.now():
        raise AgentDenied('export_approval_changed')
    status = 'approved' if payload['decision'] == 'approve' else 'rejected'
    with transaction.atomic():
        from front.models import AgentExecution
        fresh = AgentExecution.objects.select_for_update().get(pk=run.pk)
        current = AgentExport.objects.select_for_update().get(pk=row.pk)
        if bound(fresh, current.call)[-1] != current.binding or current.expires_at <= timezone.now():
            raise AgentDenied('export_approval_changed')
        if current.status != 'pending':
            if current.status == status:
                return {'status': 'authorized'}  # Duplicate click has no new effect.
            raise AgentDenied('export_already_decided')
        # Cancellation/reclaim must not race approval across a stale execution.
        if fresh.status != 'active' or fresh.expires_at <= timezone.now():
            raise AgentDenied('export_execution_expired')
        current.status, current.approved_at = status, timezone.now()
        current.save(update_fields=['status', 'approved_at'])
    return {'status': 'authorized'}


def approval_state(token, attempt, payload):
    if payload:
        raise ValueError()
    run, _ = authenticate(token, attempt)
    row = AgentExport.objects.get(execution=run)
    if bound(run, row.call)[-1] != row.binding or row.expires_at <= timezone.now():
        raise AgentDenied('export_approval_changed')
    return {'status': 'authorized', 'decision': row.status}


def execute(token, attempt, payload):
    run, _, call = authorize_tool(token, attempt, payload)
    row = AgentExport.objects.get(execution=run)
    connection, private, artifact, _, binding = bound(run, call.model_dump())
    if (row.binding != binding or row.call != call.model_dump() or row.expires_at <= timezone.now()
            or row.status not in ('approved', 'intent', 'uncertain', 'completed')):
        raise AgentDenied('export_approval_required')
    if row.status == 'completed':
        return {'status': 'approved', 'reference': str(row.pk)}
    # An atomic intent claim serializes overlapping resumes on PostgreSQL too.
    with locked(token, attempt) as (fresh, _):
        claimed = AgentExport.objects.filter(pk=row.pk, status='approved', binding=binding).update(
            status='intent', intent_at=timezone.now())
        if claimed:
            event(fresh, 'export_intent', reference=str(row.pk))
    row.refresh_from_db()
    try:
        if claimed:
            reservation = mcp.call(private, 'reserve', {})
            remote = reservation.get('document')
            if not isinstance(remote, str) or not mcp.ID.fullmatch(remote):
                raise AgentDenied('export_reservation_failed')
            row.remote_id = remote
            row.save(update_fields=['remote_id'])
            # The reservation may have waited; check both lease and approval anew.
            authenticate(token, attempt)
            _, private, _, _, fresh_binding = bound(run, row.call)
            if fresh_binding != binding or row.expires_at <= timezone.now():
                raise AgentDenied('export_approval_changed')
            result = mcp.call(private, 'save_revision', {'document': remote,
                'name': json.loads(row.proposal)['name'], 'mime': MIMES[artifact.format],
                'base64': base64.b64encode(_bytes(artifact)).decode(), 'sha256': artifact.sha256})
        elif row.remote_id:
            # No creation on replay, even when a GET returns missing/ambiguous.
            result = mcp.call(private, 'reconcile', {'document': row.remote_id, 'sha256': artifact.sha256})
        else:
            result = {'matched': False}
        if result != {'matched': True}:
            raise AgentDenied('export_outcome_unknown')
    except Exception:
        AgentExport.objects.filter(pk=row.pk, status__in=['intent', 'uncertain']).update(status='uncertain')
        event(run, 'export_uncertain', reference=str(row.pk))
        return {'status': 'withheld', 'reference': str(row.pk), 'code': 'export_outcome_unknown'}
    # Capture the actual receipt even if authority was revoked during the effect.
    AgentExport.objects.filter(pk=row.pk, status__in=['intent', 'uncertain']).update(
        status='completed', finished_at=timezone.now())
    event(run, 'export_completed', reference=str(row.pk))
    authenticate(token, attempt)  # Withhold subsequent model/user delivery on revocation.
    if bound(run, row.call)[-1] != binding:
        raise AgentDenied('export_approval_changed')
    return {'status': 'approved', 'reference': str(row.pk)}


def complete(token, attempt, payload):
    if payload:
        raise ValueError()
    with locked(token, attempt) as (run, _):
        row = AgentExport.objects.get(execution=run)
        if row.status != 'completed' or run.active_call:
            raise AgentDenied('export_not_confirmed')
        if bound(run, row.call)[-1] != row.binding or row.expires_at <= timezone.now():
            raise AgentDenied('export_approval_changed')
        message = Message.objects.create(conversation=run.conversation, role='assistant',
            content='Exportación confirmada de la revisión aprobada en la carpeta autorizada.')
        Response.objects.create(prompt=run.prompt, assistant_message=message, content=message.content,
            evidence={'export': str(row.pk), 'sha256': row.artifact.sha256})
        prompt = run.prompt
        prompt.decision['verification'] = {'status': 'passed', **row.artifact.verification,
            'export_reference': str(row.pk), 'export_status': 'completed'}
        prompt.save(update_fields=['decision'])
        _terminal(run, 'completed')
    return {'status': 'completed'}


def display(run):
    row = AgentExport.objects.filter(execution=run).first()
    if not row:
        return None
    return {**json.loads(row.proposal), 'id': str(row.pk), 'binding': row.binding,
        'status': row.status, 'expires_at': row.expires_at.isoformat(),
        'decision_url': f'/chat/agent/exports/{row.pk}/decision/'}


def reconcile(token, attempt, payload):
    if payload:
        raise ValueError()
    run, _ = authenticate(token, attempt)
    row = AgentExport.objects.get(execution=run)
    if row.status not in ('intent', 'uncertain', 'completed'):
        raise AgentDenied('export_reconciliation_required')
    return execute(token, attempt, row.call)


def recover(actor, run_id):
    run = authorized_run(actor, run_id)
    row = AgentExport.objects.get(execution=run)
    if (bound(run, row.call)[-1] != row.binding or row.expires_at <= timezone.now()
            or row.status not in ('intent', 'uncertain', 'completed')):
        raise AgentDenied('export_recovery_denied')
    from front.models import AgentExecution
    with transaction.atomic():
        fresh = AgentExecution.objects.select_for_update().get(pk=run.pk)
        if fresh.status == 'queued':
            return {'status': 'authorized'}
        if fresh.status != 'interrupted' or not fresh.job.get('checkpoint_ready'):
            raise AgentDenied('export_recovery_denied')
        if AgentExecution.objects.filter(conversation=run.conversation, status__in=['queued', 'active', 'outcome_unknown']).exists():
            raise AgentDenied('agent_conversation_busy')
        fresh.status, fresh.claim_id = 'queued', None
        fresh.expires_at = timezone.now() + timedelta(seconds=60)
        fresh.save(update_fields=['status', 'claim_id', 'expires_at'])
        event(fresh, 'export_recovery')
    return {'status': 'authorized'}
