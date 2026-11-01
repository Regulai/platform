"""Selective revision continuity; encrypted manifests grant no ambient authority."""
import base64
from datetime import timedelta
import hmac
import io
import json
from pathlib import PurePosixPath
import stat
import uuid
import zipfile

from django.db import transaction
from django.db.models import Max
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from front.models import AgentArtifact, AgentInput, AgentOperation, Conversation
from front.policy import digest, evaluate_policy
from .artifact_formats import canonical, inspect_file, local_dependencies, safe_filename, safe_relative
from .service import AgentDenied

MAX_FILES = 32
EXCLUDED = {'.venv', '.packages', '.git', '__pycache__', '.cache', 'node_modules', 'checkpoints', 'tmp', 'temp'}


def expires_at(artifact):
    inherited = artifact.verification.get('origin_expires_at')
    if inherited:
        parsed = parse_datetime(inherited)
        if parsed is None or timezone.is_naive(parsed):
            raise AgentDenied('artifact_expiry_invalid')
        return parsed
    run = artifact.execution
    return (run.finished_at or run.created_at) + timedelta(days=run.job.get('limits', {}).get('retention_days', 30))


def _available(artifact):
    if not artifact.content or artifact.execution.job.get('expired') or artifact.verification.get('expired') or expires_at(artifact) <= timezone.now():
        raise AgentDenied('artifact_expired')


def delivered(artifact):
    if artifact.status != 'verified' or artifact.verification.get('purpose', 'deliverable') != 'deliverable':
        return False
    run = artifact.execution
    if artifact.verification.get('contract') != 'professional-v2':
        return run.status == 'completed'
    delivery = run.prompt.decision.get('delivery', {})
    return any(isinstance(item, dict) and item.get('artifact_id', item.get('id')) == str(artifact.pk) and item.get('sha256') == artifact.sha256
               for item in delivery.get('artifacts', [])) and delivery.get('status') in ('complete', 'partial')


def _check_policy(context, text):
    if evaluate_policy(context[0], context[8] + [('files', text)], destinations=context[7]).status != 'allow':
        raise AgentDenied('artifact_policy_denied')


def authorize_artifact(actor, artifact_id, *, conversation=None, deliverable=True):
    from . import jobs
    from .service import _context
    try:
        artifact = AgentArtifact.objects.select_related('execution__prompt', 'source').get(pk=artifact_id)
    except (AgentArtifact.DoesNotExist, ValueError, TypeError):
        raise AgentDenied('artifact_not_found') from None
    if conversation is not None and artifact.execution.conversation_id != conversation.pk:
        raise AgentDenied('artifact_not_found')
    jobs.authorized_run(actor, artifact.execution_id)
    _available(artifact)
    if deliverable and not delivered(artifact):
        raise AgentDenied('artifact_not_delivered')
    raw = jobs._bytes(artifact)
    if artifact.size_bytes is not None and artifact.size_bytes != len(raw):
        raise AgentDenied('artifact_size_changed')
    proof, text, _ = inspect_file(raw, artifact.format, budget=artifact.execution.job.get('limits'))
    if not deliverable and proof['coverage']['status'] != 'complete':
        raise AgentDenied('artifact_policy_coverage_incomplete')
    if artifact.format not in ('png', 'jpg', 'jpeg') and proof['coverage']['status'] != 'complete':
        raise AgentDenied('artifact_policy_coverage_incomplete')
    _check_policy(_context(artifact.execution.prompt, artifact.execution.profile_id, allow_disabled=True), text)
    return artifact, raw


def resolve_reference(actor, conversation, command, text, budget=None):
    from .request_contract import interpret
    if not conversation:
        if command.get('artifact_id') or command.get('base_revision'):
            raise AgentDenied('artifact_not_found')
        return None
    request = interpret(text, general=True)
    identifier = command.get('base_revision') or command.get('artifact_id')
    # A newly supplied source is the object of the edit. Only an explicit
    # revision ID may additionally select a prior artifact (and the caller then
    # rejects conflicting inputs); never require an unrelated past delivery.
    if not identifier and (command.get('file') or command.get('document_reference')):
        return None
    candidates = AgentArtifact.objects.filter(execution__conversation=conversation, status='verified').select_related('execution__prompt')
    if identifier:
        try:
            key = uuid.UUID(str(identifier))
        except (ValueError, TypeError):
            raise AgentDenied('artifact_not_found') from None
        artifact = candidates.filter(pk=key).first() or candidates.filter(logical_id=key).order_by('-revision').first()
        if not artifact:
            raise AgentDenied('artifact_not_found')
        if command.get('artifact_id') and command.get('base_revision') and str(artifact.logical_id) != str(command['artifact_id']) and str(artifact.pk) != str(command['artifact_id']):
            raise AgentDenied('artifact_reference_conflict')
        return authorize_artifact(actor, artifact.pk, conversation=conversation)[0]
    if request['operation'] not in ('edit', 'download'):
        return None
    latest = {}
    for artifact in candidates.order_by('-created_at', '-revision'):
        if not delivered(artifact):
            continue
        latest.setdefault(artifact.logical_id, artifact)
    values = list(latest.values())
    exact = [item for item in values if item.filename and item.filename.casefold() in text.casefold()]
    if exact:
        values = exact
    if len(values) != 1:
        raise AgentDenied('artifact_reference_ambiguous' if values else 'artifact_reference_missing')
    return authorize_artifact(actor, values[0].pk, conversation=conversation)[0]


def _path(value):
    path = safe_relative(value, workspace=True)
    if any(part.casefold() in EXCLUDED or part.startswith('.') for part in PurePosixPath(path).parts[1:]):
        raise ValueError('artifact_working_path_excluded')
    return path


def persist_revision(run, path, raw, proof, *, base=None, operation_id=None, purpose='working', status='draft', render=None):
    """Caller may already hold the run lock; conversation serializes path revisions."""
    path = _path(path)
    kind = canonical(PurePosixPath(path).suffix)
    operation_id = operation_id or uuid.uuid5(run.pk, 'capture:' + path + ':' + proof['sha256'])
    with transaction.atomic():
        Conversation.objects.select_for_update().get(pk=run.conversation_id)
        previous = AgentArtifact.objects.filter(execution=run, operation_id=operation_id).first()
        if previous:
            return previous
        # The same path has one logical identity throughout the conversation.
        logical = base.logical_id if base else uuid.uuid5(uuid.NAMESPACE_URL, f'regulai:{run.conversation_id}:{path}')
        latest = AgentArtifact.objects.filter(execution__conversation_id=run.conversation_id, logical_id=logical).order_by('-revision').first()
        if base and latest and latest.pk != base.pk:
            # A captured working copy of this very edit can be promoted below.
            if not (latest.execution_id == run.pk and latest.base_id == base.pk and latest.sha256 == proof['sha256']):
                raise AgentDenied('artifact_revision_stale')
        if latest and latest.sha256 == proof['sha256'] and (not base or latest.pk == base.pk or latest.base_id == base.pk):
            if latest.execution_id == run.pk and purpose == 'deliverable':
                latest.verification = {**latest.verification, **proof, 'purpose': purpose,
                    'origin_expires_at': expires_at(latest).isoformat()}
                latest.status, latest.render_bundle = status, json.dumps(render or {})
                latest.save(update_fields=['verification', 'status', 'render_bundle'])
                return latest
            if purpose == 'working' or latest.status == 'verified':
                return latest
        parent = base or latest
        expiry = expires_at(parent) if parent else run.created_at + timedelta(days=run.job.get('limits', {}).get('retention_days', 30))
        verification = {**proof, 'contract': 'professional-v2', 'purpose': purpose,
                        'origin_expires_at': expiry.isoformat(), 'origin_run': str(parent.verification.get('origin_run', parent.execution_id) if parent else run.pk)}
        return AgentArtifact.objects.create(execution=run, logical_id=logical,
            revision=(AgentArtifact.objects.filter(logical_id=logical).aggregate(n=Max('revision'))['n'] or 0) + 1,
            base=parent, source_id=run.job['manifest'], operation_id=operation_id, status=status,
            content=base64.b64encode(raw).decode(), sha256=proof['sha256'], format=kind,
            filename=safe_filename(path, kind), size_bytes=len(raw), render_bundle=json.dumps(render or {}), verification=verification)


def _entry(artifact, path, dependencies):
    return {'artifact_id': str(artifact.pk), 'logical_id': str(artifact.logical_id), 'revision': artifact.revision,
        'sha256': artifact.sha256, 'size_bytes': artifact.size_bytes, 'relative_path': _path(path),
        'purpose': artifact.verification.get('purpose', 'deliverable'), 'expires_at': expires_at(artifact).isoformat(),
        'dependencies': [{'artifact_id': str(item.pk), 'sha256': item.sha256, 'revision': item.revision} for item, _ in dependencies]}


def write_manifest(run, files, *, references=False):
    entries = [_entry(artifact, path, dependencies) for artifact, path, dependencies in files]
    if len(entries) > MAX_FILES or sum(item['size_bytes'] or 0 for item in entries) > min(20_000_000, run.job['limits']['workspace_bytes']):
        raise ValueError('artifact_continuity_limit')
    packed = json.dumps({'version': 2, 'files': entries}, ensure_ascii=False, sort_keys=True)
    hashed = digest(packed)
    row, _ = AgentInput.objects.get_or_create(execution=run, path='manifest/' + hashed,
        defaults={'kind': 'manifest', 'original': packed, 'digest': hashed})
    if not references:
        for artifact, _, dependencies in files:
            if artifact.execution_id == run.pk and (dependencies or not artifact.verification.get('manifest_id')):
                artifact.verification.update(manifest_id=str(row.pk), manifest_digest=hashed)
                artifact.save(update_fields=['verification'])
    prefix = 'references' if references else 'files'
    run.job[prefix + '_manifest'], run.job[prefix + '_digest'] = str(row.pk), hashed
    run.save(update_fields=['job'])
    return row


def read_manifest(run, *, references=False):
    prefix = 'references' if references else 'files'
    key = run.job.get(prefix + '_manifest')
    if not key:
        return []
    row = AgentInput.objects.filter(pk=key, execution=run, kind='manifest').first()
    if not row or not row.original or not hmac.compare_digest(digest(row.original), row.digest) or row.digest != run.job.get(prefix + '_digest'):
        raise AgentDenied('artifact_manifest_unavailable')
    value = json.loads(row.original)
    if value.get('version') != 2 or not isinstance(value.get('files'), list) or len(value['files']) > MAX_FILES:
        raise AgentDenied('artifact_manifest_invalid')
    return value['files']


def publication_files(run, context, decoded, main_path, related_paths):
    declared = {_path(path): path for path in [main_path, *related_paths]}
    if len(declared) != len(related_paths) + 1 or len(declared) > MAX_FILES:
        raise ValueError('artifact_dependency_limit')
    if sum(len(decoded[path]) for path in declared.values()) > min(20_000_000, run.job['limits']['workspace_bytes']):
        raise ValueError('artifact_continuity_limit')
    pending = []
    for relative, path in declared.items():
        kind = canonical(PurePosixPath(path).suffix)
        proof, text, _ = inspect_file(decoded[path], kind, budget=run.job['limits'])
        if proof['coverage']['status'] != 'complete' and path != main_path:
            raise AgentDenied('artifact_dependency_coverage_incomplete')
        _check_policy(context, text)
        dependency_check = local_dependencies(decoded[path], kind, relative, declared)
        proof['dependency_coverage'] = {key: value for key, value in dependency_check.items() if key != 'local_paths'}
        if path != main_path:
            pending.append((path, decoded[path], proof))
    return [(persist_revision(run, path, raw, proof), path) for path, raw, proof in pending]


def _selected(base):
    if base.verification.get('manifest_id'):
        row = AgentInput.objects.filter(pk=base.verification['manifest_id'], execution=base.execution, kind='manifest').first()
        if not row or not row.original or digest(row.original) != row.digest or row.digest != base.verification.get('manifest_digest'):
            raise AgentDenied('artifact_manifest_unavailable')
        value = json.loads(row.original)
        if value.get('version') != 2 or len(value.get('files', [])) > MAX_FILES:
            raise AgentDenied('artifact_manifest_invalid')
        entries = value['files']
    else:
        entries = read_manifest(base.execution)
    own = next((entry for entry in entries if entry['artifact_id'] == str(base.pk)), None)
    if own is None:
        return [(base, 'output/' + (base.filename or safe_filename('archivo', base.format)))]
    by_id = {item['artifact_id']: item for item in entries}
    selected, visited, stack = [], set(), [own]
    while stack:
        entry = stack.pop()
        if entry['artifact_id'] in visited:
            continue
        visited.add(entry['artifact_id'])
        item = AgentArtifact.objects.select_related('execution__prompt').filter(pk=entry['artifact_id'],
            execution__conversation_id=base.execution.conversation_id).first()
        if not item or item.sha256 != entry['sha256'] or item.revision != entry['revision']:
            raise AgentDenied('artifact_dependency_changed')
        selected.append((item, entry['relative_path']))
        for dependency in entry['dependencies']:
            child = by_id.get(dependency['artifact_id'])
            if not child or child['sha256'] != dependency['sha256'] or child['revision'] != dependency['revision']:
                raise AgentDenied('artifact_dependency_missing')
            stack.append(child)
    return selected


def bind_references(run, base, context):
    selected = _selected(base)
    bound = []
    for item, path in selected:
        item, raw = authorize_artifact(context[0], item.pk, conversation=run.conversation, deliverable=item.pk == base.pk)
        proof, text, _ = inspect_file(raw, item.format, budget=run.job['limits'])
        if proof['coverage']['status'] != 'complete':
            raise AgentDenied('artifact_policy_coverage_incomplete')
        _check_policy(context, text)
        packed = json.dumps({'text': text, 'artifact_id': str(item.pk), 'sha256': item.sha256,
            'expires_at': expires_at(item).isoformat(), 'extraction_digest': digest(text)}, ensure_ascii=False)
        AgentInput.objects.get_or_create(execution=run, path='policy/refs/' + str(item.pk),
            defaults={'kind': 'policy_text', 'original': packed, 'digest': digest(packed)})
        bound.append((item, path, []))
    write_manifest(run, bound, references=True)
    run.job['private_data'] = True
    run.save(update_fields=['job'])
    return len(bound)


def restore_references(run, context):
    entries = read_manifest(run, references=True)
    result, total = [], 0
    root = str(run.job.get('base') or run.pk)
    for entry in entries:
        item, raw = authorize_artifact(context[0], entry['artifact_id'], conversation=run.conversation, deliverable=False)
        if item.sha256 != entry['sha256'] or item.revision != entry['revision'] or len(raw) != entry['size_bytes']:
            raise AgentDenied('artifact_reference_changed')
        proof, text, _ = inspect_file(raw, item.format, budget=run.job['limits'])
        if proof['coverage']['status'] != 'complete':
            raise AgentDenied('artifact_policy_coverage_incomplete')
        _check_policy(context, text)
        total += len(raw)
        if total > min(20_000_000, run.job['limits']['workspace_bytes']):
            raise AgentDenied('artifact_continuity_limit')
        path = _path(entry['relative_path'])
        result.append({'path': '/workspace/input/refs/' + root + '/' + path,
            'work_path': '/workspace/work/refs/' + root + '/' + path,
            'base64': base64.b64encode(raw).decode(), 'sha256': item.sha256})
    return result


def validate_policy_reference(value, run):
    """Called at every _context revalidation; avoid recursive authorization."""
    if not value.get('artifact_id'):
        return
    item = AgentArtifact.objects.select_related('execution__prompt').filter(pk=value['artifact_id'],
        execution__conversation_id=run.conversation_id, execution__prompt__user_id=run.prompt.user_id,
        execution__prompt__company_id=run.prompt.company_id).first()
    if not item or item.sha256 != value.get('sha256') or value.get('extraction_digest') != digest(value.get('text', '')):
        raise AgentDenied('artifact_policy_reference_changed')
    _available(item)


def capture_checkpoint_files(run, raw, mark, context):
    """Capture only output and explicitly referenced completed-operation paths."""
    wanted = set()
    for operation in AgentOperation.objects.filter(execution=run, status='completed'):
        try:
            args = json.loads(operation.request).get('args', {})
        except (ValueError, TypeError):
            continue
        for name in ('file_path', 'path'):
            if isinstance(args.get(name), str):
                try:
                    wanted.add(_path(args[name]))
                except ValueError:
                    pass
    candidates, total, failures = [], 0, []
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for item in archive.infolist():
            if item.is_dir():
                continue
            try:
                path = _path(item.orig_filename)
                if not (path.startswith('output/') or path in wanted):
                    continue
                if item.flag_bits & 1 or stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG):
                    raise ValueError('artifact_capture_link_denied')
                if len(candidates) >= MAX_FILES or item.file_size > run.job['limits']['file_bytes'] or total + item.file_size > min(20_000_000, run.job['limits']['workspace_bytes']):
                    raise ValueError('artifact_continuity_limit')
                with archive.open(item) as stream:
                    data = stream.read(run.job['limits']['file_bytes'] + 1)
                proof, text, _ = inspect_file(data, PurePosixPath(path).suffix, budget=run.job['limits'])
                if proof['coverage']['status'] != 'complete':
                    raise ValueError('artifact_capture_coverage_incomplete')
                _check_policy(context, text)
                operation_id = uuid.uuid5(run.pk, 'capture:' + digest(mark) + ':' + path + ':' + proof['sha256'])
                artifact = persist_revision(run, path, data, proof, operation_id=operation_id)
                candidates.append((artifact, path, []))
                total += len(data)
            except (ValueError, AgentDenied, zipfile.BadZipFile) as exc:
                failures.append(type(exc).__name__)
    if candidates:
        # Published dependency sets remain authoritative if present.
        existing = read_manifest(run)
        retained = [(AgentArtifact.objects.get(pk=e['artifact_id']), e['relative_path'],
            [(AgentArtifact.objects.get(pk=d['artifact_id']), next(x['relative_path'] for x in existing if x['artifact_id'] == d['artifact_id'])) for d in e['dependencies']])
            for e in existing if e['purpose'] == 'deliverable']
        known = {str(item.pk) for item, _, _ in retained}
        merged = retained + [(a, p, d) for a, p, d in candidates if str(a.pk) not in known]
        write_manifest(run, merged)
    run.job['continuity'] = {'status': 'partial' if failures else 'captured', 'files': len(candidates), 'bytes': total,
                             'limitations': sorted(set(failures))}
    run.save(update_fields=['job'])
    return run.job['continuity']


def recover_member(actor, run, member, *, apply=False):
    from . import jobs
    from .service import _context
    jobs.authorized_run(actor, run.pk)
    path = _path(member)
    row = AgentInput.objects.filter(pk=run.job.get('checkpoint'), execution=run, kind='checkpoint').first()
    if not row or not row.original or not hmac.compare_digest(digest(row.original), row.digest):
        raise AgentDenied('checkpoint_unavailable_or_expired')
    if (run.finished_at or run.created_at) + timedelta(days=run.job['limits'].get('retention_days', 30)) <= timezone.now():
        raise AgentDenied('checkpoint_unavailable_or_expired')
    packed = json.loads(row.original)
    archive_bytes = base64.b64decode(packed['archive'], validate=True)
    if len(archive_bytes) > run.job['limits']['file_bytes']:
        raise AgentDenied('checkpoint_size_limit')
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        entries = [item for item in archive.infolist() if item.orig_filename == path]
        if len(entries) != 1:
            raise AgentDenied('checkpoint_member_unavailable')
        item = entries[0]
        if item.is_dir() or item.flag_bits & 1 or stat.S_IFMT(item.external_attr >> 16) not in (0, stat.S_IFREG) or item.file_size > run.job['limits']['file_bytes'] or item.file_size > max(1, item.compress_size) * 100:
            raise AgentDenied('checkpoint_member_denied')
        with archive.open(item) as stream:
            raw = stream.read(run.job['limits']['file_bytes'] + 1)
    proof, text, _ = inspect_file(raw, PurePosixPath(path).suffix, budget=run.job['limits'])
    if proof['coverage']['status'] != 'complete':
        raise AgentDenied('artifact_policy_coverage_incomplete')
    _check_policy(_context(run.prompt, run.profile_id, allow_disabled=True), text)
    preview = {'apply': apply, 'member': path, 'sha256': proof['sha256'], 'size_bytes': len(raw), 'checkpoint_digest': row.digest}
    if apply:
        with transaction.atomic():
            Conversation.objects.select_for_update().get(pk=run.conversation_id)
            jobs.authorized_run(actor, run.pk)
            key = uuid.uuid5(run.pk, 'checkpoint_file_import:' + row.digest + ':' + path + ':' + proof['sha256'])
            proof.update(provenance='checkpoint_file_import', checkpoint_digest=row.digest, automated_passed=True)
            artifact = persist_revision(run, path, raw, proof, operation_id=key, purpose='deliverable', status='verified')
            write_manifest(run, [(artifact, path, [])])
            run.prompt.refresh_from_db()
            receipt = run.prompt.decision.setdefault('delivery', {'status': 'complete', 'artifacts': []})
            entry = {'artifact_id': str(artifact.pk), 'sha256': artifact.sha256}
            if entry not in receipt['artifacts']:
                receipt['artifacts'].append(entry)
                run.prompt.save(update_fields=['decision'])
                jobs.event(run, 'verified', reference=str(artifact.pk), actor_id=actor.pk, provenance='checkpoint_file_import')
            preview['artifact_id'] = str(artifact.pk)
    return preview
