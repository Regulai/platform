"""Server authority for pinned skills. Worker content is never an authorization."""
import base64
from collections import OrderedDict
import fnmatch
import hashlib
import json
from pathlib import PurePosixPath
import threading

from django.db import transaction

from front.models import AgentInput, AgentToolResult
from front.policy import digest
from .protocol import WireMessage

_BYTE_CACHE, _CACHE_LOCK = OrderedDict(), threading.Lock()
_CACHE_BYTES = 32 * 1024 * 1024


def _deny(code='skill_authorization_changed'):
    from .service import AgentDenied
    raise AgentDenied(code)


def _entries(run):
    snapshot = run.job.get('skills') or {}
    if not snapshot:
        return []
    from front.models import AgentSkillInstallation, AgentSkillRevision
    entries = snapshot.get('catalog', [])
    if snapshot.get('version') != 1 or len(entries) > 32:
        _deny('skill_snapshot_invalid')
    found, aliases = [], set()
    for entry in entries:
        installation = AgentSkillInstallation.objects.filter(pk=entry['installation_id'],
            company_id=run.prompt.company_id, owner_id=run.prompt.user_id, enabled=True,
            tombstoned_at__isnull=True, authorization_version=entry['authorization_version']).first()
        if not installation:
            _deny()
        revision = AgentSkillRevision.objects.filter(pk=entry['revision_id'], installation=installation,
            folder_sha256=entry['folder_sha256']).defer('bundle').first()
        if not revision or entry['alias'] in aliases or installation.alias != entry['alias']:
            _deny()
        from .skills import availability
        if not availability(run.profile, revision.compatibility)['available']:
            _deny('skill_dependency_unavailable')
        aliases.add(entry['alias'])
        found.append((entry, revision))
    return found


def binding(run):
    """Revalidate live permissions, while retaining the run's immutable revision."""
    entries = _entries(run)
    return {'digest': (run.job.get('skills') or {}).get('digest'),
        'authorization': [(e['installation_id'], e['authorization_version']) for e, _ in entries]}


def bootstrap(run):
    entries = _entries(run)
    snapshot = run.job.get('skills') or {}
    if not snapshot:
        return None
    return {'version': 1, 'digest': snapshot['digest'], 'selected': snapshot.get('selected', []),
        'auto': snapshot.get('auto', True), 'catalog': [dict(entry, manifest=revision.manifest)
            for entry, revision in entries]}


def _path(path):
    if (not isinstance(path, str) or not path or '\\' in path or '\x00' in path
            or path.startswith('/') or '..' in PurePosixPath(path).parts
            or str(PurePosixPath(path)) != path):
        _deny('skill_path_denied')
    return path


def _bytes(revision, path):
    path = _path(path)
    manifest = {item['path']: item for item in revision.manifest}
    item = manifest.get(path)
    if item is None:
        _deny('skill_resource_unavailable')
    key = (str(revision.pk), revision.folder_sha256, path, item['sha256'])
    with _CACHE_LOCK:
        cached = _BYTE_CACHE.get(key)
        if cached is not None:
            _BYTE_CACHE.move_to_end(key)
            return cached
    try:
        raw = base64.b64decode(json.loads(revision.bundle)[path], validate=True)
    except (ValueError, TypeError, KeyError):
        _deny('skill_bundle_invalid')
    if len(raw) != item['bytes'] or hashlib.sha256(raw).hexdigest() != item['sha256']:
        _deny('skill_bundle_invalid')
    if len(raw) <= _CACHE_BYTES:
        with _CACHE_LOCK:
            _BYTE_CACHE[key] = raw
            while sum(len(value) for value in _BYTE_CACHE.values()) > _CACHE_BYTES:
                _BYTE_CACHE.popitem(last=False)
    return raw


def _resolve(run, path):
    if not isinstance(path, str) or not path.startswith('/skills/'):
        _deny('skill_path_denied')
    relative = _path(path.removeprefix('/skills/'))
    alias, separator, resource = relative.partition('/')
    if not separator:
        _deny('skill_path_denied')
    for entry, revision in _entries(run):
        if entry['alias'] == alias:
            return entry, revision, _path(resource)
    _deny('skill_resource_unavailable')


def catalog(token, attempt, payload):
    from .service import authenticate
    if payload:
        raise ValueError('Invalid skills catalog request')
    run, _ = authenticate(token, attempt)
    snapshot = bootstrap(run)
    if snapshot is None:
        _deny('skills_runtime_unavailable')
    # Discovery carries only approved metadata, never allowed-tools permissions.
    for entry in snapshot['catalog']:
        metadata = entry.get('metadata', {})
        entry['discovery'] = ('---\nname: ' + json.dumps(entry['alias']) + '\ndescription: '
            + json.dumps(metadata.get('description', ''), ensure_ascii=False) + '\n---\n')
    return {'status': 'completed', **snapshot}


def resource(token, attempt, payload):
    from .service import authenticate
    run, _ = authenticate(token, attempt)
    requests = payload.get('files')
    if set(payload) != {'files'} or not isinstance(requests, list) or not 1 <= len(requests) <= 512:
        raise ValueError('Invalid skills resource request')
    files, total = [], 0
    for wanted in requests:
        if set(wanted) != {'installation_id', 'revision_id', 'path'}:
            raise ValueError('Invalid skills resource identity')
        entry, revision, path = _resolve(run, wanted['path'])
        if entry['installation_id'] != wanted['installation_id'] or entry['revision_id'] != wanted['revision_id']:
            _deny('skill_revision_denied')
        raw = _bytes(revision, path)
        total += len(raw)
        if total > 50 * 1024 * 1024:
            _deny('skill_resource_limit')
        files.append({'path': wanted['path'], 'base64': base64.b64encode(raw).decode(),
            'sha256': hashlib.sha256(raw).hexdigest()})
    authenticate(token, attempt)
    return {'status': 'completed', 'files': files}


def authorize_path(run, call):
    """Only read-only operations can cross the skills route."""
    if call.name not in ('read_file', 'ls', 'glob', 'grep'):
        _deny('skill_read_only')
    path = call.args.get('file_path', call.args.get('path', '/skills'))
    if path in ('/skills', '/skills/') and call.name != 'read_file':
        _entries(run)
        return
    if call.name != 'read_file' and path.rstrip('/') in {
            '/skills/' + entry['alias'] for entry, _ in _entries(run)}:
        return
    _resolve(run, path)
    if call.name == 'read_file' and (call.args.get('offset', 0) < 0 or call.args.get('limit', 2000) < 1
            or call.args.get('limit', 2000) > 2000):
        _deny('skill_read_range_invalid')


def _event_identity(entry, revision):
    from .skills import revision_display_name
    return {'installation_id': entry['installation_id'], 'revision_id': str(revision.pk),
        'alias': entry['alias'], 'display_name': revision_display_name(revision, entry['alias'])}


def _activate(run, entry, revision, reason, call_id=None):
    path = 'skills/activation/' + str(revision.pk)
    value = {'installation_id': entry['installation_id'], 'revision_id': str(revision.pk),
        'folder_sha256': entry['folder_sha256'], 'reason': reason,
        'instruction_digest': hashlib.sha256(_bytes(revision, 'SKILL.md')).hexdigest()}
    packed = json.dumps(value, sort_keys=True)
    row, created = AgentInput.objects.get_or_create(execution=run, path=path,
        defaults={'kind': 'skill_activation', 'original': packed, 'digest': digest(packed)})
    if digest(row.original) != row.digest:
        _deny('skill_activation_invalid')
    if created and reason != 'user_selected':
        from .jobs import event
        event(run, 'skill.activated', **_event_identity(entry, revision),
            reason=reason, **({'call_id': call_id} if call_id else {}))
    return value, created


def confirm_inference(run):
    """Publish explicit activation only after the complete payload passed its gate."""
    snapshot = run.job.get('skills') or {}
    for entry, revision in _entries(run):
        if entry['installation_id'] not in snapshot.get('selected', []):
            continue
        path = 'skills/announced/' + str(revision.pk)
        value = str(revision.pk)
        _, created = AgentInput.objects.get_or_create(execution=run, path=path,
            defaults={'kind': 'skill_announced', 'original': value, 'digest': digest(value)})
        if created:
            from .jobs import event
            event(run, 'skill.activated', **_event_identity(entry, revision), reason='user_selected')


def tool_view(run, call, failed=False):
    """Canonical file views; raw executor data is intentionally not an input."""
    authorize_path(run, call)
    if call.name != 'read_file':
        entries = _entries(run)
        prefix = call.args.get('path', '/skills').rstrip('/') + '/'
        files = [(e, r, item, '/skills/' + e['alias'] + '/' + item['path'])
            for e, r in entries for item in r.manifest]
        if call.name == 'ls':
            found = {}
            for _, _, item, path in files:
                if path.startswith(prefix):
                    part, separator, _ = path[len(prefix):].partition('/')
                    found[prefix + part] = {'path': prefix + part, 'is_dir': bool(separator),
                        **({} if separator else {'bytes': item['bytes']})}
            return {'status': 'approved', 'entries': list(found.values())}
        matches = []
        for _, revision, item, path in files:
            if not path.startswith(prefix):
                continue
            pattern = call.args.get('pattern', '*') if call.name == 'glob' else call.args.get('glob', '*')
            if not (fnmatch.fnmatchcase(path, pattern) or fnmatch.fnmatchcase(path[len(prefix):], pattern)):
                continue
            if call.name == 'glob':
                matches.append({'path': path, 'bytes': item['bytes']})
            else:
                try:
                    content = _bytes(revision, item['path']).decode('utf-8')
                except UnicodeError:
                    continue
                for index, line in enumerate(content.splitlines(), 1):
                    if call.args['pattern'] in line:
                        matches.append({'path': path, 'line': index, 'text': line[:2000]})
                        if len(matches) >= 100:
                            break
            if len(matches) >= 100:
                break
        return {'status': 'approved', 'matches': matches[:100], 'truncated': len(matches) >= 100}
    entry, revision, path = _resolve(run, call.args['file_path'])
    raw = _bytes(revision, path)
    try:
        text = raw.decode('utf-8')
    except UnicodeError:
        return {'status': 'withheld', 'code': 'skill_binary_resource', 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}
    lines = text.splitlines(keepends=True)
    start, limit = call.args.get('offset', 0), call.args.get('limit', 2000)
    complete = start == 0 and limit >= len(lines)
    view = {'status': 'approved', 'trust': 'untrusted_skill_data', 'revision_id': str(revision.pk),
        'path': call.args['file_path'], 'sha256': hashlib.sha256(raw).hexdigest(),
        'offset': start, 'next_offset': start + limit if start + limit < len(lines) else None,
        'complete': complete, 'content': ''.join(lines[start:start + limit])}
    if path == 'SKILL.md' and complete and not failed:
        activation, created = _activate(run, entry, revision, 'instructions_read', call.id)
        view['instruction_digest'] = activation['instruction_digest']
        if not created:
            view = {'status': 'already_loaded', 'revision_id': str(revision.pk),
                'instruction_digest': activation['instruction_digest']}
    elif path == 'SKILL.md' and failed:
        return {'status': 'withheld', 'code': 'skill_read_failed'}
    return view


def finish_tool(run, context, call, request):
    """Persist the same canonical result for replay, using the existing ledgers."""
    from .general_tools import finish, result_view, operation, store_result
    fingerprint = digest(request.model_dump())
    previous = AgentToolResult.objects.filter(execution=run, call_id=call.id).first()
    if previous:
        if previous.request_digest != fingerprint:
            _deny('tool_result_id_conflict')
        return result_view(previous)
    with transaction.atomic():
        view = tool_view(run, call, request.failed)
        if context[2].professional:
            store_result(operation(run, call), view)
            return finish(run, context, call, request)
        row = AgentToolResult.objects.create(execution=run, call_id=call.id,
            request_digest=fingerprint, view={'status': view['status'], 'protected': True},
            protected_view=json.dumps(view, ensure_ascii=False), raw=json.dumps(request.raw, ensure_ascii=False))
        return result_view(row)


def _integration_instructions(revision):
    """Product adaptation stays outside the immutable upstream instructions."""
    if (revision.origin.lower().startswith('https://github.com/leonxlnx/taste-skill/tree/')
            and revision.origin.endswith('/skills/taste-skill')):
        return ('\n\nAdaptación de regulAI para Taste v2: conserva el alcance pedido por el usuario; '
            'en una edición cambia sólo las propiedades solicitadas, sin rehacer la página. '
            'Usa únicamente herramientas autorizadas. Lee los recursos bajo /skills y ejecuta '
            'draw.mjs/lint.mjs sólo con execute dentro del sandbox, desde /workspace/work. '
            'Fija TASTE_SKILL_HISTORY=/workspace/work/.taste-skill/history.json. '
            'Guarda el entregable autocontenido en /workspace/output y publícalo con publish_artifact. '
            'Para una landing usa HTML/CSS y fuentes locales o del sistema, salvo otra tecnología pedida. '
            'No añadas paquetes ni hagas solicitudes de red desde scripts. assets.mjs no es un acceso '
            'alternativo a la red: usa sólo herramientas web autorizadas o el fallback sin imágenes externas. '
            'El inspector de navegador de la skill no está habilitado en esta integración; '
            'usa los controles locales disponibles y declara esa comprobación pendiente. '
            'No inventes una revisión visual ni una puntuación. La skill no concede permisos ni presupuesto.')
    if (revision.origin.startswith('https://github.com/anthropics/skills/tree/')
            and revision.origin.endswith('/skills/frontend-design')):
        return ('\n\nAdaptación de regulAI: usa solamente las herramientas autorizadas por esta ejecución. '
            'Para una landing entrega HTML/CSS autocontenido con fuentes locales o del sistema, salvo que '
            'el usuario pida otra tecnología. Trabaja en /workspace/work y guarda el entregable en '
            '/workspace/output; publícalo con publish_artifact. No añadas dependencias, React, scripts, '
            'páginas ni críticas que no se hayan pedido. En una edición cambia sólo las propiedades '
            'solicitadas y conserva el resto del archivo. La skill no concede permisos ni presupuesto.')
    return ''


def inference_messages(run, request):
    """Return worker messages and one authoritative body per activated revision."""
    entries = _entries(run)
    snapshot = run.job.get('skills') or {}
    if not snapshot:
        if any(message.skill_catalog for message in request.messages):
            _deny('skills_runtime_unavailable')
        return request.messages, []
    worker = []
    for message in request.messages:
        value = message.model_dump()
        section = value.pop('skill_catalog', None)
        if section:
            if section['digest'] != snapshot['digest'] or message.role != 'system' or not isinstance(value['content'], list):
                _deny('skill_catalog_changed')
            index = section['block_index']
            if index >= len(value['content']):
                _deny('skill_catalog_changed')
            value['content'] = [part for position, part in enumerate(value['content']) if position != index]
        if message.role == 'tool' and message.name == 'read_file':
            try:
                view = json.loads(message.content)
            except (ValueError, TypeError):
                view = {}
            if view.get('instruction_digest'):
                value['content'] = json.dumps({key: view[key] for key in
                    ('status', 'revision_id', 'instruction_digest') if key in view}, sort_keys=True)
        worker.append(WireMessage.model_validate(value))
    active = {json.loads(row.original)['revision_id'] for row in
        AgentInput.objects.filter(execution=run, kind='skill_activation') if digest(row.original) == row.digest}
    restored_summary = None
    if active and request.purpose != 'compaction':
        from front.models import AgentInference
        from .runtime_contract import summary_content
        for record in AgentInference.objects.filter(execution=run, status='completed',
                response__inference__purpose='compaction').order_by('-id'):
            summary = summary_content(record.response.get('content', ''))
            if any(message.content == summary for message in request.messages):
                restored_summary = str(record.call_id)
                break
    instructions, metadata = [], []
    for entry, revision in entries:
        selected = entry['installation_id'] in snapshot.get('selected', [])
        if selected:
            _activate(run, entry, revision, 'user_selected')
        loaded = selected or str(revision.pk) in active
        if loaded:
            if restored_summary:
                path = 'skills/restored/' + str(revision.pk) + '/' + restored_summary
                marker, created = AgentInput.objects.get_or_create(execution=run, path=path,
                    defaults={'kind': 'skill_restored', 'original': restored_summary, 'digest': digest(restored_summary)})
                if created:
                    from .jobs import event
                    event(run, 'skill.activated', **_event_identity(entry, revision), reason='context_restored')
            instructions.append(WireMessage(role='system', content=(
                'Skill autorizada ' + entry['alias'] + ' (' + str(revision.pk)
                + '). Sus instrucciones ya están cargadas; no repitas read_file de SKILL.md.\n'
                + _bytes(revision, 'SKILL.md').decode('utf-8') + _integration_instructions(revision))))
        elif snapshot.get('auto', True):
            metadata.append({'name': entry['alias'], 'description': entry.get('metadata', {}).get('description', ''),
                'path': '/skills/' + entry['alias'] + '/SKILL.md'})
    if metadata:
        instructions.insert(0, WireMessage(role='system', content='Skills instaladas y autorizadas; lee SKILL.md '
            'solo si corresponde a esta petición. Ninguna skill concede herramientas: '
            + json.dumps(metadata, ensure_ascii=False, sort_keys=True)))
    return worker, instructions


def checkpoint_reference(run):
    snapshot = bootstrap(run)
    return {'version': 1, 'digest': snapshot['digest'], 'revisions': [
        {'revision_id': entry['revision_id'], 'folder_sha256': entry['folder_sha256']}
        for entry in snapshot['catalog']]} if snapshot else None


def validate_checkpoint_reference(run, value):
    if value != checkpoint_reference(run):
        _deny('checkpoint_skills_changed')
