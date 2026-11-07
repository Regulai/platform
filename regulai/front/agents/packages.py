"""Download exact registry packages before private computation; install offline."""
import base64
import hashlib
import json
import re
import time
from decimal import Decimal
from urllib.parse import quote, urlsplit

from django.conf import settings
from django.utils import timezone
from front.governance import PipelineStop
from front.models import AgentInput
from front.policy import digest
from .general_tools import operation, store_result
from .public_web import WebError, fetch
from .service import AgentDenied, _government, _totals
from .capabilities import execution_limits, call_timeout


def specifications(ecosystem, values):
    if not 1 <= len(values) <= 32 or len(set(values)) != len(values):
        raise WebError('package_count_or_duplicate')
    result = []
    for value in values:
        pattern = (r'([A-Za-z0-9][A-Za-z0-9._-]{0,79})==([0-9][A-Za-z0-9.!+_-]{0,79})' if ecosystem == 'pip'
            else r'((?:@[a-z0-9][a-z0-9._-]{0,63}/)?[a-z0-9][a-z0-9._-]{0,63})@([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?)')
        match = re.fullmatch(pattern, value)
        if not match:
            raise WebError('package_exact_version_required')
        result.append(match.groups())
    return result


def _wheel(filename):
    from packaging.utils import parse_wheel_filename
    try:
        _, _, _, tags = parse_wheel_filename(filename)
    except ValueError:
        return False
    def platform(value):
        if value in ('any', 'manylinux2014_x86_64', 'manylinux2010_x86_64', 'manylinux1_x86_64'):
            return True
        found = re.fullmatch(r'manylinux_2_(\d+)_x86_64', value)
        return bool(found and int(found[1]) <= 41)
    return any(t.interpreter in ('py3', 'py312', 'cp312') and t.abi in ('none', 'abi3', 'cp312') and platform(t.platform) for t in tags)


def prepare(ecosystem, packages, *, get):
    specs = specifications(ecosystem, packages)
    names = {re.sub('[-_.]+', '-', name).lower() for name, _ in specs}
    files, manifest = [], []
    for name, version in specs:
        if ecosystem == 'pip':
            url = f'https://pypi.org/pypi/{quote(name, safe="")}/{quote(version, safe="")}/json'
            metadata = json.loads(get(url, metadata=True)['raw'])
            if str(metadata['info']['version']) != version:
                raise WebError('package_version_mismatch')
            from packaging.requirements import Requirement
            for dependency in metadata['info'].get('requires_dist') or []:
                requirement = Requirement(dependency)
                if requirement.marker and not requirement.marker.evaluate({'python_version': '3.12', 'python_full_version': '3.12.11',
                        'sys_platform': 'linux', 'platform_system': 'Linux', 'platform_machine': 'x86_64', 'extra': ''}):
                    continue
                if re.sub('[-_.]+', '-', requirement.name).lower() not in names:
                    raise WebError('package_dependency_pin_required:' + requirement.name)
                selected_version = next(v for n, v in specs if re.sub('[-_.]+', '-', n).lower() == re.sub('[-_.]+', '-', requirement.name).lower())
                if selected_version not in requirement.specifier:
                    raise WebError('package_dependency_version_conflict')
            item = next((item for item in metadata['urls'] if item.get('packagetype') == 'bdist_wheel'
                and not item.get('yanked') and _wheel(item['filename'])), None)
            if not item or urlsplit(item['url']).hostname != 'files.pythonhosted.org':
                raise WebError('package_compatible_wheel_unavailable')
            raw = get(item['url'], metadata=False)['raw']
            if hashlib.sha256(raw).hexdigest() != item['digests']['sha256']:
                raise WebError('package_digest_mismatch')
            filename = item['filename']
        else:
            metadata = json.loads(get('https://registry.npmjs.org/' + quote(name, safe='') + '/' + quote(version, safe=''), metadata=True)['raw'])
            if metadata.get('name') != name or metadata.get('version') != version:
                raise WebError('package_version_mismatch')
            if set(metadata.get('dependencies', {})) - {n for n, _ in specs}:
                raise WebError('package_dependency_pins_required')
            dist = metadata['dist']
            if urlsplit(dist['tarball']).hostname != 'registry.npmjs.org':
                raise WebError('package_registry_denied')
            raw = get(dist['tarball'], metadata=False)['raw']
            integrity = 'sha512-' + base64.b64encode(hashlib.sha512(raw).digest()).decode()
            if dist.get('integrity') != integrity:
                raise WebError('package_digest_mismatch')
            filename = re.sub('[^a-zA-Z0-9._-]', '_', name) + '-' + version + '.tgz'
        if '/' in filename or '\\' in filename:
            raise WebError('package_filename_denied')
        entry = {'name': name, 'version': version, 'filename': filename, 'sha256': hashlib.sha256(raw).hexdigest(),
            'bytes': len(raw), 'registry': 'pypi' if ecosystem == 'pip' else 'npm'}
        manifest.append(entry)
        files.append({'path': '/workspace/work/.packages/' + filename, 'base64': base64.b64encode(raw).decode(), 'sha256': entry['sha256']})
    return {'files': files, 'manifest': manifest, 'ecosystem': ecosystem}


def execute(token, attempt, payload):
    from .data_views import authorize_tool
    run, context, call = authorize_tool(token, attempt, payload['call'])
    row = operation(run, call)
    if call.name != 'install_packages' or not getattr(settings, 'REGULAY_AGENT_PACKAGES_ENABLED', False):
        raise AgentDenied('packages_disabled')
    if run.job.get('network_sealed'):
        raise AgentDenied('private_computation_network_sealed')
    budget = execution_limits(run, context[2])
    path = 'packages/' + digest(call.id)
    prior = AgentInput.objects.filter(execution=run, path=path).first()
    if prior:
        cached = json.loads(prior.original)
        if cached.get('status') != 'completed':
            raise AgentDenied('package_download_outcome_uncertain')
        return cached
    pending = json.dumps({'status': 'started'})
    receipt = AgentInput.objects.create(execution=run, kind='package_lock', path=path, original=pending, digest=digest(pending))
    government = _government(run, context, token, attempt, str(run.active_call))
    government.destinations += ['research:packages'] if 'research:packages' in context[10].allowed_destinations else []
    used = 0
    def get(url, *, metadata):
        nonlocal used
        permitted_hosts = {'pypi.org', 'files.pythonhosted.org', 'registry.npmjs.org'}
        def authorized(target):
            if urlsplit(target).hostname not in permitted_hosts or urlsplit(target).query:
                raise WebError('package_registry_denied')
            if government.protect_texts([target], context[8])[0] != target:
                raise WebError('package_sensitive_request_denied')
            government.preflight('research:packages', context[8] + [('prompts', target)])
        authorized(url)
        record, started = government.start_call('package_download', 'research:packages', None,
            context[8] + [('prompts', url)], Decimal(0), {})
        record.update(cost='0', cost_kind='no_api_charge', cost_scope='public_registry_http_only')
        try:
            result = fetch(url, max_bytes=min(2000000 if metadata else budget['file_bytes'], budget['file_bytes'] - used),
                timeout=call_timeout(run, context[2], budget['web_seconds']), authorize=authorized)
            government.complete_call(record, started, None)
        except Exception:
            record.update(status='failed', completed_at=timezone.now().isoformat(),
                duration_ms=round((time.monotonic() - started) * 1000))
            raise
        used += len(result['raw'])
        return result
    try:
        prepared = prepare(call.args['ecosystem'], call.args['packages'], get=get)
        result = {'status': 'completed', **prepared}
        packed = json.dumps(result)
        receipt.original, receipt.digest = packed, digest(packed)
        receipt.save(update_fields=['original', 'digest'])
        # Installation happens in the sandbox. A successful download is never
        # recorded as a successful install; the worker's command result proves it.
        return result
    except (WebError, PipelineStop) as error:
        result = {'status': 'approved', 'succeeded': False, 'code': error.code if isinstance(error, PipelineStop) else str(error)}
        store_result(row, result)
        return {'status': 'completed', 'succeeded': False}
    finally:
        _totals(run.prompt)
