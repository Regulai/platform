"""Browser network broker. Chromium itself has no network or private mounts."""
import base64
from decimal import Decimal
import json
import time

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from front.models import AgentInput, AgentOperation
from front.policy import digest
from .capabilities import execution_limits, call_timeout
from .general_tools import operation, store_result
from .public_web import WebError, fetch, public_url
from .service import AgentDenied, _government, _totals
from .web_tools import _source, _excerpt


def fetch_resource(token, attempt, payload):
    from .data_views import authorize_tool
    if set(payload) != {'call', 'url', 'request_id'}:
        raise ValueError('Invalid browser fetch')
    run, context, call = authorize_tool(token, attempt, payload['call'])
    row = operation(run, call)
    if (call.name != 'web_browse' or not getattr(settings, 'REGULAY_AGENT_BROWSER_ENABLED', False)
            or not getattr(settings, 'REGULAY_AGENT_WEB_ENABLED', False) or run.job.get('network_sealed')):
        raise AgentDenied('browser_unavailable')
    if type(payload['request_id']) is not int or not 0 <= payload['request_id'] < 50:
        raise ValueError('Browser request limit')
    path = f'browser/{digest(call.id)}/{payload["request_id"]}'
    url = public_url(payload['url'])
    budget = execution_limits(run, context[2])
    with transaction.atomic():
        row = AgentOperation.objects.select_for_update().get(pk=row.pk)
        state = json.loads(row.result) if row.result else {'status': 'browser_pending', 'requests': [], 'bytes': 0}
        previous = AgentInput.objects.filter(execution=run, path=path).first()
        if previous:
            cached = json.loads(previous.original)
            if cached['url'] != url or not cached.get('completed'):
                raise AgentDenied('browser_request_uncertain')
            return cached['response']
        if len(state['requests']) >= 50 or state['bytes'] >= budget['web_bytes']:
            raise AgentDenied('browser_resource_budget')
        state['requests'].append(url)
        store_result(row, state)
        pending = json.dumps({'url': url, 'completed': False})
        receipt = AgentInput.objects.create(execution=run, kind='browser_resource', path=path, original=pending, digest=digest(pending))
    government = _government(run, context, token, attempt, str(run.active_call))
    government.destinations += ['research:web'] if 'research:web' in context[10].allowed_destinations else []
    record, started = None, None
    def permitted(target):
        if government.protect_texts([target], context[8])[0] != target or '[[R_' in target:
            raise WebError('browser_sensitive_request_denied')
        government.preflight('research:web', context[8] + [('prompts', target)])
    try:
        permitted(url)
        record, started = government.start_call('web_browser_resource', 'research:web', None,
            context[8] + [('prompts', url)], Decimal(0), {})
        record.update(cost='0', cost_kind='no_api_charge', cost_scope='public_http_only')
        fetched = fetch(url, timeout=call_timeout(run, context[2], budget['web_seconds']), max_bytes=min(3000000, budget['web_bytes'] - state['bytes']), authorize=permitted)
        response = {'status': 'completed', 'succeeded': True, 'body': base64.b64encode(fetched['raw']).decode(),
            'headers': fetched.get('browser_headers', {}),
            'media_type': fetched['media_type'], 'url': url, 'final_url': fetched['final_url']}
        government.complete_call(record, started, None)
        state['bytes'] += fetched['bytes']
    except (WebError, ValueError) as error:
        response = {'status': 'completed', 'succeeded': False, 'code': str(error) if isinstance(error, WebError) else 'browser_fetch_failed'}
        if record:
            record.update(status='failed', duration_ms=round((time.monotonic() - started) * 1000))
    finally:
        _totals(run.prompt)
    state['requests'] = list(dict.fromkeys(state['requests']))
    if not response['succeeded']:
        state['partial'] = True
    store_result(row, state)
    packed = json.dumps({'url': url, 'completed': True, 'response': response})
    receipt.original, receipt.digest = packed, digest(packed)
    receipt.save(update_fields=['original', 'digest'])
    return response


def submit(token, attempt, payload):
    from .data_views import authorize_tool
    if set(payload) != {'call', 'url', 'html', 'limitations'}:
        raise ValueError('Invalid browser result')
    run, context, call = authorize_tool(token, attempt, payload['call'])
    row = operation(run, call)
    state = json.loads(row.result) if row.result else {}
    if call.name != 'web_browse' or public_url(payload['url']) not in state.get('requests', []):
        raise AgentDenied('browser_navigation_not_observed')
    if (not isinstance(payload['html'], str) or len(payload['html'].encode()) > 1000000
            or not isinstance(payload['limitations'], list) or len(payload['limitations']) > 20
            or any(not isinstance(item, str) or len(item) > 160 for item in payload['limitations'])):
        raise ValueError('Browser DOM size limit')
    raw = payload['html'].encode()
    from hashlib import sha256
    response = {'url': call.args['url'], 'final_url': payload['url'], 'raw': raw,
        'media_type': 'text/html', 'updated_at': None, 'sha256': sha256(raw).hexdigest(), 'bytes': len(raw), 'redirects': []}
    # A rendered DOM is separate evidence from a static HTTP response.
    source, value = _source(run, call.args['url'] + '#rendered', lambda _: response, execution_limits(run, context[2]))
    if state.get('partial') or payload['limitations']:
        value['extraction'] = 'partial'
        value['warnings'].append('browser_partial_resources_or_navigation')
    result = _excerpt(source, value, 0, 16000)
    result.update(renderer='isolated_chromium', browser_resources=len(state['requests']),
        limitations=payload['limitations'][:20], session='ephemeral_no_cookies')
    store_result(row, result)
    return {'status': 'completed'}
