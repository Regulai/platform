"""General web tools, governed egress, durable evidence and truthful coverage."""
import base64
from decimal import Decimal
import io
import json
import time
from urllib.parse import urlsplit

import httpx
import yara
from django.conf import settings
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone

from front.models import AgentInput
from front.policy import digest
from front.governance import PipelineStop
from .capabilities import execution_limits, call_timeout, search_configuration
from .general_tools import operation, store_result
from .public_web import ReadableHTML, WebError, fetch, public_url
from .service import AgentDenied, _government, _totals, authenticate


def search(query, configuration, *, max_results=5, language=None, time_range=None, timeout=25, transport=None):
    """Tavily basic retrieval only. No answer inference, retries or fallback."""
    body = {'query': query + (f' (language: {language})' if language else ''), 'topic': 'general',
        'search_depth': 'basic', 'max_results': max_results, 'include_answer': False,
        'include_raw_content': False, 'include_images': False, 'auto_parameters': False, 'include_usage': True}
    if time_range:
        body['time_range'] = time_range
    with httpx.Client(transport=transport, trust_env=False, follow_redirects=False, timeout=timeout) as client:
        with client.stream('POST', 'https://api.tavily.com/search', json=body,
                headers={'Authorization': 'Bearer ' + configuration['api_key']}) as response:
            if response.status_code != 200:
                raise WebError('search_rate_limited' if response.status_code == 429 else
                    'search_credentials_rejected' if response.status_code in (401, 403) else 'search_provider_failed')
            raw = bytearray()
            for chunk in response.iter_bytes():
                raw.extend(chunk)
                if len(raw) > 1000000:
                    raise WebError('search_response_too_large')
    value = json.loads(raw)
    if not isinstance(value, dict) or not isinstance(value.get('results'), list):
        raise WebError('search_response_invalid')
    results = []
    for item in value['results'][:max_results]:
        if not isinstance(item, dict):
            raise WebError('search_response_invalid')
        try:
            url = public_url(item['url'])
        except (KeyError, WebError):
            continue
        results.append({'title': str(item.get('title', ''))[:300], 'url': url,
            'snippet': str(item.get('content', ''))[:2000], 'publication_date': item.get('published_date'),
            'opened': False, 'evidence_kind': 'search_snippet'})
    return {'results': results, 'provider': 'tavily', 'provider_inference': False,
        'pagination': 'not_supported', 'retrieved_at': timezone.now().isoformat()}


def _read(row):
    if digest(row.original) != row.digest:
        raise AgentDenied('web_evidence_digest_changed')
    return json.loads(row.original)


def _save(row, value):
    row.original = json.dumps(value, ensure_ascii=False, allow_nan=False)
    row.digest = digest(row.original)
    row.save(update_fields=['original', 'digest'])


def _extract(response, budget):
    raw, media = response['raw'], response['media_type']
    title, links, published = '', [], None
    if media == 'application/pdf' or raw.startswith(b'%PDF-'):
        from front.documents import extract_document
        document = extract_document(SimpleUploadedFile('public.pdf', raw))
        fragments = document.fragments[:budget['pdf_pages']]
        if not fragments:
            raise WebError('web_pdf_unreadable_ocr_unavailable')
        parts = [{'location': f['locator'], 'text': f['text']} for f in fragments]
        coverage = 'complete' if document.status == 'complete' and len(fragments) == document.units_total else 'partial'
        return {'title': title, 'links': links, 'publication_date': None, 'parts': parts,
            'extraction': coverage, 'warnings': [*document.warnings,
                *(['web_pdf_page_budget'] if len(document.fragments) > len(fragments) else [])], 'ocr': 'not_performed',
            'units_read': len(parts), 'units_total': document.units_total}
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeError:
        raise WebError('web_text_encoding_unsupported') from None
    if media in ('text/html', 'application/xhtml+xml') or text.lstrip().lower().startswith(('<!doctype html', '<html')):
        parser = ReadableHTML(response['final_url'])
        parser.feed(text)
        text, title, links, published = parser.text(), parser.title[:300], list(dict.fromkeys(parser.links))[:40], parser.publication_date
        if any(term in text[:2000].lower() for term in ('verify you are human', 'captcha', 'access denied')):
            raise WebError('web_access_restricted')
    elif not (media.startswith('text/') or media in ('application/json', 'application/xml', '')):
        raise WebError('web_media_requires_download')
    if not text.strip():
        raise WebError('web_empty_page_try_browser')
    lines = text.splitlines()
    parts, used = [], 0
    for number, line in enumerate(lines, 1):
        if used + len(line) > 200000:
            break
        parts.append({'location': 'line:' + str(number), 'text': line})
        used += len(line)
    return {'title': title, 'links': links, 'publication_date': published, 'parts': parts,
        'extraction': 'complete' if len(parts) == len(lines) else 'partial', 'ocr': 'not_applicable',
        'warnings': [], 'units_read': len(parts), 'units_total': len(lines)}


def _source(run, url, get, budget):
    path = 'web/' + digest(url)
    row = AgentInput.objects.filter(execution=run, path=path, kind='web_source').first()
    if row:
        return row, _read(row)
    response = get(url)
    extracted = _extract(response, budget)
    data = {k: v for k, v in response.items() if k != 'raw'}
    data.update(extracted, retrieved_at=timezone.now().isoformat(), event_date=None, read_ranges=[])
    # Retain consulted bytes encrypted alongside the extraction and its hash.
    content = base64.b64encode(response['raw']).decode()
    AgentInput.objects.create(execution=run, kind='web_bytes', path='bytes/' + digest(url),
        original=content, digest=response['sha256'])
    row = AgentInput.objects.create(execution=run, kind='web_source', path=path, original='', digest='')
    _save(row, data)
    return row, data


def _excerpt(row, source, offset, length):
    # Stable character offsets reference the full located extraction hash.
    text = '\n'.join(p['location'] + ': ' + p['text'] for p in source['parts'])
    end = min(len(text), offset + length)
    if offset > len(text):
        raise WebError('web_offset_out_of_range')
    source['read_ranges'].append([offset, end])
    source['read_ranges'] = sorted({tuple(pair) for pair in source['read_ranges']})
    _save(row, source)
    return {'status': 'approved', 'trust': 'untrusted_source_text', 'reference': str(row.pk),
        **{k: source[k] for k in ('url', 'final_url', 'title', 'sha256', 'bytes', 'media_type',
            'retrieved_at', 'publication_date', 'updated_at', 'event_date', 'extraction', 'ocr', 'warnings', 'links')},
        'text': text[offset:end], 'location': f'chars:{offset}-{end}', 'offset': offset,
        'reading': 'complete' if offset == 0 and end == len(text) and source['extraction'] == 'complete' else 'partial',
        'total_characters': len(text), 'next_offset': end if end < len(text) else None}


# Consent rules ask the user before matching data reaches a provider. Text read from a
# public page cannot be confirmed mid-task, so those matches are masked before the model
# sees them. Blocking rules are left untouched and still stop the next inference.
MASKED = '[dato personal omitido]'
_IDENTIFIERS = {'reference', 'url', 'final_url', 'sha256'}  # Citations must keep matching sources.


def _mask_public_text(actor, result):
    from front.policy import active_rules
    rules = [rule for rule in active_rules(actor) if rule.action == 'consent' and rule.applies_to in ('prompts', 'both')]
    if not rules:
        return result
    masked = 0

    def clean(text):
        nonlocal masked
        data = text.encode('utf-8')
        spans = sorted((found.offset, found.offset + found.matched_length) for match in compiled.match(data=data, timeout=2)
                       for string in match.strings for found in string.instances)
        merged = []
        for start, end in spans:
            if merged and start <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        if not merged:
            return text
        masked += len(merged)
        out, last = bytearray(), 0
        for start, end in merged:
            out += data[last:start] + MASKED.encode()
            last = end
        return (out + data[last:]).decode('utf-8', 'replace')

    def walk(value, key=None):
        if isinstance(value, str):
            return value if key in _IDENTIFIERS else clean(value)
        if isinstance(value, list):
            return [walk(item, key) for item in value]
        if isinstance(value, dict):
            return {name: walk(item, name) for name, item in value.items()}
        return value

    try:
        compiled = yara.compile(sources={f'rule_{rule.pk}': rule.yara_rule for rule in rules}, includes=False)
        cleaned = walk(result)
    except yara.Error:
        return result  # Unmasked text still meets the gateway scan, which stops the inference.
    return {**cleaned, 'masked_personal_data': masked} if masked else result


def execute(token, attempt, payload):
    from .data_views import authorize_tool
    if not isinstance(payload, dict) or set(payload) != {'call'}:
        raise ValueError('Invalid web operation')
    run, context, call = authorize_tool(token, attempt, payload['call'])
    row = operation(run, call)
    previous = AgentInput.objects.filter(execution=run, path='web-call/' + digest(call.id)).first()
    if previous:
        cached = json.loads(previous.original)
        if cached.get('status') != 'completed':
            raise AgentDenied('web_request_outcome_uncertain')
        return cached
    pending = json.dumps({'status': 'started'})
    receipt = AgentInput.objects.create(execution=run, kind='web_receipt', path='web-call/' + digest(call.id),
        original=pending, digest=digest(pending))
    budget = execution_limits(run, context[2])
    government = _government(run, context, token, attempt, str(run.active_call))
    government.destinations = [*government.destinations, *(['research:web'] if 'research:web' in context[10].allowed_destinations else [])]
    record, started = None, None
    result, transfer = None, {}

    def permitted(value):
        # Check every outbound path/query before resolution, including redirects.
        protected = government.protect_texts([value], context[8])[0]
        if protected != value or '[[R_' in value or '[[REGULAI_' in value:
            raise WebError('web_sensitive_request_denied')
        government.preflight('research:web', context[8] + [('prompts', value)])

    def get(url):
        return fetch(url, max_bytes=budget['web_bytes'], timeout=call_timeout(run, context[2], budget['web_seconds']), authorize=permitted)

    try:
        if call.name == 'web_find':
            source_row = AgentInput.objects.get(pk=call.args['reference'], execution=run, kind='web_source')
            source = _read(source_row)
            text = '\n'.join(p['location'] + ': ' + p['text'] for p in source['parts'])
            term = call.args['term']
            if not term:
                raise WebError('web_find_term_required')
            positions, start = [], 0
            while len(positions) < 20:
                found = text.casefold().find(term.casefold(), start)
                if found < 0:
                    break
                positions.append(found)
                start = found + max(1, len(term))
            result = {'status': 'approved', 'reference': str(source_row.pk), 'matches': [
                _excerpt(source_row, source, max(0, found - 150), 600) for found in positions]}
        else:
            if not getattr(settings, 'REGULAY_AGENT_WEB_ENABLED', False):
                raise WebError('web_disabled')
            if run.job.get('network_sealed'):
                raise WebError('private_computation_network_sealed')
            value = call.args.get('query') or call.args.get('url')
            if not value:
                raise WebError('web_request_required')
            permitted(value)
            configuration = search_configuration(context[2]) if call.name == 'web_search' else None
            cost = Decimal(configuration['call_cost_bound']) if configuration else Decimal(0)
            record, started = government.start_call('web_search' if configuration else 'web_read',
                'research:web', None, context[8] + [('prompts', value)], cost, {})
            if configuration:
                record.update(provider_name='tavily', provider_inference=False, cost=None, cost_kind='unknown')
            else:
                record.update(cost='0', cost_kind='no_api_charge', cost_scope='public_http_only')
            run.prompt.save(update_fields=['decision', 'updated_at'])
            if call.name == 'web_search':
                result = {'status': 'approved', 'trust': 'untrusted_search_snippets', **search(value, configuration,
                    max_results=call.args.get('max_results', 5), language=call.args.get('language'),
                    time_range=call.args.get('time_range'), timeout=call_timeout(run, context[2], budget['web_seconds']))}
            elif call.name == 'web_open':
                source_row, source = _source(run, public_url(value), get, budget)
                result = _excerpt(source_row, source, call.args.get('offset', 0), call.args.get('limit', 12000))
            elif call.name == 'web_download':
                fetched = get(value)
                transfer = {'base64': base64.b64encode(fetched.pop('raw')).decode(), 'file_path': call.args['file_path']}
                result = {'status': 'approved', 'downloaded': True, 'opened': False, **fetched,
                    'path': call.args['file_path'], 'retrieved_at': timezone.now().isoformat()}
                raw = json.dumps(result)
                AgentInput.objects.create(execution=run, kind='web_download', path='download/' + digest(call.id), original=raw, digest=digest(raw))
            else:
                raise WebError('web_tool_unknown')
            government.complete_call(record, started, None)
            if configuration:
                # The tariff ceiling is an estimate, never a reported invoice.
                record.update(cost=str(cost), cost_kind='configured_upper_bound_estimate')
        authenticate(token, attempt)
    except (AgentDenied, PipelineStop, WebError, httpx.HTTPError, AgentInput.DoesNotExist, ValueError) as error:
        code = error.code if isinstance(error, (AgentDenied, PipelineStop)) else str(error) if isinstance(error, WebError) else 'web_unavailable'
        result = {'status': 'approved', 'succeeded': False, 'code': code, 'sources': []}
        transfer = {}
        if record:
            record.update(status='failed', completed_at=timezone.now().isoformat(),
                duration_ms=round((time.monotonic() - started) * 1000))
    finally:
        _totals(run.prompt)
    if call.name in ('web_open', 'web_find', 'web_search') and result.get('succeeded', True):
        result = _mask_public_text(run.prompt.user, result)
    store_result(row, result)
    response = {'status': 'completed', **transfer}
    packed = json.dumps(response)
    receipt.original, receipt.digest = packed, digest(packed)
    receipt.save(update_fields=['original', 'digest'])
    return response


def consulted_sources(run):
    sources = {}
    for row in AgentInput.objects.filter(execution=run, kind='web_source'):
        value = _read(row)
        if value['read_ranges']:
            sources[str(row.pk)] = {k: value[k] for k in ('url', 'final_url', 'title', 'sha256', 'retrieved_at',
                'publication_date', 'updated_at', 'read_ranges', 'extraction')}
    return sources


def source_summary(run):
    """Private viewer projection, with discovery and actual reading separated."""
    from front.models import AgentToolResult
    from .general_tools import result_view
    opened, found = {}, {}
    for row in AgentInput.objects.filter(execution=run, kind='web_source'):
        value = _read(row)
        if not value['read_ranges']:
            continue
        text = '\n'.join(p['location'] + ': ' + p['text'] for p in value['parts'])
        end = 0
        for start, stop in sorted(value['read_ranges']):
            if start > end:
                break
            end = max(end, stop)
        start, stop = value['read_ranges'][0]
        entry = {key: value.get(key) for key in ('url', 'final_url', 'title', 'retrieved_at', 'publication_date', 'updated_at', 'sha256')}
        entry.update(reference=str(row.pk), opened=True,
            reading='complete' if end >= len(text) and value['extraction'] == 'complete' else 'partial',
            excerpt=text[start:min(stop, start + 600)], locations=value['read_ranges'])
        opened[value['url']] = entry
    for row in AgentToolResult.objects.filter(execution=run):
        for item in result_view(row).get('results', []):
            if isinstance(item, dict) and item.get('url'):
                found[item['url']] = {key: item.get(key) for key in ('title', 'url', 'snippet', 'publication_date')}
                found[item['url']].update(opened=False, reading='search_result_only')
    found.update(opened)
    return list(found.values())
