"""Governed, read-only primary-source retrieval in the trusted application.

The executor chooses reviewed catalog IDs, never URLs, queries or credentials.
Source text remains untrusted data and goes through the normal inference gateway.
Reading a source proves provenance, not the truth of every later model claim.
"""
from copy import deepcopy
from decimal import Decimal
from hashlib import sha256
from html.parser import HTMLParser
import ipaddress
import json
import re
import socket
import time
from urllib.parse import unquote, urlsplit
import uuid

import httpx
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from front.governance import PipelineStop
from front.models import AgentExecution, AgentInput
from front.policy import digest
from .aliases import alias_text
from .service import AgentDenied, _government, _totals, authenticate


MAX_SOURCES = 4
MAX_RESEARCH_CALLS = 6
MAX_BYTES = 500_000
MAX_EXCERPT = 6000
MAX_SECONDS = 40
SOURCE_ID = re.compile(r'^[a-z][a-z0-9_-]{0,63}$')
DEFAULT_CATALOG = {
    'nist-pqc': {'title': 'Post-Quantum Cryptography', 'publisher': 'NIST',
        'url': 'https://csrc.nist.gov/projects/post-quantum-cryptography', 'content_id': 'overview'},
    'nist-fips-203': {'title': 'FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard',
        'publisher': 'NIST', 'url': 'https://csrc.nist.gov/pubs/fips/203/final', 'content_id': 'body-section'},
    'nist-fips-204': {'title': 'FIPS 204: Module-Lattice-Based Digital Signature Standard',
        'publisher': 'NIST', 'url': 'https://csrc.nist.gov/pubs/fips/204/final', 'content_id': 'body-section'},
    'nist-fips-205': {'title': 'FIPS 205: Stateless Hash-Based Digital Signature Standard',
        'publisher': 'NIST', 'url': 'https://csrc.nist.gov/pubs/fips/205/final', 'content_id': 'body-section'},
}


def _url(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise AgentDenied('research_catalog_invalid')
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ''
        valid = (parsed.scheme == 'https' and not parsed.username and not parsed.password
            and parsed.port in (None, 443) and not parsed.query and not parsed.fragment
            and re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', host)
            and '.' in host and not host.endswith(('.localhost', '.local', '.internal'))
            and not any(ord(char) < 33 or ord(char) > 126 for char in value)
            and not any(ord(char) < 32 for char in unquote(parsed.path))
            and '\\' not in value)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            valid = False
        if not valid:
            raise ValueError()
    except ValueError:
        raise AgentDenied('research_catalog_invalid') from None
    return parsed


def catalog():
    """Only server configuration can extend this reviewed primary-source list."""
    configured = getattr(settings, 'REGULAY_AGENT_RESEARCH_CATALOG', DEFAULT_CATALOG)
    if not isinstance(configured, dict) or len(configured) > 64:
        raise AgentDenied('research_catalog_invalid')
    result = {}
    for key, item in configured.items():
        if (not isinstance(key, str) or not SOURCE_ID.fullmatch(key) or not isinstance(item, dict)
                or not {'title', 'publisher', 'url'} <= set(item)
                or set(item) - {'title', 'publisher', 'url', 'content_id'}
                or any(not isinstance(item[field], str) or not 1 <= len(item[field]) <= 240
                    or any(ord(char) < 32 for char in item[field]) for field in ('title', 'publisher'))):
            raise AgentDenied('research_catalog_invalid')
        if 'content_id' in item and (not isinstance(item['content_id'], str)
                or not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_-]{0,79}', item['content_id'])):
            raise AgentDenied('research_catalog_invalid')
        _url(item['url'])
        result[key] = dict(item)
    return result


def available(context):
    """Safe bootstrap metadata; a catalog listing never means it was consulted."""
    if not getattr(settings, 'REGULAY_AGENT_RESEARCH_ENABLED', False):
        return {'status': 'disabled', 'code': 'research_disabled', 'sources': []}
    if 'research_sources' not in context[2].tools:
        return {'status': 'denied', 'code': 'research_tool_not_allowed', 'sources': []}
    try:
        entries = catalog()
    except AgentDenied as error:
        return {'status': 'unavailable', 'code': error.code, 'sources': []}
    allowed = set(context[10].allowed_destinations)
    sources = [{'id': key, **item} for key, item in entries.items() if 'research:' + key in allowed]
    return {'status': 'available' if sources else 'denied', 'sources': sources,
        'code': 'research_catalog_available' if sources else 'research_destination_not_allowed'}


def validate_ids(value):
    if (not isinstance(value, list) or not 1 <= len(value) <= MAX_SOURCES
            or any(not isinstance(item, str) or not SOURCE_ID.fullmatch(item) for item in value)
            or len(set(value)) != len(value)):
        raise AgentDenied('research_ids_invalid')
    if any(item not in catalog() for item in value):
        raise AgentDenied('research_source_unknown')


def _public_address(host):
    try:
        addresses = list(dict.fromkeys(item[4][0] for item in socket.getaddrinfo(
            host, 443, type=socket.SOCK_STREAM)))
        if not addresses or any(not ipaddress.ip_address(value).is_global
                or ipaddress.ip_address(value).is_multicast for value in addresses):
            raise AgentDenied('research_address_denied')
        # Pin one public address. The later connection must not resolve the host
        # again, closing the DNS check/connect race even for configured sources.
        return next((value for value in addresses if ':' not in value), addresses[0])
    except AgentDenied:
        raise
    except (OSError, ValueError):
        raise AgentDenied('research_fetch_failed') from None


class _Text(HTMLParser):
    ignored = {'script', 'style', 'noscript', 'svg', 'nav', 'footer', 'header',
        'form', 'iframe', 'template', 'object', 'head'}
    void = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}

    def __init__(self, content_id=None):
        super().__init__(convert_charrefs=True)
        self.stack, self.parts, self.main = [], [], []
        self.content_id, self.matches = content_id, 0

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        hidden = (tag in self.ignored or 'hidden' in fields or fields.get('aria-hidden') == 'true'
            or any(value in (fields.get('style') or '').replace(' ', '').lower()
                for value in ('display:none', 'visibility:hidden')))
        selected = fields.get('id') == self.content_id if self.content_id else (
            tag in ('main', 'article') or fields.get('role') == 'main')
        if selected:
            self.matches += 1
        if tag not in self.void:
            if len(self.stack) >= 128:
                raise AgentDenied('research_html_too_complex')
            self.stack.append((tag, hidden or any(entry[1] for entry in self.stack), selected))

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def handle_data(self, data):
        if not any(item[1] for item in self.stack):
            self.parts.append(data)
            if any(item[2] for item in self.stack):
                self.main.append(data)

    def text(self):
        if self.content_id and self.matches != 1:
            raise AgentDenied('research_content_region_unavailable')
        selected = self.main if self.content_id else self.main or self.parts
        return ' '.join(' '.join(selected).split())


def fetch_source(entry, *, timeout=10, transport=None):
    """The sole HTTP boundary. Tests replace only transport and DNS resolution."""
    parsed = _url(entry['url'])
    host = parsed.hostname
    address = _public_address(host)
    target = httpx.URL(entry['url']).copy_with(host=address)
    headers = {'Host': host, 'User-Agent': 'Regulay-Primary-Source/1.0',
        'Accept': 'text/html,text/plain', 'Accept-Encoding': 'identity'}
    # httpcore's SNI extension preserves normal hostname certificate validation
    # while connecting only to the already checked public IP address.
    with httpx.Client(transport=transport or httpx.HTTPTransport(retries=0, trust_env=False),
            follow_redirects=False, trust_env=False, timeout=timeout) as client:
        with client.stream('GET', target, headers=headers, extensions={'sni_hostname': host}) as response:
            if response.status_code != 200:
                raise AgentDenied('research_http_failed')
            media = response.headers.get('content-type', '').split(';', 1)[0].strip().lower()
            if media not in ('text/html', 'text/plain'):
                raise AgentDenied('research_media_unsupported')
            if response.headers.get('content-encoding', 'identity').lower() not in ('', 'identity'):
                raise AgentDenied('research_encoding_unsupported')
            length = response.headers.get('content-length')
            if length and (not length.isdecimal() or int(length) > MAX_BYTES):
                raise AgentDenied('research_too_large')
            raw = bytearray()
            started = time.monotonic()
            for chunk in response.iter_bytes():
                if time.monotonic() - started > timeout:
                    raise AgentDenied('research_deadline_exceeded')
                raw.extend(chunk)
                if len(raw) > MAX_BYTES:
                    raise AgentDenied('research_too_large')
            try:
                content = bytes(raw).decode(response.encoding or 'utf-8', errors='strict')
            except (LookupError, UnicodeError):
                raise AgentDenied('research_decode_failed') from None
    if media == 'text/html':
        parser = _Text(entry.get('content_id'))
        parser.feed(content)
        content = parser.text()
    else:
        content = ' '.join(content.split())
    if len(content) < 80:
        raise AgentDenied('research_text_insufficient')
    return {'text': content, 'sha256': sha256(raw).hexdigest(), 'bytes': len(raw), 'media_type': media}


def _receipt(row):
    if row.kind != 'research' or digest(row.original) != row.digest:
        raise AgentDenied('research_receipt_invalid')
    try:
        value = json.loads(row.original)
        if not isinstance(value, dict) or set(value) != {'call_digest', 'view'}:
            raise ValueError()
        return value
    except (ValueError, TypeError):
        raise AgentDenied('research_receipt_invalid') from None


def _store(row, call, view):
    row.original = json.dumps({'call_digest': digest(call.model_dump()), 'view': view},
        sort_keys=True, ensure_ascii=False)
    row.digest = digest(row.original)
    row.save(update_fields=['original', 'digest'])


def execute(token, attempt, payload):
    from .data_views import authorize_tool
    if not isinstance(payload, dict) or set(payload) != {'call'}:
        raise AgentDenied('research_request_invalid')
    run, context, call = authorize_tool(token, attempt, payload['call'])
    if call.name != 'research_sources' or set(call.args) != {'ids'}:
        raise AgentDenied('research_request_invalid')
    validate_ids(call.args['ids'])
    path = 'research/' + digest(call.id)
    claim = uuid.uuid5(run.attempt, path)
    pending = {'status': 'withheld', 'research_status': 'interrupted',
        'sources': [], 'limitations': ['research_in_progress_or_interrupted']}
    with transaction.atomic():
        previous = AgentInput.objects.filter(execution=run, path=path).first()
        if previous:
            if _receipt(previous)['call_digest'] != digest(call.model_dump()):
                raise AgentDenied('research_call_conflict')
            if previous.original and _receipt(previous)['view'] == pending:
                raise AgentDenied('research_in_progress_or_interrupted')
            return {'status': 'completed', 'reference': str(previous.pk)}
        if AgentInput.objects.filter(execution=run, kind='research').count() >= MAX_RESEARCH_CALLS:
            raise AgentDenied('research_call_limit')
        if not AgentExecution.objects.filter(pk=run.pk, status='active', attempt=run.attempt,
                active_call__isnull=True).update(active_call=claim):
            raise AgentDenied('execution_busy_or_uncertain')
        row = AgentInput.objects.create(execution=run, kind='research', path=path, original='', digest='')
        _store(row, call, pending)
    government = None
    try:
        run, context = authenticate(token, attempt)
        view = {'status': 'approved', 'research_status': 'disabled', 'sources': [],
            'limitations': ['research_disabled']}
        if getattr(settings, 'REGULAY_AGENT_RESEARCH_ENABLED', False):
            entries = catalog()
            binding = digest(entries)
            consulted = consulted_sources(run)
            policy_texts = context[8]
            government = _government(run, context, token, attempt, str(claim))
            government.destinations = [*government.destinations,
                *['research:' + key for key in call.args['ids'] if 'research:' + key in context[10].allowed_destinations]]
            view.update(research_status='failed', limitations=[])
            deadline = time.monotonic() + MAX_SECONDS
            for key in call.args['ids']:
                destination = 'research:' + key
                if destination not in government.destinations:
                    view['limitations'].append({'id': key, 'code': 'research_destination_not_allowed'})
                    continue
                if time.monotonic() >= deadline:
                    view['limitations'].append({'id': key, 'code': 'research_deadline_exceeded'})
                    continue
                if not getattr(settings, 'REGULAY_AGENT_RESEARCH_ENABLED', False) or digest(catalog()) != binding:
                    raise AgentDenied('research_authorization_changed')
                if key in consulted:
                    source = consulted[key]
                    if any(source[field] != entries[key][field] for field in ('title', 'publisher', 'url')):
                        raise AgentDenied('research_authorization_changed')
                    government.preflight(destination, policy_texts + [('files', source['excerpt'])])
                    view['sources'].append(source)
                    continue
                record, started = government.start_call('research', destination, None,
                    policy_texts + [('prompts', entries[key]['url'])], Decimal(0), {})
                record.update(cost='0', cost_kind='no_api_charge', cost_scope='api')
                run.prompt.save(update_fields=['decision', 'updated_at'])
                try:
                    remaining = government.remaining()
                    seconds = min(10, deadline - time.monotonic(), remaining if remaining is not None else 10)
                    if seconds <= 0:
                        raise AgentDenied('research_deadline_exceeded')
                    source = fetch_source(entries[key], timeout=seconds)
                    government.complete_call(record, started, None)
                    # Inspect the full extracted text before any truncation or
                    # alias replacement, including company rules for files.
                    government.preflight(destination, policy_texts + [('files', source['text'])])
                    if digest(catalog()) != binding or not getattr(settings, 'REGULAY_AGENT_RESEARCH_ENABLED', False):
                        raise AgentDenied('research_authorization_changed')
                    excerpt = alias_text(run, source['text'][:MAX_EXCERPT])
                    view['sources'].append({'id': key, **entries[key], 'retrieved_at': timezone.now().isoformat(),
                        'sha256': source['sha256'], 'excerpt': excerpt, 'media_type': source['media_type'],
                        'bytes': source['bytes'], 'extracted_characters': len(source['text']),
                        'excerpt_truncated': len(source['text']) > MAX_EXCERPT,
                        'trust': 'untrusted_source_text', 'factual_verification': 'not_performed'})
                except PipelineStop:
                    raise
                except AgentDenied as error:
                    if error.code == 'research_authorization_changed':
                        raise
                    record.update(status='failed', duration_ms=round((time.monotonic() - started) * 1000))
                    view['limitations'].append({'id': key, 'code': error.code})
                except (httpx.HTTPError, OSError, ValueError):
                    record.update(status='failed', duration_ms=round((time.monotonic() - started) * 1000))
                    view['limitations'].append({'id': key, 'code': 'research_fetch_failed'})
            view['research_status'] = ('partial' if view['limitations'] else 'completed') if view['sources'] else (
                'denied' if all(item['code'] == 'research_destination_not_allowed' for item in view['limitations']) else 'failed')
        authenticate(token, attempt)
        _store(row, call, view)
        return {'status': 'completed', 'reference': str(row.pk)}
    except (AgentDenied, PipelineStop) as error:
        # Preserve the reason without retaining any newly disallowed content.
        _store(row, call, {'status': 'withheld', 'research_status': 'denied', 'sources': [],
            'limitations': [error.code]})
        raise AgentDenied(error.code) from None
    finally:
        try:
            if government is not None:
                for item in run.prompt.decision['calls']:
                    if item.get('call_id') == str(claim) and item['status'] == 'started':
                        item.update(status='failed', cost='0', cost_kind='no_api_charge')
                _totals(run.prompt)
        finally:
            AgentExecution.objects.filter(pk=run.pk, active_call=claim, attempt=run.attempt).update(active_call=None)


def approved_view(execution, call, raw):
    """Resolve the opaque receipt, never source metadata supplied by the executor."""
    try:
        reference = json.loads(raw['content'])['reference']
        if not isinstance(reference, str):
            raise ValueError()
        reference = str(uuid.UUID(reference))
        row = AgentInput.objects.get(pk=reference, execution=execution, kind='research',
            path='research/' + digest(call.id))
        value = _receipt(row)
        if value['call_digest'] != digest(call.model_dump()):
            raise ValueError()
        return deepcopy(value['view'])
    except (ValueError, TypeError, KeyError, AgentInput.DoesNotExist):
        return {'status': 'withheld', 'research_status': 'failed', 'sources': [],
            'limitations': ['research_receipt_invalid']}


def consulted_sources(execution):
    """Trusted report-reference map, scoped to one run; no network or new grants."""
    result = {}
    for row in AgentInput.objects.filter(execution=execution, kind='research').order_by('path'):
        value = _receipt(row)['view']
        if value.get('status') == 'approved' and value.get('research_status') in ('completed', 'partial'):
            result.update({source['id']: deepcopy(source) for source in value['sources']})
    return result
