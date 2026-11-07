"""Credential-free public HTTP broker: validate, resolve once, pin, bound, repeat.

Only this module opens public sockets for documents. A model, redirect, browser
subresource or package manifest cannot set request headers, methods or cookies.
"""
from hashlib import sha256
from html.parser import HTMLParser
import ipaddress
import socket
import time
import zlib
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

import httpx


class WebError(ValueError):
    pass


_dns_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix='public-dns')
_dns_slots = threading.BoundedSemaphore(4)


def public_url(value):
    try:
        if (not isinstance(value, str) or not 1 <= len(value) <= 4096 or '\\' in value
                or any(ord(c) < 33 or ord(c) > 126 for c in value)):
            raise ValueError()
        p = urlsplit(value)
        if (p.scheme not in ('http', 'https') or p.username is not None or p.password is not None
                or p.port not in (None, 443 if p.scheme == 'https' else 80) or not p.hostname
                or '%' in p.hostname or p.hostname.endswith(('.', '.localhost', '.local', '.internal'))
                or any(ord(c) < 32 for c in unquote(value))):
            raise ValueError()
        host = p.hostname.encode('idna').decode('ascii')
        if host == 'localhost' or '.' not in host and ':' not in host:
            raise ValueError()
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            check_address(address)
        return urlunsplit((p.scheme, p.netloc, p.path or '/', p.query, ''))
    except (ValueError, UnicodeError):
        raise WebError('web_url_denied') from None


def check_address(address):
    blocked_v6 = ('64:ff9b::/96', '64:ff9b:1::/48', '2002::/16', '2001::/32')
    if (not address.is_global or address.is_multicast or address.is_unspecified
            or isinstance(address, ipaddress.IPv6Address) and (address.ipv4_mapped is not None
            or any(address in ipaddress.ip_network(cidr) for cidr in blocked_v6))):
        raise WebError('web_address_denied')


def resolve(host, port, timeout=5):
    if not _dns_slots.acquire(blocking=False):
        raise WebError('web_dns_capacity')
    future = _dns_pool.submit(socket.getaddrinfo, host, port, type=socket.SOCK_STREAM)
    future.add_done_callback(lambda _: _dns_slots.release())
    try:
        addresses = list(dict.fromkeys(item[4][0] for item in future.result(timeout=max(.01, timeout))))
        if not addresses:
            raise WebError('web_dns_failed')
        for address in addresses:
            check_address(ipaddress.ip_address(address))
        return next((a for a in addresses if ':' not in a), addresses[0])
    except FutureTimeout:
        future.cancel()
        raise WebError('web_dns_timeout') from None
    except (OSError, ValueError) as error:
        raise WebError(str(error) if isinstance(error, WebError) else 'web_dns_failed') from None


def fetch(url, *, max_bytes=10000000, timeout=25, authorize=lambda url: None, transport=None):
    requested = public_url(url)
    current = requested
    deadline = time.monotonic() + timeout
    redirects = []
    # Per-fetch client has no persistent session or ambient proxy/credentials.
    with httpx.Client(transport=transport or httpx.HTTPTransport(retries=0, trust_env=False),
            follow_redirects=False, trust_env=False) as client:
        for hop in range(6):
            current = public_url(current)
            authorize(current)  # Also covers every path/query and redirect before DNS.
            parsed = urlsplit(current)
            address = resolve(parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80), timeout=min(5, deadline-time.monotonic()))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WebError('web_timeout')
            target = httpx.URL(current).copy_with(host=address)
            client.cookies.clear()
            try:
                with client.stream('GET', target, headers={'Host': parsed.netloc,
                        'User-Agent': 'Regulay-Public-Research/1.0', 'Accept-Encoding': 'gzip, deflate'},
                        extensions={'sni_hostname': parsed.hostname}, timeout=remaining) as response:
                    if response.status_code in (301, 302, 303, 307, 308):
                        if hop == 5 or not response.headers.get('location'):
                            raise WebError('web_redirect_limit')
                        redirects.append(current)
                        current = urljoin(current, response.headers['location'])
                        continue
                    if response.status_code != 200:
                        raise WebError('web_rate_limited' if response.status_code == 429 else
                            'web_access_restricted' if response.status_code in (401, 403, 402) else 'web_http_failed')
                    encoding = response.headers.get('content-encoding', 'identity').lower()
                    if encoding not in ('identity', '', 'gzip', 'deflate'):
                        raise WebError('web_encoding_unsupported')
                    length = response.headers.get('content-length')
                    if length and (not length.isdecimal() or int(length) > max_bytes):
                        raise WebError('web_size_limit')
                    data, wire_bytes = bytearray(), 0
                    decoder = zlib.decompressobj(31 if encoding == 'gzip' else 15) if encoding in ('gzip', 'deflate') else None
                    chunks = [response.content] if response.is_stream_consumed else response.iter_raw(chunk_size=65536)
                    for chunk in chunks:
                        if time.monotonic() >= deadline:
                            raise WebError('web_timeout')
                        wire_bytes += len(chunk)
                        if wire_bytes > max_bytes:
                            raise WebError('web_size_limit')
                        try:
                            data.extend(decoder.decompress(chunk, max_bytes - len(data) + 1) if decoder else chunk)
                        except zlib.error:
                            raise WebError('web_encoding_invalid') from None
                        if len(data) > max_bytes:
                            raise WebError('web_size_limit')
                    if decoder and (not decoder.eof or decoder.unused_data):
                        raise WebError('web_encoding_invalid')
                    return {'url': requested, 'final_url': current, 'redirects': redirects,
                        'media_type': response.headers.get('content-type', '').split(';')[0].lower(),
                        'browser_headers': {name: response.headers[name] for name in (
                            'access-control-allow-origin', 'content-security-policy', 'x-frame-options', 'referrer-policy')
                            if name in response.headers},
                        'updated_at': response.headers.get('last-modified'), 'raw': bytes(data),
                        'sha256': sha256(data).hexdigest(), 'bytes': len(data)}
            except httpx.HTTPError:
                raise WebError('web_fetch_failed') from None
    raise WebError('web_redirect_limit')


class ReadableHTML(HTMLParser):
    def __init__(self, url):
        super().__init__(convert_charrefs=True)
        self.url, self.parts, self.links = url, [], []
        self.ignore, self.in_title, self.title = 0, False, ''
        self.publication_date = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ('script', 'style', 'template', 'noscript'):
            self.ignore += 1
        if tag == 'title':
            self.in_title = True
        if tag in ('p', 'br', 'div', 'tr', 'h1', 'h2', 'h3', 'li', 'article'):
            self.parts.append('\n')
        if tag in ('td', 'th'):
            self.parts.append(' | ')
        if tag == 'meta' and attrs.get('property') in ('article:published_time', 'datePublished'):
            self.publication_date = attrs.get('content', '')[:100] or None
        if tag == 'a' and 'href' in attrs and len(self.links) < 200:
            try:
                self.links.append(public_url(urljoin(self.url, attrs['href'])))
            except WebError:
                pass

    def handle_endtag(self, tag):
        if tag in ('script', 'style', 'template', 'noscript'):
            self.ignore = max(0, self.ignore - 1)
        if tag == 'title':
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title += data
        elif not self.ignore:
            self.parts.append(data)

    def text(self):
        return '\n'.join(' '.join(line.split()) for line in ''.join(self.parts).splitlines() if line.strip())
