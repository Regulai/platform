"""Incremental delivery of authorized answer text for the web chat.

The provider streams raw text into a server-side buffer. Text reaches the browser
only after the same output checks used for the final answer have run on all text
received so far, and only up to a point where the local masker can no longer
change its result:

* masking is recomputed by the shared local detector (``detect_spans``); text is
  held back until no detected or still-possible sensitive value can cross the
  cut (bounded patterns, contact/name fields, private-key blocks);
* the output policy (YARA and destination authorization) is re-evaluated with
  ``GovernedCalls.preflight`` on the whole buffer before every emission;
* responses that need the complete text are delivered whole: semantic
  verification, document citations, structured (JSON) answers, remote masking,
  providers without verified streaming usage, and any applicable YARA rules.

The final answer still goes through every existing check. Retraction cannot undo
exposure: eligibility and prefix authorization, not withdrawal, protect privacy.
The agent persists only authorized prefixes and marks interrupted text incomplete.
"""
import asyncio
import json
import logging
import re
import threading
import time
import uuid
from urllib.parse import urlsplit

from django.conf import settings
from django.db import connection
from django.http import StreamingHttpResponse

from .governance import PipelineStop
from .local_masking import _matching_view, detect_spans, mask_local_texts, detector_metadata

logger = logging.getLogger(__name__)

HOLDBACK = 96           # normalized characters never shown before more text arrives
EMIT_INTERVAL = 0.12    # seconds between emissions; each emission re-runs the checks
EMIT_CHARS = 48         # ...or this much new text: a burst followed by silence is not held back
# A detector change must re-run the full split corpus before incremental release.
STREAM_DETECTOR_SHA256 = '418ad88bd3d462c2d6c103e5a48ce2e850beb49a9009279785d219b81ef7deb6'
STREAMING_HOSTS = frozenset({'api.openai.com', 'api.anthropic.com', 'api.deepseek.com',
                             'generativelanguage.googleapis.com'})
DEFAULT_HOSTS = {'openai': 'api.openai.com', 'anthropic': 'api.anthropic.com'}

_CONTACT_LABEL = re.compile(r'(?:correo|e-?mail|contacto)(?:[ \t]+[\w-]{1,24}){0,2}[ \t]*:', re.I)
_NAME_LABEL = re.compile(r'(?:nombre(?: completo)?|full name|name|titular|cliente)\s*:', re.I)
_DANGLING_LABEL = re.compile(r'(?:nombre(?: completo)?|full name|name|titular|cliente)\s*:?\s*\Z', re.I)
_PEM_BEGIN = re.compile(r'-----BEGIN (?:[A-Z0-9 ]{0,32})PRIVATE KEY-----')
_PEM_END = re.compile(r'-----END (?:[A-Z0-9 ]{0,32})PRIVATE KEY-----')
_SAFE_CONDITION = re.compile(
    r'(?:any|1) of them|(?:any|1) of \(\s*\$\w*\*?(?:\s*,\s*\$\w*\*?)*\s*\)|\$\w+(?:\s+or\s+\$\w+)*', re.I)


# ---------------------------------------------------------------- eligibility

def _prefix_decidable(source):
    """True if every rule matches as soon as one of its strings is present.

    Then a match on the complete answer implies a match on a buffer that already
    contains that string, so checking each buffer before showing it is exact.
    Counts, conjunctions, negations, file size or imports need the whole text.
    """
    text = re.sub(r'/\*.*?\*/|//[^\n]*', ' ', source or '', flags=re.S)
    if re.search(r'^\s*import\b|\b(?:global|private)\s+rule\b', text, re.M):
        return False
    conditions = re.findall(r'\bcondition\s*:\s*(.*?)(?=\n\s*(?:private\s+|global\s+)?rule\s|\Z)', text, re.S)
    if not conditions:
        return False
    for condition in conditions:
        condition = ' '.join(condition.strip().rstrip('}').split())
        if not _SAFE_CONDITION.fullmatch(condition):
            return False
    return True


def streaming_host(engine):
    connector = engine.engine.connector_type
    host = urlsplit(engine.engine.base_url or '').hostname or DEFAULT_HOSTS.get(connector)
    allowed = STREAMING_HOSTS | set(getattr(settings, 'CHAT_STREAMING_EXTRA_HOSTS', ()))
    return connector in ('openai', 'openai_compatible', 'anthropic') and host in allowed


def delivery_plan(*, document, semantic, masks, engine, rules):
    """('streamed', None) or ('complete', reason). Reasons are stable codes."""
    if not getattr(settings, 'CHAT_STREAMING_ENABLED', True):
        return 'complete', 'streaming_disabled'
    if document is not None:
        return 'complete', 'document_citations'
    if semantic:
        return 'complete', 'response_verification'
    if any(mask.backend != 'local' for mask in masks):
        return 'complete', 'remote_masking'
    if detector_metadata()['patterns_sha256'] != STREAM_DETECTOR_SHA256:
        return 'complete', 'detector_stability_unverified'
    if not streaming_host(engine):
        return 'complete', 'provider_streaming_unverified'
    # Even a plain string may match only at the very end and prohibit the entire
    # answer. Parsing its condition does not prove earlier text may be disclosed.
    if any(rule.applies_to in ('prompts', 'both') for rule in rules):
        return 'complete', 'policy_needs_complete_text'
    return 'streamed', None


# ------------------------------------------------------------- safe emission

def _whitespace_cut(text, limit):
    """Largest cut <= limit that follows whitespace (0 if none)."""
    index = min(limit, len(text))
    while index > 0 and not text[index - 1].isspace():
        index -= 1
    return index


def _line_start(text, index):
    return text.rfind('\n', 0, max(index, 0)) + 1


def safe_cut(text, view=None):
    """Raw index up to which masking of ``text`` is final, whatever follows.

    Values that may contain whitespace are either bounded (ID, account, phone,
    card: at most 64 normalized characters, so HOLDBACK covers them) or need a
    field label on the same line (contact e-mail, name) or an open private key
    block; those lines are held until complete. Other values never contain
    whitespace, so a cut after whitespace cannot split them.
    """
    stripped = text.lstrip()
    if not stripped or stripped[0] in '{[':
        return 0  # Structured answers are masked as JSON at the end; never partial.
    matching, offsets = view or _matching_view(text)
    if len(matching) <= HOLDBACK:
        return 0
    limit = offsets[len(matching) - HOLDBACK]
    for candidate, mapping in ((text, None), (matching, offsets)):
        ends = [match.start() for match in _PEM_END.finditer(candidate)]
        for match in _PEM_BEGIN.finditer(candidate):
            if not any(end > match.start() for end in ends):
                limit = min(limit, match.start() if mapping is None else mapping[match.start()])
    spans = [(start, end) for start, end, _ in detect_spans(text, (matching, offsets))]
    cut = _whitespace_cut(text, limit)
    for _ in range(256):
        moved = cut
        line = _line_start(text, cut)
        segment, segment_offsets = _matching_view(text[line:cut])
        labels = [match.start() for pattern in (_CONTACT_LABEL, _NAME_LABEL) for match in pattern.finditer(segment)]
        if labels:
            # The value follows its label on this line and may hold spaces: wait for the line.
            moved = min(moved, _whitespace_cut(text, line + segment_offsets[min(labels)]))
        if line > 0 and _DANGLING_LABEL.search(_matching_view(text[max(0, line - 200):line])[0]):
            moved = min(moved, line)  # A name label ended the previous line; its value may be here.
        for start, end in spans:
            if start < moved < end:
                moved = _whitespace_cut(text, start)
        if moved == cut:
            return cut
        cut = moved
    return 0


class StreamGuard:
    """Feeds provider text in and emits only checked, masked, stable text."""

    def __init__(self, events, government, masks, policy_texts, *, response_bytes=None, attempt=1, prompt=None,
                 protector=None, authorize=None, strict_interval=False):
        self.events, self.government, self.masks = events, government, masks
        self.policy_texts, self.response_bytes, self.attempt = policy_texts, response_bytes, attempt
        self.prompt = prompt
        self.protector, self.authorize, self.strict_interval = protector, authorize, strict_interval
        self.text, self.emitted, self.cut, self.last = '', '', 0, 0.0
        self.matching, self.offsets, self.size = '', [], 0
        self.structured = None
        self.reading, self.interrupted = False, False
        self.checked = 0

    def opened(self, close):
        """The provider stream is open: a user's stop closes it at once.

        Waiting for the next fragment could take long (reasoning models stay
        silent). Closing the HTTP stream ends the read in the request thread;
        the pipeline then records the call as cancelled with an unknown cost.
        """
        self.reading = True

        def stop():
            if self.reading:
                self.interrupted = True
                close()
        self.events.on_cancel(stop)

    def closed(self):
        self.reading = False

    def feed(self, fragment):
        if self.events.cancelled():
            raise PipelineStop('cancelled_by_user', 'cancelled')
        self.government.remaining()  # The request deadline also bounds a long stream.
        # The normalized view is per character, so it extends with the buffer.
        matching, offsets = _matching_view(fragment)
        self.offsets.extend(len(self.text) + offset for offset in offsets)
        self.matching += matching
        self.text += fragment
        self.size += len(fragment.encode('utf-8'))
        if self.response_bytes is not None and self.size > self.response_bytes:
            raise PipelineStop('evaluation_input_too_large')
        now = time.monotonic()
        # Nothing runs while the provider is silent, so a burst is checked in steps.
        if now - self.last >= EMIT_INTERVAL or (not self.strict_interval and len(self.text) - self.checked >= EMIT_CHARS):
            self.last, self.checked = now, len(self.text)
            self.advance()

    def advance(self):
        if self.structured is None and self.text.strip():
            self.structured = self.text.lstrip()[0] in '{['
            if self.structured:
                if self.prompt is not None:
                    self.prompt.decision.setdefault('delivery', {}).update(mode='complete', reason='structured_answer')
                self.events.delivery('complete', 'structured_answer', attempt=self.attempt)
        if self.structured:
            return
        cut = safe_cut(self.text, (self.matching, self.offsets))
        if cut <= self.cut:
            return
        # Same output authorization as the final answer, on everything received.
        if self.authorize is not None:
            self.authorize(self.text)
        for mask in self.masks:
            self.government.preflight(f'obfuscation:{mask.pk}', self.policy_texts + [('prompts', self.text)])
        masked = self.mask(self.text[:cut])
        if not masked.startswith(self.emitted):
            raise PipelineStop('security_check_failed')  # Never correct text already shown.
        delta, self.emitted, self.cut = masked[len(self.emitted):], masked, cut
        if delta:
            if self.prompt is not None:
                self.prompt._shown = self.attempt
            self.events.emit('delta', text=delta, attempt=self.attempt)

    def mask(self, value):
        if self.protector is not None:
            return self.protector(value)
        current = [value]
        for config in self.masks:
            remaining = self.government.remaining()
            current = mask_local_texts(current, language=config.language,
                                       timeout=10 if remaining is None else min(10, remaining))
        return current[0]


# ------------------------------------------------------------ event channel

class ChatEvents:
    """Ordered, thread-safe events of one web request. Memory only, never persisted."""

    def __init__(self, user_id, request_id):
        self.user_id, self.request_id = user_id, str(request_id)
        self.condition = threading.Condition()
        self.events, self.cancel_requested, self.done, self.finished_at = [], False, False, None
        self.streamed = None
        self.stoppers = []

    def emit(self, kind, **data):
        with self.condition:
            payload = {'type': kind, 'seq': len(self.events) + 1, **data}
            self.events.append(payload)
            if kind == 'final':
                self.done, self.finished_at = True, time.monotonic()
            self.condition.notify_all()
        return payload

    def stage(self, name, **data):
        if self.cancelled():
            raise PipelineStop('cancelled_by_user', 'cancelled')
        self.emit('stage', stage=name, **data)

    def delivery(self, mode, reason=None, **data):
        self.emit('delivery', mode=mode, reason=reason, **data)

    def on_cancel(self, stop):
        """Run ``stop`` when the user cancels (now, if that already happened)."""
        with self.condition:
            if not self.cancel_requested:
                self.stoppers.append(stop)
                return
        stop()

    def cancel(self):
        with self.condition:
            self.cancel_requested = True
            stoppers, self.stoppers = self.stoppers, []
        for stop in stoppers:
            try:
                stop()
            except Exception:  # The request thread still sees the flag at its next step.
                logger.warning('Stream stop failed', extra={'code': 'stream_stop_failed', 'request_id': self.request_id})

    def cancelled(self):
        return self.cancel_requested

    def since(self, seq):
        with self.condition:
            return self.events[seq:]

    def wait(self, seq, timeout):
        with self.condition:
            if len(self.events) <= seq and not self.done:
                self.condition.wait(timeout)
            return self.events[seq:]


_REGISTRY, _LOCK = {}, threading.Lock()
RETAIN_SECONDS = 120


def register(events):
    with _LOCK:
        now = time.monotonic()
        for key, value in list(_REGISTRY.items()):
            if value.done and now - value.finished_at > RETAIN_SECONDS:
                del _REGISTRY[key]
        _REGISTRY[(events.user_id, events.request_id)] = events
    return events


def lookup(user_id, request_id):
    with _LOCK:
        return _REGISTRY.get((user_id, str(request_id)))


# --------------------------------------------------------------- transport

def _frame(event):
    return (f"id: {event['seq']}\nevent: {event['type']}\n"
            f"data: {json.dumps(event, ensure_ascii=False, default=str)}\n\n")


def _sync_frames(events, after=0):
    seq = after
    while True:
        batch = events.wait(seq, 10)
        if not batch:
            yield ': keepalive\n\n'
            continue
        for event in batch:
            seq = event['seq']
            yield _frame(event)
            if event['type'] == 'final':
                return


async def _async_frames(events, after=0):
    seq, idle = after, 0.0
    try:
        while True:
            batch = events.since(seq)
            if not batch:
                await asyncio.sleep(0.04)
                idle += 0.04
                if idle >= 10:
                    idle = 0.0
                    yield ': keepalive\n\n'
                continue
            idle = 0.0
            for event in batch:
                seq = event['seq']
                yield _frame(event)
                if event['type'] == 'final':
                    return
    except asyncio.CancelledError:
        return  # A closed browser connection never cancels the request.


def frames(request, events, after=0):
    return _async_frames(events, after) if hasattr(request, 'scope') else _sync_frames(events, after)


def event_stream(request, iterator):
    response = StreamingHttpResponse(iterator, content_type='text/event-stream; charset=utf-8')
    response['Cache-Control'] = 'private, no-store'
    response['X-Accel-Buffering'] = 'no'
    response['X-Content-Type-Options'] = 'nosniff'
    return response


def _run(user, command, events):
    from .chat_service import send_chat_message
    try:
        result = send_chat_message(user, command, events=events)
        events.emit('final', result=result.data, http_status=result.http_status)
    except Exception:
        logger.exception('Streamed chat failed', extra={'code': 'stream_internal_error', 'request_id': events.request_id},
                         exc_info=(RuntimeError, RuntimeError('stream_internal_error'), None))
        events.emit('final', http_status=500, result={'success': False, 'status': 'failed',
            'request_id': events.request_id, 'error_type': 'internal_error',
            'error': 'Un error interno impidió completar la petición.'})
    finally:
        if getattr(settings, 'CHAT_STREAM_THREADS', True):
            connection.close()


def stream_send(request, command):
    """Start (or rejoin) one request and stream its events to this response."""
    try:
        request_id = str(uuid.UUID(str(command.get('request_id') or uuid.uuid4())))
    except ValueError:
        request_id = str(uuid.uuid4())  # The pipeline rejects malformed IDs itself.
    command = {**command, 'request_id': request_id}
    user = getattr(request.user, '_wrapped', request.user)
    events = lookup(user.pk, request_id)
    if events is None or events.done:
        uploaded = command.get('file')
        if uploaded is not None:
            # The request (and its upload) closes with the response; the run may outlive it.
            from django.core.files.uploadedfile import SimpleUploadedFile
            command['file'] = SimpleUploadedFile(uploaded.name, uploaded.read(), uploaded.content_type)
        events = register(ChatEvents(user.pk, request_id))
        if getattr(settings, 'CHAT_STREAM_THREADS', True):
            # Not a daemon: a graceful shutdown lets the request finish and persist.
            threading.Thread(target=_run, args=(user, command, events),
                             name='chat-stream-' + request_id[:8]).start()
        else:
            _run(user, command, events)  # Tests: same transaction, same thread.
    return event_stream(request, frames(request, events))


WAIT_SECONDS = 60


def _stored(prompt_id, user_id, *, final=False):
    """Stored state for a request this process is not running. Read only."""
    from .chat_service import request_result
    from .models import Prompt
    prompt = Prompt.objects.select_related('user_message').get(pk=prompt_id, user_id=user_id)
    if prompt.status in ('processing', 'received') and not final:
        return None
    result = request_result(prompt)
    return {'type': 'final', 'result': result.data, 'http_status': result.http_status}


def _sync_db(prompt_id, user_id, after):
    """No live buffer here (finished, or another process): wait for the stored result."""
    deadline, seq = time.monotonic() + WAIT_SECONDS, after
    while True:
        event = _stored(prompt_id, user_id, final=time.monotonic() > deadline)
        if event:
            yield _frame({**event, 'seq': seq + 1})
            return
        if seq == after:
            seq += 1
            yield _frame({'type': 'stage', 'seq': seq, 'stage': 'waiting'})
        else:
            yield ': keepalive\n\n'
        time.sleep(1)


async def _async_db(prompt_id, user_id, after):
    from asgiref.sync import sync_to_async
    load = sync_to_async(_stored)
    deadline, seq = time.monotonic() + WAIT_SECONDS, after
    try:
        while True:
            event = await load(prompt_id, user_id, final=time.monotonic() > deadline)
            if event:
                yield _frame({**event, 'seq': seq + 1})
                return
            if seq == after:
                seq += 1
                yield _frame({'type': 'stage', 'seq': seq, 'stage': 'waiting'})
            else:
                yield ': keepalive\n\n'
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        return
