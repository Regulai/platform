"""Provider streaming remains inside the governed application boundary."""
import threading
import time

from django.conf import settings
from django.db import close_old_connections, connections
from django.utils import timezone

from front.chat_streaming import StreamGuard, delivery_plan, streaming_host, EMIT_INTERVAL
from front.governance import PipelineStop
from front.local_masking import mask_local_texts
from front.policy import active_rules
from .aliases import alias_text, preserve_aliases
from .event_store import append_event, append_events, utf8_frames, BATCH_BYTES


class CancellationWatch:
    """One bounded watcher per open inference, not per browser or token."""

    def __init__(self, execution, *, deadline=None):
        self.execution, self.deadline = execution, deadline
        self.stopped, self.cancelled_event = threading.Event(), threading.Event()
        self.thread = None

    def opened(self, close):
        def watch():
            from front.models import AgentExecution
            try:
                while not self.stopped.is_set():
                    close_old_connections()
                    state = AgentExecution.objects.filter(pk=self.execution.pk).values(
                        'status', 'attempt', 'expires_at').first()
                    if (not state or state['status'] != 'active'
                            or state['attempt'] != self.execution.attempt
                            or state['expires_at'] <= timezone.now()
                            or self.deadline is not None and time.monotonic() >= self.deadline):
                        self.cancelled_event.set()
                        close()
                        return
                    self.stopped.wait(0.2)
            except Exception:
                # Losing the cancellation authority fails closed as well.
                self.cancelled_event.set()
                close()
            finally:
                connections.close_all()
        self.thread = threading.Thread(target=watch, name='agent-stream-stop', daemon=True)
        self.thread.start()

    def closed(self):
        self.stopped.set()
        if self.thread is not None and self.thread is not threading.current_thread():
            self.thread.join(timeout=1)

    def cancelled(self):
        return self.cancelled_event.is_set()


class AgentStream:
    """Authorized batches use the same aliases as the final protected response."""

    def __init__(self, execution, context, government, request):
        self.execution, self.government, self.request = execution, government, request
        actor, _, agent, cfg, engine, model, masks, _, policy_texts, *_ = context
        self.engine, self.model, self.policy_texts = engine, model, policy_texts
        self.call_id = str(request.call_id)
        self.message_id = f'inference:{self.call_id}'
        self.offset, self.last_append = 0, None
        self.started_at, self.started = timezone.now().isoformat(), time.monotonic()
        self.enabled = getattr(settings, 'REGULAY_AGENT_TEXT_STREAM', False)
        self.transport = self.enabled and streaming_host(engine) and engine.engine.connector_type in (
            'openai', 'openai_compatible')
        self.mode, self.reason = delivery_plan(document=None,
            semantic=cfg.verification.mode != 'local', masks=masks, engine=engine, rules=active_rules(actor))
        if not self.enabled:
            self.mode, self.reason = 'complete', 'agent_streaming_disabled'
        elif request.purpose != 'generation':
            self.mode, self.reason = 'complete', 'internal_inference'
        elif execution.job.get('kind') in ('document', 'presentation', 'export'):
            self.mode, self.reason = 'complete', 'document_citations'
        self.max_bytes = min(cfg.routing.max_response_bytes or 512_000, 512_000)
        if agent.professional:
            from .capabilities import execution_limits
            self.max_bytes = min(self.max_bytes, execution_limits(execution, agent)['output_bytes'])
        remaining = government.remaining()
        self.watch = CancellationWatch(execution,
            deadline=None if remaining is None else time.monotonic() + remaining)
        self.guard = StreamGuard(self, government, masks, policy_texts, response_bytes=self.max_bytes,
            protector=self.protect, authorize=self.authorize, strict_interval=True)
        append_event(execution, 'inference.started', event_key=f'inference:{self.call_id}:started',
            call_id=self.call_id, purpose=request.purpose, mode=self.mode, reason=self.reason,
            started_at=self.started_at)

    def authorize(self, text):
        # Authorization is outside the mask loop: an empty/broken mask list must
        # never turn the presence of output text into implicit permission.
        self.government.preflight(f'engine:{self.engine.pk}',
            self.policy_texts + [('prompts', text)], model_pk=self.model.pk)

    def protect(self, text):
        aliased = alias_text(self.execution, text)
        def local(values):
            for config in self.government.masks:
                if config.backend != 'local':
                    raise PipelineStop('remote_masking')
                remaining = self.government.remaining()
                values = mask_local_texts(values, language=config.language,
                    timeout=min(10, remaining) if remaining is not None else 10)
            return values
        # Local stream checks do not create one financial ledger entry per batch.
        return preserve_aliases([aliased], local)[0]

    def cancelled(self):
        return self.watch.cancelled()

    def delivery(self, mode, reason, **unused):
        self.mode, self.reason = mode, reason
        append_event(self.execution, 'inference.delivery',
            event_key=f'inference:{self.call_id}:delivery:{reason}',
            call_id=self.call_id, mode=mode, reason=reason)

    def emit(self, kind, *, text, final=False, **unused):
        if kind != 'delta':
            raise ValueError('invalid_agent_stream_event')
        frames = list(utf8_frames(text))
        batch, size = [], 0
        next_offset = self.offset
        for frame in frames:
            width = len(frame.encode('utf-8'))
            if batch and (size + width > BATCH_BYTES or len(batch) == 4):
                self._append(batch, final=final)
                batch, size = [], 0
            batch.append({'kind': 'text.delta', 'event_key': f'text:{self.call_id}:{next_offset}',
                'public_text': frame, 'data': {'inference_id': self.call_id,
                    'message_id': self.message_id, 'offset': next_offset}})
            next_offset += width
            size += width
        if batch:
            self._append(batch, final=final)

    def _append(self, batch, *, final=False):
        if self.last_append is not None and not final:
            wait = EMIT_INTERVAL - (time.monotonic() - self.last_append)
            if wait > 0 and self.watch.cancelled_event.wait(wait):
                raise PipelineStop('cancelled_by_user', 'cancelled')
        if self.cancelled():
            raise PipelineStop('cancelled_by_user', 'cancelled')
        self.authorize(self.guard.text)
        append_events(self.execution, batch)
        self.offset = batch[-1]['data']['offset'] + len(batch[-1]['public_text'].encode('utf-8'))
        self.last_append = time.monotonic()

    def event(self, value):
        # Private tool fragments, thinking, signatures and usage are never SSE.
        if self.cancelled():
            raise PipelineStop('cancelled_by_user', 'cancelled')
        if value.kind == 'text' and self.mode == 'streamed':
            self.guard.feed(value.text)

    def callbacks(self):
        return {'on_event': self.event, 'on_open': self.watch.opened,
            'on_close': self.watch.closed, 'stream_max_bytes': self.max_bytes} if self.transport else {}

    def complete_text(self, text):
        if self.mode == 'streamed':
            if not isinstance(text, str) or not text.startswith(self.guard.emitted):
                raise PipelineStop('security_check_failed')
            # Final text is already protected. Tools remain private until the
            # terminal inference receipt commits and infer returns to the worker.
            if len(text) > len(self.guard.emitted):
                self.emit('delta', text=text[len(self.guard.emitted):], final=True)

    def finish(self, record):
        self.watch.closed()
        append_event(self.execution, 'inference.finished', event_key=f'inference:{self.call_id}:finished',
            call_id=self.call_id, purpose=self.request.purpose, status=record.status,
            mode=self.mode, reason=self.reason, message_id=self.message_id,
            incomplete=record.status != 'completed', offset=self.offset,
            tool_count=len(record.response.get('tool_calls', [])),
            usage_reference=self.call_id, started_at=self.started_at, completed_at=timezone.now().isoformat(),
            duration_ms=record.response.get('inference', {}).get('duration_ms', round((time.monotonic()-self.started)*1000)))
