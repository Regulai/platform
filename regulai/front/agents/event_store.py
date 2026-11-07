"""Ordered durable public progress. Content is encrypted; cursors are global IDs."""
from datetime import timedelta
import json

from django.db import transaction
from django.utils import timezone

from front.models import AgentEvent, AgentExecution

FRAME_BYTES = 4096
BATCH_BYTES = 16384


def utf8_frames(text, limit=FRAME_BYTES-768):
    """Bound JSON-escaped UTF-8 text, leaving room for the SSE envelope."""
    parts, size = [], 0
    for char in text:
        width = (2 if char in '\\"\b\t\n\f\r' else 6 if ord(char) < 32 else len(char.encode('utf-8')))
        if width > limit:
            raise ValueError('event_frame_limit_too_small')
        if parts and size + width > limit:
            yield ''.join(parts)
            parts, size = [], 0
        parts.append(char)
        size += width
    if parts:
        yield ''.join(parts)


def append_events(execution, entries):
    """One brief run lock serializes all producers and their committed cursors."""
    rows = []
    with transaction.atomic():
        run = AgentExecution.objects.select_for_update().get(pk=execution.pk)
        for entry in entries:
            kind, data = entry['kind'], entry.get('data', {})
            key, text = entry.get('event_key'), entry.get('public_text', '')
            if ('text' in data and kind.startswith('text.') or len(kind) > 32
                    or len(json.dumps(data).encode('utf-8')) > BATCH_BYTES
                    or key is not None and len(key) > 200):
                raise ValueError('invalid_public_event')
            # A retry must match the already committed content, not mutate it.
            previous = run.events.filter(event_key=key).first() if key is not None else None
            if previous:
                if previous.kind != kind or previous.data != data or previous.public_text != text:
                    raise ValueError('event_identity_conflict')
                rows.append(previous)
                continue
            if kind == 'text.delta' and (run.status != 'active' or run.attempt != execution.attempt):
                raise ValueError('event_execution_no_longer_active')
            rows.append(AgentEvent.objects.create(execution=run, kind=kind, data=data,
                event_key=key, public_text=text, attempt_id=execution.attempt))
    return rows


def append_event(execution, kind, *, event_key=None, public_text='', **data):
    return append_events(execution, [{'kind': kind, 'event_key': event_key,
        'public_text': public_text, 'data': data}])[0]


def serialized_event(row, *, snapshot_text=True):
    data = dict(row.data)
    if row.kind == 'text.snapshot' and not snapshot_text:
        # The authorized HTTP snapshot carries the compacted body. A bounded
        # SSE marker asks old cursors to fetch it instead of a huge single frame.
        data['snapshot_required'] = True
    elif row.kind.startswith('text.'):
        data['text'] = row.public_text
    return {'v': 1 if row.attempt_id else 0, 'id': row.pk, 'seq': row.pk,
        'execution_id': str(row.execution_id),
        'attempt_id': str(row.attempt_id) if row.attempt_id else None,
        'kind': row.kind, 'data': data, 'created_at': row.created_at.isoformat()}


def fetch_event_batch(actor, run_id, cursor=0, limit=100):
    """Read-only polling: no reaper, artifacts, receipts or recovery computation."""
    from .jobs import authorized_run
    run = authorized_run(actor, run_id)
    with transaction.atomic():
        # Same lock as append: a reader cannot skip an uncommitted lower ID.
        run = AgentExecution.objects.select_for_update().get(pk=run.pk)
        rows = list(run.events.filter(pk__gt=cursor).order_by('pk')[:limit])
        high = run.events.order_by('-pk').values_list('pk', flat=True).first() or 0
        return {'run': {'id': str(run.pk), 'status': run.status},
            'events': [serialized_event(row, snapshot_text=False) for row in rows], 'high_watermark': high,
            'provider_active': run.active_call is not None}


def text_snapshot(execution):
    """Call under the run lock when pairing this projection with a watermark."""
    segments = {}
    for row in execution.events.filter(kind__in=['text.delta', 'text.snapshot']).order_by('pk'):
        data = row.data
        key = data['message_id']
        segment = segments.setdefault(key, {'message_id': key, 'inference_id': data['inference_id'],
            'text': '', 'offset': 0, 'expired': False})
        if row.kind == 'text.snapshot':
            segment.update(text=row.public_text, offset=len(row.public_text.encode('utf-8')), expired=True)
        elif data['offset'] == segment['offset']:
            segment['text'] += row.public_text
            segment['offset'] += len(row.public_text.encode('utf-8'))
        else:
            raise ValueError('event_text_offset_gap')
    return list(segments.values())


def compact_expired_text(execution, *, now=None):
    """Replace expired frames with encrypted snapshots; never retain raw content."""
    cutoff = (now or timezone.now()) - timedelta(hours=24)
    with transaction.atomic():
        run = AgentExecution.objects.select_for_update().get(pk=execution.pk)
        old = list(run.events.filter(kind='text.delta', created_at__lt=cutoff).order_by('pk'))
        if not old:
            return 0
        # Compact whole segments, including their recent suffix, to preserve offsets.
        keys = {row.data['message_id'] for row in old}
        snapshots = [segment for segment in text_snapshot(run) if segment['message_id'] in keys]
        all_ids = [row.pk for row in run.events.filter(kind__in=['text.delta', 'text.snapshot'])
                   if row.data.get('message_id') in keys]
        for segment in snapshots:
            append_event(run, 'text.snapshot', public_text=segment['text'],
                message_id=segment['message_id'], inference_id=segment['inference_id'],
                offset=0, expired=True)
        run.events.filter(pk__in=all_ids).delete()
        return len(all_ids)
