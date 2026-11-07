"""Durable admission on existing rows; no lock is held across an external effect."""
from contextlib import contextmanager
from datetime import timedelta
import re
import uuid
from urllib.parse import urlsplit, urlunsplit

from django.conf import settings
from django.db import connection, transaction
from django.db.models import Q
from django.utils import timezone

from front.models import AgentExecution, AgentInference
from front.policy import digest
from .service import AgentDenied


class CapacityDenied(AgentDenied):
    retry_after = 5


DEFAULTS = {'active_global': 2, 'active_company': 2, 'queued_global': 32,
    'queued_company': 8, 'queue_seconds': 300, 'provider': 1, 'sandbox': 1}
CEILINGS = {**DEFAULTS, 'provider': 2}
OCCUPIED = ('reserved', 'active', 'uncertain')
LOCK_ID = 752682419631  # All admission paths share one PostgreSQL transaction lock.


def limits():
    configured = getattr(settings, 'REGULAY_AGENT_CAPACITY', {})
    if not isinstance(configured, dict) or set(configured) - set(DEFAULTS):
        raise AgentDenied('invalid_agent_capacity')
    result = {**DEFAULTS, **configured}
    if any(type(value) is not int or not 1 <= value <= CEILINGS[key] for key, value in result.items()):
        raise AgentDenied('invalid_agent_capacity')
    return result


@contextmanager
def admission_lock():
    with transaction.atomic():
        if connection.vendor == 'postgresql':
            with connection.cursor() as cursor:
                cursor.execute('SELECT pg_advisory_xact_lock(%s)', [LOCK_ID])
        elif not getattr(settings, 'DEBUG', False) and connection.vendor != 'sqlite':
            raise AgentDenied('agent_postgresql_required')
        # SQLite is only the existing isolated serial fixture backend. Worker
        # authentication independently requires PostgreSQL in production.
        yield


def _locked():
    if not connection.in_atomic_block:
        raise RuntimeError('capacity_admission_requires_transaction')


def admit_queue(company_id):
    """Call after checking request-id replay, before creating a new Prompt."""
    _locked()
    caps = limits()
    pending = AgentExecution.objects.filter(status='queued')
    if pending.count() >= caps['queued_global'] or pending.filter(prompt__company_id=company_id).count() >= caps['queued_company']:
        raise CapacityDenied('agent_queue_saturated')


def queue_expired(*, now=None):
    return AgentExecution.objects.filter(status='queued',
        created_at__lte=(now or timezone.now()) - timedelta(seconds=limits()['queue_seconds']))


def occupied_runs():
    """Cancellation cannot release tasks still holding physical resources."""
    uncertain = AgentInference.objects.filter(response___capacity__state__in=OCCUPIED).values('execution_id')
    return AgentExecution.objects.filter(Q(status='active') | Q(pk__in=uncertain) |
        Q(job__sandbox_reservation__state__in=OCCUPIED))


def claim_available(company_id):
    _locked()
    caps, occupied = limits(), occupied_runs()
    return occupied.count() < caps['active_global'] and occupied.filter(prompt__company_id=company_id).count() < caps['active_company']


def provider_key(engine):
    # Identical credentials at one destination share a quota even when stored
    # as separate company connections. Neither key nor endpoint enters traces.
    endpoint = engine.engine.base_url or {'openai': 'https://api.openai.com/v1',
        'openai_compatible': 'https://api.openai.com/v1',
        'vercel_gateway': 'https://ai-gateway.vercel.sh/v1'}.get(engine.engine.connector_type, '')
    parsed = urlsplit(endpoint.rstrip('/'))
    endpoint = urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, parsed.query, ''))
    return digest([endpoint, digest(engine.api_key)])


def reserve_provider(record, engine):
    key = provider_key(engine)
    with admission_lock():
        current = AgentInference.objects.select_for_update().get(pk=record.pk)
        previous = current.response.get('_capacity')
        if previous:
            # A reservation replay is never permission for a second dispatch.
            raise AgentDenied('provider_reservation_already_exists')
        used = AgentInference.objects.filter(response___capacity__key=key,
            response___capacity__state__in=OCCUPIED).count()
        if used >= limits()['provider']:
            raise CapacityDenied('agent_provider_saturated')
        value = {'version': 1, 'key': key, 'state': 'active', 'reserved_at': timezone.now().isoformat(),
            'attempt': str(record.attempt), 'transport_finished_at': None}
        current.response = {**current.response, '_capacity': value}
        current.save(update_fields=['response'])
        record.response = {**record.response, '_capacity': value}
        return value


def finish_provider(record, *, transport_finished):
    """Merge with the caller's final response, retaining occupancy on uncertainty."""
    if type(transport_finished) is not bool:
        raise ValueError('invalid_provider_transport_state')
    with admission_lock():
        stored = AgentInference.objects.select_for_update().get(pk=record.pk)
        value = stored.response.get('_capacity')
        if value is None:
            return
        if value['state'] != 'released':
            value = {**value, 'state': 'released' if transport_finished else 'uncertain'}
            if transport_finished:
                value['transport_finished_at'] = timezone.now().isoformat()
        record.response = {**record.response, '_capacity': value}
        # Keep the durable reservation correct even if final receipt persistence
        # crashes. Never make a failed effect appear completed here.
        stored.response = {**stored.response, '_capacity': value}
        stored.save(update_fields=['response'])


def validate_reconciliation(actor, reason, evidence_reference, kind):
    reasons = {'provider': ('response_finished', 'cancellation_confirmed', 'operator_review'),
        'sandbox': ('destruction_confirmed', 'ttl_confirmed', 'operator_review')}
    if (not actor.is_active or not actor.is_superuser or reason not in reasons.get(kind, ()) or
            not isinstance(evidence_reference, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/#-]{0,199}', evidence_reference)):
        raise AgentDenied('capacity_reconciliation_denied')


def reconcile_provider(record_id, actor, reason, evidence_reference):
    """Operator evidence releases occupancy only; result and money remain intact."""
    validate_reconciliation(actor, reason, evidence_reference, 'provider')
    with admission_lock():
        row = AgentInference.objects.select_for_update().get(pk=record_id)
        value = row.response.get('_capacity')
        if value is None:
            raise AgentDenied('provider_reservation_missing')
        if value['state'] == 'released':
            return value
        value = {**value, 'state': 'released', 'reconciliation': {'actor_id': actor.pk,
            'reason': reason, 'evidence_reference': evidence_reference, 'recorded_at': timezone.now().isoformat()}}
        row.response = {**row.response, '_capacity': value}
        row.save(update_fields=['response'])
        return value


def _uuid(value):
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise AgentDenied('sandbox_reservation_invalid') from None


def _sandbox_id(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', value):
        raise AgentDenied('sandbox_reservation_invalid')
    return value


def _current_reservation(run, payload):
    value = run.job.get('sandbox_reservation')
    if (not value or value['reservation_id'] != _uuid(payload.get('reservation_id')) or
            value['worker_id'] != str(run.worker_id) or value['attempt'] != str(run.attempt)):
        raise AgentDenied('sandbox_reservation_mismatch')
    return value


def sandbox_operation(run, payload):
    """Execution authorization occurs before entry; reservation is never a grant."""
    action = payload.get('action')
    expected = {'action', 'reservation_id'} | ({'sandbox_id', 'ttl_seconds'} if action in ('attach', 'renew') else
        {'sandbox_id', 'duration_ms'} if action == 'prepared' else set())
    if action == 'attach' and 'duration_ms' in payload:
        expected.add('duration_ms')
    if action not in ('reserve', 'attach', 'renew', 'prepared') or set(payload) != expected:
        raise ValueError('sandbox_request_invalid')
    if 'duration_ms' in payload and (type(payload['duration_ms']) is not int or not 0 <= payload['duration_ms'] <= 3600000):
        raise ValueError('sandbox_duration_invalid')
    reservation_id = _uuid(payload['reservation_id'])
    with admission_lock():
        current = AgentExecution.objects.select_for_update().get(pk=run.pk)
        if current.status != 'active' or current.attempt != run.attempt or current.worker_id != run.worker_id or current.expires_at <= timezone.now():
            raise AgentDenied('attempt_not_active')
        previous = current.job.get('sandbox_reservation')
        if action == 'reserve':
            if previous:
                if (previous['reservation_id'] != reservation_id or previous['attempt'] != str(run.attempt)
                        or previous['worker_id'] != str(run.worker_id) or previous['state'] == 'released'):
                    raise AgentDenied('sandbox_reservation_mismatch')
                # Reserved/attached replay refers to the same physical creation;
                # the worker must not create another VM after an uncertain call.
                return {'status': 'authorized', 'available': True, 'reservation_id': reservation_id,
                    'sandbox_id': previous.get('sandbox_id'), 'replay': True}
            used = AgentExecution.objects.filter(job__sandbox_reservation__state__in=OCCUPIED).count()
            if used >= limits()['sandbox']:
                return {'status': 'authorized', 'available': False, 'reservation_id': reservation_id}
            value = {'version': 1, 'reservation_id': reservation_id, 'worker_id': str(run.worker_id),
                'attempt': str(run.attempt), 'sandbox_id': None, 'state': 'reserved',
                'reserved_at': timezone.now().isoformat(), 'expires_at': None}
        else:
            value = _current_reservation(current, payload)
            identifier = _sandbox_id(payload['sandbox_id'])
            if value['state'] == 'released':
                raise AgentDenied('sandbox_reservation_invalid')
            if value.get('sandbox_id') not in (None, identifier) or (action in ('renew', 'prepared') and value.get('sandbox_id') is None):
                raise AgentDenied('sandbox_reservation_mismatch')
            if action == 'prepared':
                value = {**value, 'preparation_duration_ms': payload['duration_ms']}
            else:
                ttl = payload['ttl_seconds']
                if type(ttl) is not int or not 1 <= ttl <= 180:
                    raise AgentDenied('sandbox_reservation_invalid')
                value = {**value, 'sandbox_id': identifier, 'state': 'active',
                    'expires_at': (timezone.now() + timedelta(seconds=ttl)).isoformat()}
            if 'duration_ms' in payload:
                from .jobs import event
                kind = 'sandbox_prepared' if action == 'prepared' else 'sandbox_acquired'
                if not current.events.filter(kind=kind, data__reservation_id=reservation_id).exists():
                    event(current, kind, reservation_id=reservation_id, duration_ms=payload['duration_ms'],
                        category='preparation', execution_id=str(current.pk), attempt=str(current.attempt), resource='sandbox')
        current.job = {**current.job, 'sandbox_reservation': value}
        current.save(update_fields=['job'])
        run.job = current.job
        return {'status': 'authorized' if action == 'reserve' else 'completed',
            'available': True, 'reservation_id': reservation_id}


def sandbox_cleanup(payload):
    """Worker authentication is required by the endpoint, not the revoked run."""
    if set(payload) != {'execution', 'attempt', 'worker_id', 'reservation_id', 'sandbox_id', 'destroyed'} or payload['destroyed'] is not True:
        raise ValueError('sandbox_cleanup_invalid')
    with admission_lock():
        current = AgentExecution.objects.select_for_update().filter(pk=_uuid(payload['execution'])).first()
        value = current.job.get('sandbox_reservation') if current else None
        if (not value or any(value[key] != _uuid(payload[key]) for key in ('attempt', 'worker_id', 'reservation_id'))
                or value.get('sandbox_id') != _sandbox_id(payload['sandbox_id'])):
            raise AgentDenied('sandbox_cleanup_mismatch')
        if value['state'] != 'released':
            value = {**value, 'state': 'released', 'destroyed_at': timezone.now().isoformat()}
            current.job = {**current.job, 'sandbox_reservation': value}
            current.save(update_fields=['job'])
        return {'status': 'completed', 'reservation_id': value['reservation_id']}


def reconcile_sandbox(execution_id, actor, reason, evidence_reference):
    """Release an orphaned/uncertain VM only after recorded operator evidence."""
    validate_reconciliation(actor, reason, evidence_reference, 'sandbox')
    with admission_lock():
        run = AgentExecution.objects.select_for_update().get(pk=execution_id)
        value = run.job.get('sandbox_reservation')
        if value is None:
            raise AgentDenied('sandbox_reservation_missing')
        if value['state'] == 'released':
            return value
        value = {**value, 'state': 'released', 'reconciliation': {'actor_id': actor.pk,
            'reason': reason, 'evidence_reference': evidence_reference, 'recorded_at': timezone.now().isoformat()}}
        run.job = {**run.job, 'sandbox_reservation': value}
        run.save(update_fields=['job'])
        return value
