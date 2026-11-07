"""PostgreSQL exclusion and capacity/money independence using synthetic rows."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import timedelta
from threading import Barrier, Event
import json
from statistics import median
import time
from unittest import skipUnless
import uuid

from django.contrib.auth import get_user_model
from django.db import close_old_connections, connection
from django.test import TransactionTestCase, override_settings, tag
from django.utils import timezone

from front.agents import capacity
from front.agents.service import AgentDenied
from front.models import AgentExecution, AgentInference, AgentModelProfile, Company, CompanyEngine, Engine, EngineModel, Prompt


@skipUnless(connection.vendor == 'postgresql', 'Distributed capacity exclusion requires PostgreSQL')
class CapacityTests(TransactionTestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user('capacity-synthetic')
        self.operator = get_user_model().objects.create_superuser('capacity-operator', password='synthetic')
        self.company = Company.objects.create(name='Capacity synthetic')
        engine = Engine.objects.create(name='Capacity synthetic', connector_type='openai', base_url='https://provider.invalid/v1')
        model = EngineModel.objects.create(engine=engine, name='Synthetic', model_id='synthetic')
        self.engine = CompanyEngine.objects.create(company=self.company, engine=engine, api_key='synthetic-provider-key')
        self.profile = AgentModelProfile.objects.create(company=self.company, name='Synthetic', connection=self.engine, model=model)

    def run_row(self, *, status='active', company=None):
        prompt = Prompt.objects.create(user=self.user, company=company or self.company, content='Synthetic',
            status='processing', decision={'calls': [], 'total': {'cost': None, 'known_cost': '0', 'complete': False}})
        return AgentExecution.objects.create(prompt=prompt, profile=self.profile, token_digest=uuid.uuid4().hex,
            authorization_digest='a' * 64, expires_at=timezone.now() + timedelta(minutes=5), status=status,
            worker_id=uuid.uuid4(), started_at=timezone.now() if status == 'active' else None)

    def inference(self, run):
        return AgentInference.objects.create(execution=run, call_id=uuid.uuid4(), attempt=run.attempt,
            request_digest='b' * 64, status='processing')

    def parallel(self, action, values):
        barrier = Barrier(len(values))
        def run(value):
            close_old_connections()
            try:
                barrier.wait(10)
                return action(value)
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=len(values)) as pool:
            return list(pool.map(run, values))

    @override_settings(REGULAY_AGENT_CAPACITY={'active_global': 1})
    def test_two_workers_cannot_claim_beyond_global_limit(self):
        rows = [self.run_row(status='queued') for _ in range(2)]
        def claim(pk):
            with capacity.admission_lock():
                row = AgentExecution.objects.select_for_update().get(pk=pk)
                if not capacity.claim_available(row.prompt.company_id):
                    return False
                row.status = 'active'
                row.save(update_fields=['status'])
                return True
        self.assertEqual(sorted(self.parallel(claim, [row.pk for row in rows])), [False, True])
        self.assertEqual(AgentExecution.objects.filter(status='active').count(), 1)

    @override_settings(REGULAY_AGENT_CAPACITY={'active_company': 1, 'queued_company': 1})
    def test_company_quota_does_not_block_other_company_and_queue_has_own_deadline(self):
        self.run_row()
        another = Company.objects.create(name='Another synthetic')
        with capacity.admission_lock():
            self.assertFalse(capacity.claim_available(self.company.pk))
            self.assertTrue(capacity.claim_available(another.pk))
        waiting = self.run_row(status='queued')
        with capacity.admission_lock():
            with self.assertRaises(capacity.CapacityDenied) as failure:
                capacity.admit_queue(self.company.pk)
            self.assertEqual(failure.exception.retry_after, 5)
            capacity.admit_queue(another.pk)
        AgentExecution.objects.filter(pk=waiting.pk).update(created_at=timezone.now() - timedelta(seconds=301))
        self.assertEqual(list(capacity.queue_expired().values_list('pk', flat=True)), [waiting.pk])

    def test_provider_admission_is_atomic_across_cancelled_runs(self):
        rows = [self.inference(self.run_row()) for _ in range(2)]
        def reserve(pk):
            row = AgentInference.objects.get(pk=pk)
            try:
                capacity.reserve_provider(row, self.engine)
                return True
            except capacity.CapacityDenied:
                return False
        self.assertEqual(sorted(self.parallel(reserve, [row.pk for row in rows])), [False, True])
        occupied = AgentInference.objects.get(response___capacity__state='active')
        AgentExecution.objects.filter(pk=occupied.execution_id).update(status='cancelled')
        other = next(row for row in rows if row.pk != occupied.pk)
        with self.assertRaises(capacity.CapacityDenied):
            capacity.reserve_provider(other, self.engine)
        self.assertIn(occupied.execution_id, capacity.occupied_runs().values_list('pk', flat=True))
        occupied.response = {'status': 'rejected', 'code': 'revoked', 'cost': None}
        capacity.finish_provider(occupied, transport_finished=True)
        occupied.save(update_fields=['response'])
        capacity.reserve_provider(other, self.engine)
        occupied.refresh_from_db()
        self.assertIsNone(occupied.response['cost'])
        self.assertEqual(occupied.response['_capacity']['state'], 'released')

    def test_equivalent_connector_aliases_share_the_same_provider_quota(self):
        from types import SimpleNamespace
        first = SimpleNamespace(api_key='synthetic-secret',
            engine=SimpleNamespace(connector_type='openai', base_url=None))
        alias = SimpleNamespace(api_key='synthetic-secret',
            engine=SimpleNamespace(connector_type='openai_compatible', base_url='https://API.OPENAI.COM/v1/'))
        self.assertEqual(capacity.provider_key(first), capacity.provider_key(alias))
        self.assertNotIn('synthetic-secret', capacity.provider_key(first))

    def test_uncertain_provider_requires_operator_evidence_without_changing_result_or_money(self):
        run = self.run_row()
        row = self.inference(run)
        capacity.reserve_provider(row, self.engine)
        row.status, row.response = 'outcome_unknown', {'status': 'outcome_unknown', 'cost': None}
        capacity.finish_provider(row, transport_finished=False)
        row.save(update_fields=['status', 'response'])
        before = deepcopy(run.prompt.decision)
        with self.assertRaises(AgentDenied):
            capacity.reconcile_provider(row.pk, self.user, 'operator_review', 'lab:ticket-17')
        value = capacity.reconcile_provider(row.pk, self.operator, 'operator_review', 'lab:ticket-17')
        self.assertEqual(value['state'], 'released')
        self.assertEqual(value['reconciliation']['actor_id'], self.operator.pk)
        self.assertEqual(capacity.reconcile_provider(row.pk, self.operator, 'operator_review', 'lab:ticket-17'), value)
        row.refresh_from_db()
        run.prompt.refresh_from_db()
        self.assertEqual(row.status, 'outcome_unknown')
        self.assertIsNone(row.response['cost'])
        self.assertEqual(run.prompt.decision, before)

    def test_sandbox_global_reservation_and_late_cleanup_after_revocation(self):
        rows = [self.run_row() for _ in range(2)]
        identifiers = {row.pk: str(uuid.uuid4()) for row in rows}
        def reserve(pk):
            run = AgentExecution.objects.get(pk=pk)
            return capacity.sandbox_operation(run, {'action': 'reserve', 'reservation_id': identifiers[pk]})['available']
        self.assertEqual(sorted(self.parallel(reserve, [row.pk for row in rows])), [False, True])
        run = AgentExecution.objects.get(job__sandbox_reservation__state='reserved')
        reservation = identifiers[run.pk]
        capacity.sandbox_operation(run, {'action': 'attach', 'reservation_id': reservation,
            'sandbox_id': 'synthetic-vm', 'ttl_seconds': 180})
        cleanup = {'execution': str(run.pk), 'attempt': str(run.attempt), 'worker_id': str(run.worker_id),
            'reservation_id': reservation, 'sandbox_id': 'synthetic-vm', 'destroyed': True}
        AgentExecution.objects.filter(pk=run.pk).update(status='cancelled', attempt=uuid.uuid4())
        with self.assertRaises(AgentDenied):
            capacity.sandbox_cleanup({**cleanup, 'worker_id': str(uuid.uuid4())})
        self.assertEqual(capacity.sandbox_cleanup(cleanup), capacity.sandbox_cleanup(cleanup))
        other = next(row for row in rows if row.pk != run.pk)
        self.assertTrue(capacity.sandbox_operation(other, {'action': 'reserve',
            'reservation_id': identifiers[other.pk]})['available'])

    def test_create_unknown_reservation_does_not_expire_on_worker_lease(self):
        run = self.run_row()
        capacity.sandbox_operation(run, {'action': 'reserve', 'reservation_id': str(uuid.uuid4())})
        AgentExecution.objects.filter(pk=run.pk).update(status='interrupted', expires_at=timezone.now() - timedelta(minutes=5))
        other = self.run_row()
        request = {'action': 'reserve', 'reservation_id': str(uuid.uuid4())}
        self.assertFalse(capacity.sandbox_operation(other, request)['available'])
        capacity.reconcile_sandbox(run.pk, self.operator, 'operator_review', 'lab:vm-inventory-17')
        self.assertTrue(capacity.sandbox_operation(other, request)['available'])

    def test_preparation_events_have_explicit_durations_and_replay_is_idempotent(self):
        run = self.run_row()
        reservation = str(uuid.uuid4())
        capacity.sandbox_operation(run, {'action': 'reserve', 'reservation_id': reservation})
        attached = {'action': 'attach', 'reservation_id': reservation, 'sandbox_id': 'synthetic-events',
            'ttl_seconds': 180, 'duration_ms': 42}
        prepared = {'action': 'prepared', 'reservation_id': reservation, 'sandbox_id': 'synthetic-events', 'duration_ms': 7}
        capacity.sandbox_operation(run, attached)
        capacity.sandbox_operation(run, attached)
        capacity.sandbox_operation(run, prepared)
        capacity.sandbox_operation(run, prepared)
        self.assertEqual(list(run.events.order_by('id').values_list('kind', 'data__duration_ms')),
            [('sandbox_acquired', 42), ('sandbox_prepared', 7)])

    def test_reconciliation_command_previews_then_releases_only_capacity(self):
        import io
        from django.core.management import call_command
        from django.core.management.base import CommandError
        run = self.run_row()
        row = self.inference(run)
        capacity.reserve_provider(row, self.engine)
        options = {'kind': 'provider', 'id': str(row.pk), 'actor_id': self.operator.pk,
            'reason': 'operator_review', 'evidence': 'lab:receipt-1', 'stdout': io.StringIO()}
        call_command('reconcile_agent_capacity', **options)
        row.refresh_from_db()
        self.assertEqual(row.response['_capacity']['state'], 'active')
        with self.assertRaises(CommandError):
            call_command('reconcile_agent_capacity', **{**options, 'evidence': 'invalid private prose'})
        call_command('reconcile_agent_capacity', apply=True, **options)
        row.refresh_from_db()
        self.assertEqual(row.status, 'processing')
        self.assertEqual(row.response['_capacity']['state'], 'released')

    @override_settings(REGULAY_AGENT_CAPACITY={'provider': 2})
    @tag('capacity_benchmark')
    def test_twenty_offline_barriers_allow_short_provider_call_before_long_finishes(self):
        import httpx
        from openai import OpenAI
        held, release = Event(), Event()
        captured, durations = [], []
        first, second = self.run_row(), self.run_row()
        reservation = str(uuid.uuid4())
        capacity.sandbox_operation(first, {'action': 'reserve', 'reservation_id': reservation})
        capacity.sandbox_operation(first, {'action': 'attach', 'reservation_id': reservation,
            'sandbox_id': 'synthetic-benchmark-vm', 'ttl_seconds': 180})

        def response(request):
            body = json.loads(request.content)
            captured.append(body)
            if body['messages'][0]['content'] == 'long':
                held.set()
                if not release.wait(10):
                    raise AssertionError('The short request did not complete before the barrier timeout.')
            return httpx.Response(200, json={'id': 'synthetic', 'object': 'chat.completion', 'created': 1,
                'model': 'synthetic', 'choices': [{'index': 0, 'message': {'role': 'assistant', 'content': 'done'},
                    'finish_reason': 'stop'}]})

        with httpx.Client(transport=httpx.MockTransport(response)) as http:
            sdk = OpenAI(api_key='synthetic-key', base_url='https://provider.invalid/v1', max_retries=0, http_client=http)
            def dispatch(pk, label):
                close_old_connections()
                try:
                    run = AgentExecution.objects.get(pk=pk)
                    row = self.inference(run)
                    capacity.reserve_provider(row, self.engine)
                    reply = sdk.chat.completions.create(model='synthetic',
                        messages=[{'role': 'user', 'content': label}], max_completion_tokens=64)
                    row.response = {'status': 'completed', 'content': reply.choices[0].message.content,
                        'usage': None, 'cost': None}
                    capacity.finish_provider(row, transport_finished=True)
                    row.status = 'completed'
                    row.save(update_fields=['status', 'response'])
                    return row.pk
                finally:
                    close_old_connections()
            with ThreadPoolExecutor(max_workers=2) as pool:
                for _ in range(20):
                    held.clear()
                    release.clear()
                    long = pool.submit(dispatch, first.pk, 'long')
                    self.assertTrue(held.wait(10))
                    try:
                        started = time.monotonic()
                        short = pool.submit(dispatch, second.pk, 'short')
                        short.result(10)
                        durations.append((time.monotonic() - started) * 1000)
                        self.assertFalse(long.done())
                        self.assertEqual(AgentExecution.objects.filter(job__sandbox_reservation__state='active').count(), 1)
                    finally:
                        release.set()
                    long.result(10)
        self.assertEqual(len(captured), 40)
        self.assertEqual(AgentInference.objects.filter(response___capacity__state__in=capacity.OCCUPIED).count(), 0)
        print(json.dumps({'capacity_offline': {'n': len(durations), 'condition': 'two_sdk_mock_calls_one_reserved_sandbox',
            'short_ms_median': round(median(durations), 3), 'short_ms_min': round(min(durations), 3),
            'short_ms_max': round(max(durations), 3), 'short_completed_before_release': 20,
            'errors': 0, 'real_provider_calls': 0, 'real_sandboxes': 0}}, sort_keys=True))
