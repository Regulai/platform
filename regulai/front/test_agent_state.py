"""Durable inference/alias races and additive migration on isolated databases."""
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from threading import Event, Barrier
from unittest import skipUnless
import uuid

from django.db import close_old_connections, connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase, override_settings

from front.agents.aliases import alias_value
from front.agents.service import AgentDenied, infer
from front.models import AgentExecution, AgentInference, ConversationAlias
from front.test_agent_inference import AgentFixture


@override_settings(REGULAY_AGENT_ENABLED=True)
class AgentStateTests(AgentFixture, TransactionTestCase):
    def test_pending_claim_replay_never_dispatches_after_restart(self):
        request = self.request()
        from front.agents.protocol import InferenceRequest
        from front.policy import digest
        AgentInference.objects.create(execution=self.execution, call_id=request['call_id'],
            attempt=self.execution.attempt, request_digest=digest(InferenceRequest.model_validate(request).model_dump()),
            status='processing')
        AgentExecution.objects.filter(pk=self.execution.pk).update(active_call=request['call_id'])
        self.assertEqual(self.infer(request)['status'], 'outcome_unknown')
        with self.assertRaises(AgentDenied):
            self.infer()
        self.assertEqual(len(self.requests), 0)

    @skipUnless(connection.vendor == 'postgresql', 'Actual concurrency proof requires PostgreSQL')
    def test_concurrent_inference_replay_and_alias_creation(self):
        entered, release = Event(), Event()
        def block_provider():
            entered.set()
            if not release.wait(10):
                raise AssertionError('Concurrent request did not finish')
        self.after_request = block_provider
        request = self.request()
        def run():
            close_old_connections()
            try:
                return infer(self.token, self.execution.attempt, request)
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(run)
            self.assertTrue(entered.wait(10))
            second = pool.submit(run)
            try:
                replay = second.result(10)
                self.assertEqual(replay['status'], 'outcome_unknown')
                self.assertNotIn('_capacity', replay)
                with self.assertRaises(AgentDenied):
                    self.infer()  # Another identified call cannot race the ledger.
            finally:
                release.set()
            self.assertEqual(first.result(10)['status'], 'completed')
        self.assertEqual(self.infer(request)['status'], 'completed')
        self.assertEqual(len(self.requests), 1)
        self.prompt.refresh_from_db()
        self.assertEqual(Decimal(self.prompt.decision['total']['cost']), Decimal('0.00014'))
        barrier = Barrier(2)
        def alias():
            close_old_connections()
            try:
                execution = AgentExecution.objects.select_related('prompt').get(pk=self.execution.pk)
                barrier.wait(10)
                return alias_value(execution, 'ID', '12345678Z')
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: alias(), range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(ConversationAlias.objects.count(), 1)


class AgentMigrationTests(TransactionTestCase):
    def test_additive_migration_preserves_existing_accounts_and_conversation(self):
        latest = MigrationExecutor(connection).loader.graph.leaf_nodes()
        old = [('front', '0035_deepseek_service_catalog')]
        new = [('front', '0036_agent_inference')]
        executor = MigrationExecutor(connection)
        try:
            executor.migrate(old)
            apps = executor.loader.project_state(old).apps
            user = apps.get_model('auth', 'User').objects.create(username='migration-task49')
            company = apps.get_model('front', 'Company').objects.create(name='Keep policy', ai_config={'revision': 19})
            conversation = apps.get_model('front', 'Conversation').objects.create(user_id=user.pk, title='Keep conversation')
            executor = MigrationExecutor(connection)
            executor.migrate(new)
            apps = executor.loader.project_state(new).apps
            self.assertEqual(apps.get_model('front', 'Company').objects.get(pk=company.pk).ai_config, {'revision': 19})
            self.assertEqual(apps.get_model('front', 'Conversation').objects.get(pk=conversation.pk).title, 'Keep conversation')
            self.assertEqual(apps.get_model('front', 'AgentModelProfile').objects.count(), 0)
            executor.migrate(old)
            self.assertEqual(executor.loader.project_state(old).apps.get_model('front', 'Conversation').objects.count(), 1)
        finally:
            MigrationExecutor(connection).migrate(latest)
