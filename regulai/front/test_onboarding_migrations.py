from decimal import Decimal

from django.core.exceptions import ValidationError
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase

from .models import Engine, EngineModel


class PriceUnitsTests(TestCase):
    def test_price_per_token_is_rejected_and_free_or_per_million_price_is_valid(self):
        engine = Engine.objects.create(name='Price boundary')
        model = EngineModel(engine=engine, name='Price', model_id='price')
        for value in ('0.00000001', '0.00009999'):
            model.input_price = Decimal(value)
            with self.assertRaises(ValidationError):
                model.full_clean()
        for value in ('0', '0.0001', '2.50'):
            model.input_price = model.output_price = Decimal(value)
            model.full_clean()


class PriceUnitsMigrationTests(TransactionTestCase):
    def test_old_prices_survive_forward_and_reverse_and_units_are_explicit(self):
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        old_target = [('front', '0028_auditlog_company')]
        target = [('front', '0029_model_price_units')]
        try:
            executor.migrate(old_target)
            old = executor.loader.project_state(old_target).apps
            engine = old.get_model('front', 'Engine').objects.create(name='Old prices')
            model = old.get_model('front', 'EngineModel').objects.create(engine_id=engine.pk,
                name='Old', model_id='old', input_price=Decimal('2.5'), output_price=Decimal('0'))
            executor = MigrationExecutor(connection)
            executor.migrate(target)
            migrated = executor.loader.project_state(target).apps.get_model('front', 'EngineModel')
            retained = migrated.objects.get(pk=model.pk)
            self.assertEqual(retained.input_price, Decimal('2.5'))
            self.assertEqual(retained.output_price, Decimal('0'))
            self.assertIn('USD per million', migrated._meta.get_field('input_price').help_text)
            retained.input_price = Decimal('0.00001')
            with self.assertRaises(ValidationError):
                retained.full_clean()
            MigrationExecutor(connection).migrate(old_target)
            self.assertEqual(old.get_model('front', 'EngineModel').objects.get(pk=model.pk).input_price, Decimal('2.5'))
        finally:
            MigrationExecutor(connection).migrate(latest)


class ReasoningMigrationTests(TransactionTestCase):
    def test_existing_models_default_to_no_reasoning_and_reverse_preserves_catalog(self):
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        old_target = [('front', '0029_model_price_units')]
        target = [('front', '0030_enginemodel_reasoning')]
        try:
            executor.migrate(old_target)
            old = executor.loader.project_state(old_target).apps
            engine = old.get_model('front', 'Engine').objects.create(name='Reasoning catalog')
            model = old.get_model('front', 'EngineModel').objects.create(engine_id=engine.pk,
                name='Existing', model_id='existing', input_price=Decimal('1'))
            executor = MigrationExecutor(connection)
            executor.migrate(target)
            migrated = executor.loader.project_state(target).apps.get_model('front', 'EngineModel')
            self.assertFalse(migrated.objects.get(pk=model.pk).reasoning)
            migrated.objects.filter(pk=model.pk).update(reasoning=True)
            MigrationExecutor(connection).migrate(old_target)
            self.assertEqual(old.get_model('front', 'EngineModel').objects.get(pk=model.pk).input_price, Decimal('1'))
        finally:
            MigrationExecutor(connection).migrate(latest)


class HistoricalCompanyMigrationTests(TransactionTestCase):
    def test_inference_preserves_decisions_relations_and_reverse_respects_later_changes(self):
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        old_target = [('front', '0030_enginemodel_reasoning')]
        target = [('front', '0031_infer_historical_prompt_company')]
        try:
            executor.migrate(old_target)
            old = executor.loader.project_state(old_target).apps
            Company = old.get_model('front', 'Company')
            User = old.get_model('auth', 'User')
            Prompt = old.get_model('front', 'Prompt')
            a = Company.objects.create(pk=2147483648, name='Historical A')
            b = Company.objects.create(name='Historical B')
            user = User.objects.create(username='historical-profile')
            orphan = User.objects.create(username='historical-no-profile')
            old.get_model('front', 'Profile').objects.create(user_id=user.pk, company_id=a.pk)
            conversation = old.get_model('front', 'Conversation').objects.create(user_id=user.pk)
            inferred = Prompt.objects.create(user_id=user.pk, conversation_id=conversation.pk,
                content='Retained', decision={'existing': 'preserved'}, file_name='retained.txt')
            changed = Prompt.objects.create(user_id=user.pk, content='Reassigned later')
            explicit = Prompt.objects.create(user_id=user.pk, company_id=b.pk, content='Explicit')
            missing = Prompt.objects.create(user_id=orphan.pk, content='No profile')
            response = old.get_model('front', 'Response').objects.create(prompt_id=inferred.pk, content='Answer retained')
            audit = old.get_model('front', 'AuditLog').objects.create(user_id=user.pk,
                action='historical', details='Unchanged original audit')
            executor = MigrationExecutor(connection)
            executor.migrate(target)
            migrated = executor.loader.project_state(target).apps.get_model('front', 'Prompt')
            row = migrated.objects.get(pk=inferred.pk)
            self.assertEqual(migrated._meta.get_field('historical_company_id').get_internal_type(), 'PositiveBigIntegerField')
            self.assertEqual((row.company_id, row.historical_company_id), (a.pk, a.pk))
            self.assertEqual(row.decision, {'existing': 'preserved'})
            self.assertEqual((row.conversation_id, row.file_name), (conversation.pk, 'retained.txt'))
            self.assertEqual(old.get_model('front', 'Response').objects.get(pk=response.pk).content, 'Answer retained')
            self.assertIsNone(migrated.objects.get(pk=explicit.pk).historical_company_id)
            self.assertIsNone(migrated.objects.get(pk=missing.pk).company_id)
            self.assertIsNone(old.get_model('front', 'AuditLog').objects.get(pk=audit.pk).company_id)
            migrated.objects.filter(pk=inferred.pk).update(decision={'later': 'preserved'})
            migrated.objects.filter(pk=changed.pk).update(company_id=b.pk)
            new = migrated.objects.create(user_id=user.pk, company_id=a.pk, content='New explicit')
            MigrationExecutor(connection).migrate(old_target)
            self.assertIsNone(Prompt.objects.get(pk=inferred.pk).company_id)
            self.assertEqual(Prompt.objects.get(pk=inferred.pk).decision, {'later': 'preserved'})
            self.assertEqual(Prompt.objects.get(pk=changed.pk).company_id, b.pk)
            self.assertEqual(Prompt.objects.get(pk=explicit.pk).company_id, b.pk)
            self.assertEqual(Prompt.objects.get(pk=new.pk).company_id, a.pk)
        finally:
            MigrationExecutor(connection).migrate(latest)
