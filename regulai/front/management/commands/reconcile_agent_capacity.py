"""Explicit operator evidence releases capacity, never an effect or its cost."""
import json

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from front.agents import capacity
from front.agents.service import AgentDenied
from front.models import AgentExecution, AgentInference


class Command(BaseCommand):
    help = 'Preview an evidenced provider/sandbox capacity reconciliation; --apply persists it.'

    def add_arguments(self, parser):
        parser.add_argument('--kind', choices=['provider', 'sandbox'], required=True)
        parser.add_argument('--id', required=True)
        parser.add_argument('--actor-id', type=int, required=True)
        parser.add_argument('--reason', required=True)
        parser.add_argument('--evidence', required=True)
        parser.add_argument('--apply', action='store_true')

    def handle(self, *args, **options):
        try:
            actor = get_user_model().objects.get(pk=options['actor_id'], is_active=True, is_superuser=True)
            kind = options['kind']
            capacity.validate_reconciliation(actor, options['reason'], options['evidence'], kind)
            row = (AgentInference if kind == 'provider' else AgentExecution).objects.get(pk=options['id'])
            value = row.response.get('_capacity') if kind == 'provider' else row.job.get('sandbox_reservation')
            if value is None:
                raise CommandError('The selected record has no capacity reservation.')
            if options['apply']:
                handler = capacity.reconcile_provider if kind == 'provider' else capacity.reconcile_sandbox
                value = handler(row.pk, actor, options['reason'], options['evidence'])
            self.stdout.write(json.dumps({'apply': options['apply'], 'kind': kind, 'id': str(row.pk),
                'state': value['state'], 'result_and_cost_unchanged': True}, ensure_ascii=False))
        except (get_user_model().DoesNotExist, AgentInference.DoesNotExist, AgentExecution.DoesNotExist,
                ValueError, TypeError, AgentDenied) as error:
            raise CommandError('Invalid reservation, operator or reconciliation evidence; no release was applied.') from error
