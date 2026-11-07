"""Explicitly append approved data scope to the fixed, shared real-test ledger."""
import json

from django.core.management.base import BaseCommand, CommandError

from front import evaluation
from front.evaluation_budget import EvaluationBudget


class Command(BaseCommand):
    help = 'Validate a scope extension; --apply explicitly registers it without resetting spend.'
    requires_system_checks = []

    def add_arguments(self, parser):
        parser.add_argument('--manifest', required=True)
        parser.add_argument('--authorization', required=True)
        parser.add_argument('--apply', action='store_true')

    def handle(self, *args, **options):
        def validate():
            check, approval = evaluation.preflight(options['manifest'], options['authorization'], check_credentials=False)
            if not check['ready_for_real'] or 'extends' not in approval:
                raise CommandError('Scope extension blocked: ' + ', '.join(check['blockers'] or ['explicit_extension_required']))
            return check, approval

        check, approval = validate()
        report = {'mode': 'validation_only', 'ledger_mutated': False, 'network_calls': 0,
            'ledger': str(evaluation.LEDGER_PATH), 'authorization_id': approval['authorization_id'],
            'authorization_digest': evaluation.digest(approval), 'previous': approval['extends'],
            'manifest_sha256': check['manifest_sha256'], 'maximum_usd': check['maximum_usd'],
            'ledger_head_checked': False}
        if options['apply']:
            # The default path never opens the ledger, even for DDL. Recheck the
            # approval under the same exclusive lock used by the real runner.
            with evaluation.real_lock():
                check, approval = validate()
                if evaluation.digest(approval) != report['authorization_digest']:
                    raise CommandError('Authorization changed while waiting for the ledger lock; review it again.')
                try:
                    created = EvaluationBudget.extend_authorization(evaluation.LEDGER_PATH, approval['maximum_usd'],
                        previous_id=approval['extends']['authorization_id'],
                        previous_digest=approval['extends']['authorization_digest'],
                        authorization_id=approval['authorization_id'], authorization_digest=evaluation.digest(approval),
                        manifest_sha256=check['manifest_sha256'], approval_reference=approval['approval_reference'],
                        max_external_calls=approval['execution_scope']['max_external_calls'])
                except ValueError as error:
                    raise CommandError(str(error)) from None
            report.update(mode='registered', ledger_mutated=created, ledger_head_checked=True)
        self.stdout.write(json.dumps(report, indent=2))
