"""Generate a reviewable draft; activation belongs to the policy simulator."""
import json

from django.core.management.base import BaseCommand, CommandError

from front.models import Company, CompanyEngine, ObfuscationConfig, Rule
from front.policy import AIConfig


def initial_policy(company):
    config = AIConfig(local_sensitivity='internal').model_dump()
    warnings = ['Model quality is uncalibrated: record measured task quality before routing. '
        'Review this draft in the simulator before activation.']
    engines = CompanyEngine.objects.filter(company=company, active=True).select_related('engine').order_by('pk')
    destinations, candidates = [], []
    for linked in engines:
        models = list(linked.engine.models.filter(active=True).order_by('pk'))
        if not linked.api_key:
            warnings.append(f'Engine {linked.pk}: generation credentials are missing.')
        if not models:
            warnings.append(f'Engine {linked.pk}: no active models are configured.')
            continue
        destinations.append(f'engine:{linked.pk}')
        for model in models:
            if model.context_window is None or model.max_tokens <= 0:
                warnings.append(f'Model {model.pk}: context/output capacity is missing.')
            if not model.supports_json:
                warnings.append(f'Model {model.pk}: structured JSON output is not enabled.')
            if model.input_price is None or model.output_price is None:
                warnings.append(f'Model {model.pk}: USD prices per million tokens are missing; budgets will block routing.')
            if model.currency != 'USD' or model.price_date is None:
                warnings.append(f'Model {model.pk}: verify USD currency and price date.')
            if len(candidates) < 64:
                candidates.append({'company_engine_id': linked.pk, 'model_id': model.pk,
                    'level': 'economy', 'quality': {}})
            else:
                warnings.append(f'Model {model.pk}: omitted from draft because the policy permits at most 64 candidates.')
    masks = list(ObfuscationConfig.objects.filter(company=company, active=True).order_by('pk'))
    if not masks:
        warnings.append('Required masking is missing: configure an active company obfuscator for PII and secrets before sending.')
    elif all(mask.backend == 'local' for mask in masks):
        config['masking']['max_call_cost'] = '0'
    for mask in masks:
        destinations.append(f'obfuscation:{mask.pk}')
        if mask.backend == 'local':
            warnings.append(f'Obfuscator {mask.pk}: local API cost is zero; explicit patterns only, without statistical name detection.')
        else:
            warnings.append(f'Obfuscator {mask.pk}: set a contractual maximum call cost before enabling a budget.')
        if mask.detect != 'both':
            warnings.append(f'Obfuscator {mask.pk}: mandatory masking requires both PII and secrets.')
    if not candidates:
        warnings.append('No active generation candidates are available.')
    if not Rule.objects.filter(rules_group__company=company, active=True).exists():
        warnings.append('No active company YARA rules: the empty-rule guard remains enabled.')
    config['destinations'] = {'public': destinations, 'internal': destinations,
        'confidential': [], 'restricted': [], 'unknown': []}
    config['routing']['candidates'] = candidates
    return AIConfig.model_validate(config).model_dump(), warnings


class Command(BaseCommand):
    help = 'Output a conservative company AI policy draft; never activate it or call a provider.'

    def add_arguments(self, parser):
        parser.add_argument('--company', type=int, required=True)
        parser.add_argument('--dry-run', action='store_true', help='Preview only; the command always leaves active policy unchanged.')

    def handle(self, *args, **options):
        try:
            company = Company.objects.get(pk=options['company'])
        except Company.DoesNotExist:
            raise CommandError('Company does not exist.') from None
        config, warnings = initial_policy(company)
        self.stdout.write(json.dumps({'proposed_config': config, 'bootstrap_warnings': warnings}, indent=2))
