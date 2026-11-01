"""Explicit administrator provisioning; preview is the default."""
import json
from pathlib import Path
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from front.models import AgentAccessGrant, AgentModelProfile, Profile
from front.agents.capabilities import GENERAL, limits, search_configuration
from front.agents.service import AgentDenied
from front.agents.inference_options import configuration, resolve_inference


class Command(BaseCommand):
    help = 'Preview an explicit professional-agent grant. --apply is required to persist it.'

    def add_arguments(self, parser):
        parser.add_argument('--profile-id', type=int, required=True)
        parser.add_argument('--user-id', type=int, required=True)
        parser.add_argument('--search-config-file', type=Path)
        parser.add_argument('--limits-file', type=Path)
        parser.add_argument('--disable', action='store_true')
        parser.add_argument('--apply', action='store_true')

    def handle(self, *args, **options):
        try:
            account = Profile.objects.select_related('user').get(user_id=options['user_id'])
            profile = AgentModelProfile.objects.select_related('connection', 'model').get(pk=options['profile_id'])
            if account.company_id != profile.company_id or profile.connection.company_id != profile.company_id:
                raise CommandError('User, profile and connection must belong to the same company.')
            if profile.model.engine_id != profile.connection.engine_id:
                raise CommandError('Model must belong to the profile connection.')
            if options['search_config_file']:
                profile.search_config = options['search_config_file'].read_text(encoding='utf-8')
            if profile.search_config and not options['disable']:
                search_configuration(profile)
            if options['limits_file']:
                profile.limits = json.loads(options['limits_file'].read_text(encoding='utf-8'))
            budget = limits(profile)
            inference = configuration(profile)
            enabled = not options['disable']
            if enabled and set(inference.profiles) - {'legacy'}:
                from front.policy import AIConfig
                cfg = AIConfig.model_validate(account.company.ai_config)
                for selection in inference.profiles:
                    resolve_inference(profile, profile.model, cfg, selection)
            summary = {'apply': options['apply'], 'user_id': account.user_id, 'company_id': profile.company_id,
                'profile_id': profile.pk, 'enabled': enabled, 'tools': sorted(GENERAL), 'limits': budget,
                'inference_profiles': inference.profiles, 'inference': inference.model_dump(),
                'work_profiles': profile.limits.get('work_profiles', False),
                'search_configured': bool(profile.search_config), 'requires_global_flags_and_destination_policy': True}
            if options['apply']:
                with transaction.atomic():
                    AgentModelProfile.objects.select_for_update().get(pk=profile.pk)
                    if enabled:
                        profile.professional, profile.tools = True, sorted(GENERAL)
                        profile.enabled = True
                        profile.save(update_fields=['professional', 'enabled', 'tools', 'limits', 'search_config'])
                    grant, created = AgentAccessGrant.objects.select_for_update().get_or_create(
                        company_id=account.company_id, user_id=account.user_id, defaults={'profile': profile})
                    grant.profile, grant.enabled, grant.version = profile, enabled, grant.version + (0 if created else 1)
                    grant.save()
            self.stdout.write(json.dumps(summary, ensure_ascii=False))
        except (Profile.DoesNotExist, AgentModelProfile.DoesNotExist, ValueError, OSError, AgentDenied) as error:
            raise CommandError('Invalid profile, account or configuration file; no grant was applied.') from error
