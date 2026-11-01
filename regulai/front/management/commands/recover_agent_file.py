"""Explicit import of one retained checkpoint member, without resuming work."""
import json
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from front.models import AgentExecution
from front.agents.file_continuity import recover_member
from front.agents.service import AgentDenied


class Command(BaseCommand):
    help = 'Preview one checkpoint file. --apply imports that file with current owner and policy checks.'

    def add_arguments(self, parser):
        parser.add_argument('--run-id', required=True)
        parser.add_argument('--member', required=True)
        parser.add_argument('--actor-id', required=True, type=int)
        parser.add_argument('--apply', action='store_true')

    def handle(self, *args, **options):
        try:
            run = AgentExecution.objects.select_related('prompt').get(pk=options['run_id'])
            actor = get_user_model().objects.get(pk=options['actor_id'])
            result = recover_member(actor, run, options['member'], apply=options['apply'])
        except (AgentExecution.DoesNotExist, get_user_model().DoesNotExist, AgentDenied, ValueError, KeyError) as exc:
            raise CommandError(str(exc)) from None
        self.stdout.write(json.dumps(result, ensure_ascii=False))
