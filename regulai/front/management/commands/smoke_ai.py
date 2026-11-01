"""The small synthetic rehearsal uses the same service, approval and ledger as evaluation."""
from django.core.management.base import BaseCommand

from front.evaluation import PILOT_MANIFEST, run_pilot


class Command(BaseCommand):
    help = 'Eight synthetic cases; offline by default. Historical approval never enables real calls.'

    def add_arguments(self, parser):
        parser.add_argument('--output', required=True)
        parser.add_argument('--manifest', default=str(PILOT_MANIFEST))
        parser.add_argument('--split', choices=['all', 'development', 'reserved'], default='all')
        parser.add_argument('--case', action='append', help='Stable case ID from the manifest; repeat to select several.')
        parser.add_argument('--real', action='store_true')
        parser.add_argument('--authorization')
        parser.add_argument('--max-usd')
        parser.add_argument('--preflight', action='store_true')

    def handle(self, *args, **options):
        return run_pilot(options, self.stdout)
