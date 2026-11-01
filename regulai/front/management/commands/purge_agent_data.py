"""Erase expired professional execution contents, keeping minimal audit metadata."""
from datetime import timedelta
import json
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone
from front.models import AgentExecution, AgentInput, AgentToolResult, AgentOperation, AgentInference, AgentArtifact, AgentEvent


class Command(BaseCommand):
    help = 'Preview expired professional run contents. --apply erases their protected bytes; never active runs.'

    def add_arguments(self, parser):
        parser.add_argument('--apply', action='store_true')
        parser.add_argument('--run-id', action='append', default=[])

    def handle(self, *args, **options):
        query = AgentExecution.objects.filter(job__kind='professional', status__in=('completed', 'failed', 'cancelled', 'interrupted'))
        if options['run_id']:
            query = query.filter(pk__in=options['run_id'])
        erased, expired = [], []
        for candidate in query.iterator():
            days = candidate.job.get('limits', {}).get('retention_days', 30)
            if candidate.job.get('expired') or (candidate.finished_at or candidate.created_at) > timezone.now() - timedelta(days=days):
                continue
            expired.append(str(candidate.pk))
            if not options['apply']:
                continue
            with transaction.atomic():
                run = AgentExecution.objects.select_for_update().get(pk=candidate.pk)
                days = run.job.get('limits', {}).get('retention_days', 30)
                if (run.status not in ('completed', 'failed', 'cancelled', 'interrupted') or run.job.get('expired')
                        or (run.finished_at or run.created_at) > timezone.now() - timedelta(days=days)):
                    continue
                run.job.update(expired=True, expired_at=timezone.now().isoformat())
                run.save(update_fields=['job'])
                # Keep FK lineage and hashes; downloads/previews are revoked.
                AgentInput.objects.filter(execution=run).update(original='')
                AgentToolResult.objects.filter(execution=run).update(raw='', protected_view='', view={})
                AgentOperation.objects.filter(execution=run).update(request='', result='')
                AgentEvent.objects.filter(execution=run).update(public_text='')
                for record in AgentInference.objects.filter(execution=run):
                    record.response = {key: value for key, value in record.response.items() if key in ('status', 'code', 'usage', 'inference', '_capacity')}
                    record.save(update_fields=['response'])
                for artifact in run.artifacts.all():
                    artifact.content, artifact.render_bundle, artifact.filename = '', '', ''
                    artifact.verification = {key: value for key, value in artifact.verification.items()
                        if key in ('contract', 'sha256', 'format', 'bytes', 'pages', 'pdf_sha256', 'docx_sha256', 'page_sha256')}
                    artifact.verification['expired'] = True
                    artifact.save(update_fields=['content', 'render_bundle', 'filename', 'verification'])
                erased.append(str(run.pk))
        # Copies and extracts inherit their source deadline. A later conversation
        # turn never extends retention, even when that turn remains active.
        from front.agents.file_continuity import expires_at
        copied = []
        for artifact in AgentArtifact.objects.filter(verification__origin_expires_at__isnull=False).select_related('execution').iterator():
            if artifact.verification.get('expired') or expires_at(artifact) > timezone.now():
                continue
            if options['run_id'] and str(artifact.execution_id) not in options['run_id'] and artifact.verification.get('origin_run') not in options['run_id']:
                continue
            copied.append(str(artifact.pk))
            if options['apply']:
                artifact.content, artifact.render_bundle, artifact.filename = '', '', ''
                artifact.verification = {key: value for key, value in artifact.verification.items()
                    if key in ('contract', 'purpose', 'sha256', 'format', 'bytes', 'origin_expires_at', 'origin_run')}
                artifact.verification['expired'] = True
                artifact.save(update_fields=['content', 'render_bundle', 'filename', 'verification'])
        expired_inputs = []
        for row in AgentInput.objects.filter(kind__in=('policy_text', 'manifest')).iterator():
            if not row.original:
                continue
            try:
                value = json.loads(row.original)
            except (ValueError, TypeError):
                continue
            refs = [value] if row.kind == 'policy_text' else value.get('files', [])
            artifact_ids = [item.get('artifact_id') for item in refs if isinstance(item, dict) and item.get('artifact_id')]
            if not artifact_ids:
                continue
            stale = AgentArtifact.objects.filter(pk__in=artifact_ids, verification__expired=True)
            if options['run_id']:
                from django.db.models import Q
                stale = stale.filter(Q(execution_id__in=options['run_id']) | Q(verification__origin_run__in=options['run_id']))
            if stale.exists():
                expired_inputs.append(str(row.pk))
                if options['apply']:
                    row.original = ''
                    row.save(update_fields=['original'])
        from front.agents.event_store import compact_expired_text
        from django.db.models import Q
        text_runs = AgentExecution.objects.filter(events__kind='text.delta',
            events__created_at__lt=timezone.now()-timedelta(hours=24)).filter(
                Q(job__expired__isnull=True) | Q(job__expired=False)).distinct()
        if options['run_id']:
            text_runs = text_runs.filter(pk__in=options['run_id'])
        compacted = []
        for run in text_runs.iterator():
            compacted.append(str(run.pk))
            if options['apply']:
                compact_expired_text(run)
        self.stdout.write(json.dumps({'apply': options['apply'], 'eligible_runs': expired, 'erased_runs': erased,
            'text_snapshot_runs': compacted,
            'expired_copies': copied, 'expired_reference_inputs': expired_inputs}))
