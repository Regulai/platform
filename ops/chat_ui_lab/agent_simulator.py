"""Lab-only stand-in for the agent worker, so agent requests can be tried by hand.

The UI lab has no worker, sandbox or PostgreSQL: without this loop a new agent request
stays queued. It moves document runs through the worker's registered steps on the lab
database, one step every few seconds:

    queued → claimed → compose → render → verify → visual review pending
    (the person confirms the review in the page) → completed

The deliverable is always a fixed sample from the task-55 fixtures (a report, or a
deck for presentation requests). It is never generated from the request, and the run's
own steps say so. Spreadsheets, Drive exports and the professional agent are not
simulated: those runs fail with an explicit lab message. No model or network is used.

    cd regulai && set DJANGO_SETTINGS_MODULE=regulai.ui_lab_settings
    python ../ops/chat_ui_lab/agent_simulator.py
"""
from datetime import timedelta
import os
from pathlib import Path
import sys
import time
import uuid

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / 'regulai'))
sys.path.insert(0, str(HERE))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'regulai.ui_lab_settings')

STEP_SECONDS = 2.5
CLAIMED = 'Laboratorio: un simulador sustituye al worker. El entregable será un documento de muestra fijo.'
REVIEW = ('Laboratorio: documento de muestra fijo, no generado a partir de tu petición. '
          'Revisa todas las páginas antes de publicar.')
UNSUPPORTED = ('Laboratorio: el simulador solo reproduce informes Word/PDF y presentaciones. '
               'Hojas Excel, exportaciones a Drive y el agente profesional necesitan el worker real.')


def sample_kind(run):
    """'report', 'deck' or None (not simulated)."""
    from front.models import AgentArtifact
    if run.job.get('kind') not in ('create', 'rename'):
        return None
    if run.job.get('base'):
        base = AgentArtifact.objects.filter(pk=run.job['base']).first()
        formats = [base.format] if base else []
    else:
        formats = list((run.job.get('request') or {}).get('formats') or [])
    if 'pptx' in formats:
        return 'deck'
    if formats and set(formats) <= {'docx', 'pdf'}:
        return 'report'
    return None


def fail(run, now):
    from front.models import AgentEvent, Prompt
    run.status, run.finished_at = 'failed', now
    run.save(update_fields=['status', 'finished_at'])
    Prompt.objects.filter(pk=run.prompt_id).update(status='failed', updated_at=now)
    AgentEvent.objects.create(execution=run, kind='failed', data={'text': UNSUPPORTED})
    print(f'  · {run.pk}: not simulated ({run.job.get("kind")})', flush=True)


def complete(run, artifact):
    """What the worker's completion records (jobs.complete), for a verified sample."""
    from front.agents.jobs import _terminal, verification_checks
    from front.models import Message, Response
    message = Message.objects.create(conversation=run.conversation, role='assistant',
        content='Documento de muestra del laboratorio disponible. No se ha generado a partir de la petición.')
    Response.objects.create(prompt=run.prompt, assistant_message=message, content=message.content,
                            evidence={'artifact': str(artifact.pk), 'sha256': artifact.sha256})
    run.prompt.decision['verification'] = {'status': 'partial', 'checks': verification_checks(artifact),
                                           'sha256': artifact.sha256, 'artifact': str(artifact.pk)}
    run.prompt.save(update_fields=['decision'])
    _terminal(run, 'completed')
    print(f'  · {run.pk}: completed after the visual review', flush=True)


def advance(run, now):
    from front.agents.jobs import event
    from front.agents.service import AgentDenied
    from front.models import AgentArtifact, AgentEvent, Prompt
    from seed import document_artifact
    events = list(run.events.order_by('id').values_list('kind', 'created_at'))
    kinds = [kind for kind, _ in events]
    if run.status == 'queued':
        if sample_kind(run) is None:
            return fail(run, now)
        run.status, run.started_at = 'active', run.started_at or now
        run.claim_id, run.worker_id = run.claim_id or uuid.uuid4(), run.worker_id or uuid.uuid4()
        run.expires_at = now + timedelta(minutes=55)
        run.save(update_fields=['status', 'started_at', 'claim_id', 'worker_id', 'expires_at'])
        Prompt.objects.filter(pk=run.prompt_id).update(status='processing', updated_at=now)
        AgentEvent.objects.create(execution=run, kind='claimed', data={'text': CLAIMED})
        print(f'  · {run.pk}: claimed', flush=True)
        return
    if events and (now - events[-1][1]).total_seconds() < STEP_SECONDS:
        return
    for kind in ('compose', 'render', 'verify'):
        if kind not in kinds:
            event(run, kind)
            return
    artifact = run.artifacts.order_by('-revision').first()
    if artifact is None:
        kind = sample_kind(run)
        if kind is None:
            return fail(run, now)
        base = AgentArtifact.objects.filter(pk=run.job.get('base')).first() if run.job.get('base') else None
        try:
            # Re-binds the run to its re-evaluated authorization, like document_jobs.candidate.
            artifact = document_artifact(run, reviewed=False, revision=base.revision + 1 if base else 1,
                                         logical=run.job['logical_id'], kind=kind)
        except AgentDenied:
            return fail(run, now)
        AgentEvent.objects.create(execution=run, kind='visual_pending', data={'text': REVIEW, 'reference': str(artifact.pk)})
        print(f'  · {run.pk}: sample {kind} waiting for the visual review', flush=True)
    elif artifact.status == 'verified' and 'completed' not in kinds:
        complete(run, artifact)


def main():
    raise SystemExit('Simulador retirado: no genera documentos a partir de la petición. Arranca el worker real front.agents.worker con su configuración E2B.')


def run_acceptance_simulator():
    """Explicit test harness only; never the interactive application's worker."""
    import django
    django.setup()
    from django.conf import settings
    from django.utils import timezone
    from front.models import AgentExecution
    database = Path(settings.DATABASES['default']['NAME'])
    if settings.SETTINGS_MODULE != 'regulai.ui_lab_settings' or not database.resolve().is_relative_to(settings.LAB_DIR.resolve()):
        raise SystemExit('The agent simulator only runs on the UI lab database.')
    print(f'LAB AGENT SIMULATOR (no model, no network): {database}', flush=True)
    while True:
        try:
            for run in AgentExecution.objects.filter(status__in=('queued', 'active'), conversation__isnull=False
                                                     ).select_related('prompt', 'conversation').order_by('created_at'):
                advance(run, timezone.now())
        except Exception as error:  # A busy SQLite file or a run changed by the page: retry next tick.
            print(f'  · retry: {type(error).__name__}: {error}', flush=True)
        time.sleep(1)


if __name__ == '__main__':
    main()
