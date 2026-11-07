"""Server-owned delivery receipts. Model prose cannot grant file access."""
import re

from django.urls import reverse
from front.policy import evaluate_policy
from .service import AgentDenied


def references(run, artifacts, context):
    from .jobs import _bytes
    from .professional_artifacts import inspect_file
    result = []
    for artifact in artifacts:
        if (artifact.status != 'verified' or artifact.execution.conversation_id != run.conversation_id
                or artifact.verification.get('purpose', 'deliverable') != 'deliverable'
                or artifact.execution.job.get('expired')):
            raise AgentDenied('artifact_not_deliverable')
        raw = _bytes(artifact)
        _, text, _ = inspect_file(raw, artifact.format, budget=run.job['limits'])
        if evaluate_policy(context[0], context[8] + [('files', text)], destinations=context[7]).status != 'allow':
            raise AgentDenied('artifact_policy_denied')
        result.append({'artifact_id': str(artifact.pk), 'id': str(artifact.pk),
            'logical_id': str(artifact.logical_id), 'revision': artifact.revision,
            'filename': artifact.filename or f'document-{artifact.logical_id}-r{artifact.revision}.{artifact.format}',
            'size_bytes': len(raw), 'sha256': artifact.sha256, 'format': artifact.format,
            'download_url': reverse('front:agent_download', kwargs={'artifact_id': artifact.pk})})
    return result


def receipt(run, artifacts, context, *, problems=(), partial=False):
    refs = references(run, artifacts, context)
    required = run.job.get('request', {}).get('delivery_required', bool(run.job.get('request', {}).get('formats')))
    status = ('partial' if refs else 'failed') if partial or problems else ('complete' if required or refs else 'not_required')
    return {'version': 2, 'required': required, 'status': status,
            'requirements': run.job.get('request', {}), 'artifacts': refs, 'problems': sorted(set(problems))}


def false_references(content, artifacts):
    valid = {str(a.pk) for a in artifacts}
    cited = re.findall(r'/chat/agent/artifacts/([\w-]+)/', content)
    return ['artifact_reference_invalid'] if any(value not in valid for value in cited) else []


def included(artifact):
    """A failed/partial run exposes only revisions explicitly in its receipt."""
    delivery = artifact.execution.prompt.decision.get('delivery')
    if not delivery:
        return artifact.execution.status == 'completed'
    return delivery.get('status') in ('complete', 'partial') and any(
        str(item.get('artifact_id', item.get('id'))) == str(artifact.pk) and item.get('sha256') == artifact.sha256
        for item in delivery.get('artifacts', []))


def partial(run, reason):
    """Deterministic terminal receipt: never call a model to explain a limit."""
    from front.models import AgentInference, Message, Response
    from .professional_artifacts import current_artifacts
    from .service import _context
    if run.prompt.decision.get('delivery', {}).get('status') in ('complete', 'not_required') or hasattr(run.prompt, 'response'):
        return
    artifacts = [a for a in current_artifacts(run) if a.status == 'verified']
    try:
        delivery = receipt(run, artifacts, _context(run.prompt, run.profile_id), problems=[reason], partial=True)
    except (ValueError, AgentDenied):
        delivery = {'version': 2, 'required': run.job.get('request', {}).get('delivery_required', False),
                    'status': 'failed', 'artifacts': [], 'problems': [reason]}
    uncertain = (run.operations.filter(status='started').exists() or
        AgentInference.objects.filter(execution=run, status__in=['processing', 'outcome_unknown']).exists())
    delivery['uncertain_effects'] = uncertain
    run.prompt.decision.update(delivery=delivery, history_eligible=False, error_type=reason)
    run.prompt.save(update_fields=['decision'])
    content = ('La ejecución se ha detenido. ' +
        ('Los archivos indicados están verificados y disponibles. ' if delivery['artifacts'] else 'No hay una entrega de archivo verificada. ') +
        ('Hay operaciones de resultado desconocido; no se repetirán automáticamente.' if uncertain else
         'El trabajo solicitado no se ha completado.'))
    message = Message.objects.create(conversation=run.conversation, role='assistant', content=content)
    Response.objects.create(prompt=run.prompt, assistant_message=message, content=content,
        evidence={'artifacts': delivery['artifacts'], 'partial': True, 'reason': reason})
