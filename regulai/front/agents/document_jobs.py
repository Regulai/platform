"""Document-specific gates; identity, leases and authorization remain in jobs."""
import base64
import hmac
import json
import uuid

from django.db import transaction
from django.db.models import Max
from django.utils import timezone

from front.models import AgentArtifact, AgentExecution, AgentInput
from . import jobs
from .document_contract import fields, valid_section, verify_bundle
from .excel_contract import sha256, valid_title
from .service import AgentDenied, _context

VISUAL_CHECKS = ['all_pages', 'no_clipping_or_overlap', 'tables_complete', 'fonts_and_spanish', 'no_template_residue']


def source_document(artifact):
    jobs._bytes(artifact)
    raw = base64.b64decode(json.loads(artifact.render_bundle)['final.docx'], validate=True)
    if sha256(raw) != artifact.verification.get('docx_sha256'):
        raise AgentDenied('document_source_digest_changed')
    return raw


def local_fields(run, call):
    from .aliases import resolve_for_operation, TOKEN
    def resolve(value):
        aliases = [m.group(0) for m in TOKEN.finditer(value)]
        if aliases:
            for alias, original in resolve_for_operation(run, aliases, operation='local_document_fields').items():
                value = value.replace(alias, original)
        return value
    base = jobs._base(run.conversation, run.job['logical_id'], run.job['base']) if run.job.get('base') else None
    if call.args.get('content') is not None or (base and base.verification.get('narrative')):
        from .report_contract import local_fields as report_fields
        return report_fields(run, call, resolve)
    if call.name in ('build_presentation', 'edit_presentation'):
        from . import presentation_contract as pptx
        asset = AgentInput.objects.get(pk=run.job['source'], execution=run)
        pptx.source_rows(jobs._decode(asset), asset.kind)
        if call.name == 'build_presentation':
            title = pptx.valid_text(resolve(call.args['title']), 'title')
            section = pptx.valid_text(resolve(call.args['section']), 'body')
            return {'status': 'authorized', 'format': 'pptx', 'title': title, 'section': section,
                    'template': call.args['template'], 'texts': pptx.expected_fields(title, section)}
        base = jobs._base(run.conversation, run.job['logical_id'], run.job['base'])
        texts = pptx.fields(jobs._bytes(base))
        slide, field = call.args['slide'], call.args['field']
        value = pptx.valid_text(resolve(call.args['value']), field)
        if field == 'body' and len(value) > {1: 140, 2: 65, 3: 340}[slide]:
            raise ValueError('presentation_text_capacity')
        texts[slide-1][field] = value
        return {'status': 'authorized', 'format': 'pptx', 'title': texts[0]['title'], 'texts': texts,
                'slide': slide, 'field': field, 'value': value}
    if call.name == 'build_document':
        return {'status': 'authorized', 'title': valid_title(resolve(call.args['title'])),
                'section': valid_section(resolve(call.args['section'])), 'format': call.args['format']}
    base = jobs._base(run.conversation, run.job['logical_id'], run.job['base'])
    content = source_document(base)
    result = fields(content)
    result['status'] = 'authorized'
    result['format'] = 'pdf' if call.name == 'export_pdf' else base.format
    if call.name == 'edit_document':
        field = call.args['field']
        value = resolve(call.args['value'])
        (valid_title if field == 'title' else valid_section)(value)
        result.update({field: value, 'field': field, 'value': value})
    return result


def candidate(token, attempt, payload):
    from .data_views import authorize_tool
    if set(payload) != {'operation_id', 'call', 'document_bundle'}:
        raise ValueError('Invalid document candidate')
    operation = uuid.UUID(payload['operation_id'])
    run, _, call = authorize_tool(token, attempt, payload['call'])
    if call.name not in ('build_document', 'edit_document', 'export_pdf', 'build_presentation', 'edit_presentation'):
        raise AgentDenied('candidate_denied')
    content = local_fields(run, call)
    narrative = content.get('narrative')
    asset = AgentInput.objects.get(pk=run.job['source'], execution=run) if run.job.get('source') else None
    base = jobs._base(run.conversation, run.job['logical_id'], run.job['base']) if run.job['base'] else None
    previous = (source_document(base) if base and base.format in ('docx', 'pdf') else None)
    encoded = payload['document_bundle']
    if not isinstance(encoded, str) or len(encoded) > 40_000_000:
        raise ValueError('Document candidate too large')
    submitted = base64.b64decode(encoded, validate=True)
    try:
        if narrative:
            from .report_contract import verify_bundle as verify_report
            preserving = call.name in ('edit_document', 'edit_presentation', 'export_pdf')
            raw, proof, bundle = verify_report(encoded, narrative, format=content['format'], request=run.job.get('request'),
                base=(previous if base.format in ('docx', 'pdf') else jobs._bytes(base)) if base and preserving else None,
                export=call.name == 'export_pdf')
        elif content['format'] == 'pptx':
            from .presentation_contract import verify_bundle as verify_presentation
            editing = call.name == 'edit_presentation'
            raw, proof, bundle = verify_presentation(encoded, jobs._decode(asset), asset.kind, content['texts'],
                base=jobs._bytes(base) if editing else None,
                changed=(content['slide'], content['field']) if editing else None, template=content.get('template', 'new'))
        else:
            raw, proof, bundle = verify_bundle(encoded, jobs._decode(asset), asset.kind,
                {key: content[key] for key in ('title', 'section')}, format=content['format'],
                base=previous if call.name != 'build_document' else None, changed=content.get('field'))
        from .request_contract import check_delivery
        check_delivery(run.job.get('request'), content['format'], proof)
        proof['request_checked'] = bool(run.job.get('request'))
    except Exception:
        # Retain the failed package encrypted as a draft, never preview or deliver it.
        raw, bundle = submitted, ''
        proof = {'sha256': sha256(raw), 'code': 'document_verification_failed', 'automated_passed': False}
    proof['submission_sha256'] = sha256(submitted)
    with jobs.locked(token, attempt) as (run, _):
        prior = AgentArtifact.objects.filter(execution=run, operation_id=operation).first()
        if prior:
            if prior.verification.get('submission_sha256') != proof['submission_sha256'] or prior.verification.get('call_id') != call.id:
                raise AgentDenied('candidate_id_conflict')
            return {'status': 'withheld', 'reference': str(prior.pk)}
        if base:
            jobs._base(run.conversation, run.job['logical_id'], run.job['base'])
        if narrative:
            original = json.dumps(narrative, ensure_ascii=False, sort_keys=True).encode()
            asset = AgentInput.objects.create(execution=run, kind='narrative', path='/workspace/input/narrative-' + str(operation) + '.json',
                original=base64.b64encode(original).decode(), digest=sha256(original))
            run.authorization_digest = _context(run.prompt, run.profile_id)[-1]
            run.save(update_fields=['authorization_digest'])
        revision = (AgentArtifact.objects.filter(logical_id=run.job['logical_id']).aggregate(n=Max('revision'))['n'] or 0) + 1
        artifact = AgentArtifact.objects.create(execution=run, logical_id=run.job['logical_id'], revision=revision,
            base=base, source=asset, operation_id=operation, content=base64.b64encode(raw).decode(),
            sha256=sha256(raw), format=content['format'], render_bundle=bundle, status='draft',
            verification={**proof, 'call_id': call.id})
        jobs.event(run, 'visual_pending' if proof['automated_passed'] else 'draft', reference=str(artifact.pk))
        return {'status': 'withheld', 'reference': str(artifact.pk)}


def review_status(token, attempt, payload):
    if payload:
        raise ValueError('Invalid review status')
    with jobs.locked(token, attempt) as (run, _):
        latest = {}
        for artifact in run.artifacts.order_by('revision'):
            latest[artifact.logical_id] = artifact
        return {'status': 'authorized', 'pending': any(item.status == 'draft' and
            item.verification.get('automated_passed') for item in latest.values())}


def render_page(artifact, number):
    if not artifact.verification.get('automated_passed') or not 1 <= number <= artifact.verification['pages']:
        raise AgentDenied('document_preview_unavailable')
    jobs._bytes(artifact)
    raw = base64.b64decode(json.loads(artifact.render_bundle)[f'page-{number}.png'], validate=True)
    if sha256(raw) != artifact.verification['page_sha256'][number - 1]:
        raise AgentDenied('document_preview_digest_changed')
    return raw


def review(actor, artifact_id, payload):
    """Only the authenticated private viewer can attest qualitative visual QA.

    The model, worker token and automatic raster checks cannot invoke this gate.
    Every approval binds all displayed pages and the final artifact's exact bytes.
    """
    artifact = AgentArtifact.objects.get(pk=artifact_id)
    jobs.authorized_run(actor, artifact.execution_id)
    with transaction.atomic():
        run = AgentExecution.objects.select_for_update().get(pk=artifact.execution_id)
        jobs.authorized_run(actor, run.pk)
        if not hmac.compare_digest(_context(run.prompt, run.profile_id)[-1], run.authorization_digest):
            raise AgentDenied('authorization_changed')
        artifact = AgentArtifact.objects.select_for_update().get(pk=artifact_id)
        if run.status != 'active' or run.expires_at <= timezone.now():
            raise AgentDenied('attempt_not_active')
        if str(run.artifacts.filter(logical_id=artifact.logical_id).order_by('-revision').first().pk) != str(artifact.pk):
            raise AgentDenied('artifact_revision_stale')
        proof = artifact.verification
        if (set(payload) != {'sha256', 'page_sha256', 'checks'} or payload['sha256'] != artifact.sha256
                or payload['page_sha256'] != proof.get('page_sha256') or payload['checks'] != VISUAL_CHECKS
                or not proof.get('automated_passed')):
            raise AgentDenied('visual_review_digest_required')
        jobs._bytes(artifact)
        for n in range(1, proof['pages'] + 1):
            render_page(artifact, n)
        if run.job['base']:
            jobs._base(run.conversation, run.job['logical_id'], run.job['base'])
        if artifact.status != 'verified':
            proof['visual_review'] = {'reviewer_id': actor.pk, 'reviewed_at': timezone.now().isoformat(),
                                     'sha256': artifact.sha256, 'checks': VISUAL_CHECKS}
            artifact.status = 'verified'
            artifact.save(update_fields=['status', 'verification'])
            jobs.event(run, 'visual_reviewed', reference=str(artifact.pk))
    return {'status': 'reviewed'}


def artifact_data(artifact):
    jobs._bytes(artifact)
    if artifact.verification.get('narrative'):
        from .report_contract import source_content
        title = source_content(artifact)['title']
    elif artifact.format == 'pptx':
        from .presentation_contract import fields as presentation_fields
        title = presentation_fields(jobs._bytes(artifact))[0]['title']
    else:
        title = fields(source_document(artifact))['title']
    proof = artifact.verification
    return {'id': str(artifact.pk), 'logical_id': str(artifact.logical_id), 'revision': artifact.revision,
        'sha256': artifact.sha256, 'format': artifact.format, 'status': artifact.status,
        'verification_checks': jobs.verification_checks(artifact),
        'preview': {'title': title, 'page_count': proof['pages'], 'pages': [
            f'/chat/agent/artifacts/{artifact.pk}/pages/{n}/' for n in range(1, proof['pages'] + 1)]},
        'page_sha256': proof['page_sha256'], 'review_checks': VISUAL_CHECKS,
        'review_url': f'/chat/agent/artifacts/{artifact.pk}/review/',
        'download_url': f'/chat/agent/artifacts/{artifact.pk}/download/',
        'downloads': [{'format': format, 'url': f'/chat/agent/artifacts/{artifact.pk}/download/?format={format}'}
            for format in (('docx', 'pdf') if artifact.format in ('docx', 'pdf') else ('pptx',))
            if format == artifact.format or proof.get(format + '_sha256')]}
