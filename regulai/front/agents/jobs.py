"""Trusted chat orchestration. All database access stays in the application."""
import base64
from contextlib import contextmanager
from datetime import timedelta
import hashlib
import hmac
import json
from pathlib import PurePath
import secrets
import uuid
import zipfile
import xml.etree.ElementTree as ET

from django.conf import settings
from django.db import connection, transaction
from django.db.models import Max
from django.utils import timezone

from front.access import authorized_conversations
from front.models import (AgentArtifact, AgentEvent, AgentExecution, AgentInference, AgentInput,
                         Conversation, Message, Profile, Prompt, Response)
from front.policy import digest
from .excel_contract import MAX_BYTES, input_rows, sha256, valid_title, verify
from .service import PROTECTED_HISTORY, AgentDenied, _context, authenticate, begin_execution
from .request_contract import interpret, allowed_tools, check_delivery, verification_checks

LIVE = ('queued', 'active', 'outcome_unknown')
LEASE_SECONDS = 60
MAX_RUN_SECONDS = 3600
EVENT_TEXT = {
    'recovered': 'Recuperación solicitada desde mensajes y archivos guardados. Los permisos y el presupuesto se revalidarán.',
    'searching': 'Buscando fuentes en la web pública.',
    'reading': 'Leyendo una fuente y registrando su cobertura.',
    'executing': 'Trabajando con archivos y código en el entorno aislado.',
    'installing': 'Preparando dependencias verificadas para instalación sin red.',
    'verifying': 'Comprobando el resultado y registrando el alcance de la revisión.',
    'queued': 'Petición aceptada. Esperando capacidad de ejecución.',
    'claimed': 'Ejecución iniciada. El entorno se adquiere cuando hace falta.',
    'sandbox_waiting': 'Esperando capacidad para preparar el entorno aislado.',
    'sandbox_acquired': 'Entorno aislado adquirido. Preparando los archivos autorizados.',
    'sandbox_prepared': 'Entorno preparado. Archivos e aislamiento comprobados.',
    'input': 'Leyendo la estructura del archivo autorizado.',
    'calculate': 'Python está calculando y preparando las fórmulas del Excel.',
    'rename': 'Actualizando el título de la revisión actual.',
    'recalculate': 'LibreOffice está recalculando las fórmulas.',
    'verify': 'Reabriendo y comprobando los bytes finales y sus resultados.',
    'compose': 'Componiendo el documento con el contenido autorizado.',
    'render': 'Convirtiendo y renderizando todas las páginas de la revisión final.',
    'visual_pending': 'Comprobaciones automáticas completadas. Revisa todas las páginas antes de publicar.',
    'visual_reviewed': 'Revisión visual registrada para estos bytes y estas páginas.',
    'draft': 'La comprobación ha fallado. Se conserva el borrador para reparación local.',
    'verified': 'El archivo ha superado las comprobaciones técnicas aplicables.',
    'completed': 'Respuesta completada. Los archivos disponibles figuran en el recibo de entrega.',
    'cancelled': 'Ejecución cancelada. No se iniciarán nuevos pasos.',
    'interrupted': 'Ejecución interrumpida. No se repetirán automáticamente operaciones de resultado incierto.',
    'failed': 'No se pudo completar un archivo verificado. Los borradores se conservan.',
    'approval_pending': 'Exportación preparada. Revisa cuenta, carpeta, nombre y revisión antes de aprobar.',
    'export_intent': 'Aprobación revalidada. Intención de exportación registrada.',
    'export_completed': 'Exportación confirmada; contenido y destino comprobados.',
    'export_uncertain': 'Resultado externo incierto. Se requiere reconciliación; no se repetirá la creación.',
    'export_recovery': 'Checkpoint recuperable. Se revalidarán los permisos antes de continuar.',
}


def development_profile(actor, *, allow_disabled=False):
    """Compatibility name for the common account-grant resolver."""
    from .capabilities import profile_for
    return profile_for(actor, allow_disabled=allow_disabled)


def available(actor):
    try:
        development_profile(actor)
        return True
    except (AgentDenied, Profile.DoesNotExist, ValueError, KeyError):
        return False


def event(execution, kind, **data):
    from .event_store import append_event
    return append_event(execution, kind, text=EVENT_TEXT.get(kind, ''), **data)


def _terminal(execution, status):
    if status != 'completed' and execution.job.get('kind') == 'professional' and execution.job.get('version') == 2:
        from .delivery import partial
        reason = execution.prompt.decision.get('error_type') or ('cancelled_by_user' if status == 'cancelled' else
            'deadline_exceeded' if execution.expires_at <= timezone.now() else 'delivery_incomplete')
        partial(execution, reason)
    execution.status, execution.finished_at = status, timezone.now()
    execution.save(update_fields=['status', 'finished_at'])
    PROTECTED_HISTORY.forget(execution.pk)
    Prompt.objects.filter(pk=execution.prompt_id).update(status=(
        'outcome_unknown' if status == 'interrupted' else status), updated_at=timezone.now())
    event(execution, status)
    from .event_store import append_event
    total = execution.prompt.decision.get('total', {})
    append_event(execution, 'run.finished', event_key='terminal:' + str(execution.attempt),
        status=status, financial_pending=not total.get('complete', True),
        known_cost=total.get('known_cost'), unknown_cost=total.get('unknown_cost'),
        close_cursor=execution.events.order_by('-pk').values_list('pk', flat=True).first() or 0)


def stop_budget(token, attempt, reason):
    """Stop before another effect; the terminal response is built only locally."""
    with locked(token, attempt) as (run, _):
        if run.active_call:
            raise AgentDenied('execution_busy_or_uncertain')
        run.prompt.decision['error_type'] = reason
        run.prompt.save(update_fields=['decision'])
        _terminal(run, 'interrupted')
    return {'status': 'interrupted', 'code': reason, 'delivery': run.prompt.decision.get('delivery', {})}


def reap():
    """Abandoned active jobs have no safe graph checkpoint: stop, never replay."""
    with transaction.atomic():
        for run in AgentExecution.objects.select_for_update(skip_locked=True).filter(
                conversation__isnull=False, status__in=LIVE, expires_at__lte=timezone.now()):
            if (run.status == 'active' and run.job.get('kind') == 'export'
                    and run.job.get('checkpoint_ready') and not run.active_call
                    and run.export.expires_at > timezone.now()):
                run.status = 'queued'
                run.claim_id = None
                run.expires_at = timezone.now() + timedelta(seconds=LEASE_SECONDS)
                run.save(update_fields=['status', 'claim_id', 'expires_at'])
                event(run, 'export_recovery')
                continue
            _terminal(run, 'interrupted')


def _decode(asset):
    raw = base64.b64decode(asset.original, validate=True)
    if sha256(raw) != asset.digest:
        raise AgentDenied('input_digest_changed')
    return raw


def _bytes(artifact):
    raw = base64.b64decode(artifact.content, validate=True)
    if sha256(raw) != artifact.sha256 or artifact.verification.get('sha256') != artifact.sha256:
        raise AgentDenied('artifact_digest_changed')
    return raw


def latest(conversation, logical_id):
    from .file_continuity import delivered
    return next((item for item in AgentArtifact.objects.filter(execution__conversation=conversation, logical_id=logical_id,
        status='verified').select_related('execution__prompt').order_by('-revision') if delivered(item)), None)


def _base(conversation, logical_id, base_id):
    try:
        row = latest(conversation, uuid.UUID(str(logical_id)))
    except (ValueError, TypeError):
        raise AgentDenied('artifact_not_found') from None
    if not row or str(row.pk) != str(base_id):
        raise AgentDenied('artifact_revision_stale')
    _bytes(row)
    return row


def enqueue(actor, command, conversation, text, request_id):
    from front.chat_service import error_result
    professional = False
    try:
        profile_id = development_profile(actor)
        from front.models import AgentModelProfile
        agent_profile = AgentModelProfile.objects.get(pk=profile_id)
        professional = agent_profile.professional
        from .skills import normalized_selection, freeze_selection
        previous_job = AgentExecution.objects.filter(prompt__user=actor,
            prompt__request_id=request_id).values_list('job', flat=True).first()
        previous_skills = (previous_job or {}).get('skills')
        default_auto = conversation.auto_skills if conversation else True
        if command.get('skills') is None and previous_skills is not None:
            default_auto = previous_skills['auto']
        selection = normalized_selection(command.get('skills'), default_auto=default_auto)
        # Replays retain their original catalogue across rollout, updates and preference changes.
        # The ordinary receipt check below still compares a changed explicit selection and
        # authorized_run revalidates the permissions of the already accepted execution.
        command = {**command, '_skill_selection': selection,
            '_skill_snapshot': previous_skills if previous_job is not None else freeze_selection(actor, agent_profile, selection)}
        if professional and not command.get('export_name'):
            from .professional import enqueue as professional_enqueue
            return professional_enqueue(actor, command, conversation, text, request_id, profile_id)
        if conversation and conversation.mode != 'agent':
            raise AgentDenied('conversation_mode_immutable')
        uploaded = command.get('file')
        if command.get('document_reference'):
            if uploaded or command.get('artifact_id') or command.get('base_revision'):
                raise AgentDenied('document_input_conflict')
            from django.core.files.uploadedfile import SimpleUploadedFile
            from .document_mcp import obtain
            external, external_kind = obtain(actor, command['document_reference'])
            uploaded = SimpleUploadedFile('document.' + external_kind, external)
        raw = uploaded.read(MAX_BYTES + 1) if uploaded else None
        kind = PurePath(uploaded.name).suffix.lower().lstrip('.') if uploaded else None
        rows = input_rows(raw, kind) if uploaded else None
        identity = [text, sha256(raw) if raw else None, 'agent',
                              command.get('artifact_id'), command.get('base_revision'),
                              command.get('document_reference')]
        if command.get('export_name'):
            identity.append(command['export_name'])
        if command.get('skills') is not None or (command.get('_skill_snapshot') or {}).get('catalog'):
            identity.append(selection)
        fingerprint = digest(identity)
        accepted_fingerprints = {fingerprint}
        if not command.get('document_reference') and not command.get('export_name') and command.get('skills') is None and not (command.get('_skill_snapshot') or {}).get('catalog'):
            accepted_fingerprints.add(digest(identity[:-1]))  # Pre-53 HTTP receipts remain replayable.
        reap()
        from .capacity import admission_lock, admit_queue
        with admission_lock():
            previous = Prompt.objects.filter(user=actor, request_id=request_id).first()
            if previous:
                if (previous.company_id != actor.profile.company_id
                        or previous.decision.get('input_digest') not in accepted_fingerprints
                        or (conversation and previous.conversation_id != conversation.pk)):
                    return error_result('idempotency_conflict', 409)
                run = AgentExecution.objects.get(prompt=previous)
                authorized_run(actor, run.pk)
                return accepted(run)
            admit_queue(actor.profile.company_id)
            if conversation:
                conversation = Conversation.objects.select_for_update().get(pk=conversation.pk)
                if AgentExecution.objects.filter(conversation=conversation, status__in=LIVE).exists():
                    return error_result('agent_conversation_busy', 409)
            else:
                conversation = Conversation.objects.create(user=actor, mode='agent', title=text[:50] or 'Documento')
            base = None
            if command.get('artifact_id') or command.get('base_revision'):
                if uploaded:
                    raise AgentDenied('revision_input_immutable')
                base = _base(conversation, command.get('artifact_id'), command.get('base_revision'))
                if command.get('export_name'):
                    from .exports import writable, export_name
                    writable(actor)
                    export_name(command['export_name'], base.format)
            requested = interpret(text, uploaded=bool(uploaded), base_format=base.format if base else None)
            if base and base.verification.get('narrative') and not requested['language_explicit']:
                from .report_contract import source_content
                requested['language'] = source_content(base)['language']
            if not uploaded and not base and requested['formats'] == ['xlsx'] and not requested['allow_mock']:
                raise AgentDenied('agent_source_required')
            message = Message.objects.create(conversation=conversation, role='user', content=text,
                file_name=PurePath(uploaded.name).name[:255] if uploaded else None,
                file_size=len(raw) if raw else 0)
            prompt = Prompt.objects.create(user=actor, company_id=actor.profile.company_id,
                conversation=conversation, user_message=message, content=text, request_id=request_id,
                status='processing', file_name=message.file_name, file_size=message.file_size,
                file_sha256=sha256(raw) if raw else None,
                decision={'schema_version': 1, 'input_digest': fingerprint, 'calls': []})
            run, _ = begin_execution(prompt, profile_id)
            run.conversation = conversation
            if uploaded:
                asset = AgentInput.objects.create(execution=run, kind=kind,
                    path='/workspace/input/source.' + kind,
                    original=base64.b64encode(raw).decode(), digest=sha256(raw))
            elif base:
                original = base.source
                asset = AgentInput.objects.create(execution=run, kind=original.kind,
                    path='/workspace/input/content.json' if original.kind == 'narrative' else original.path,
                    original=original.original, digest=original.digest)
                rows = input_rows(_decode(asset), asset.kind) if asset.kind in ('csv', 'xlsx') else None
            else:
                asset = None
            context = _context(prompt, profile_id)
            permitted = allowed_tools(requested, context[2].tools, base=bool(base), source=bool(uploaded),
                narrative=bool(base and base.verification.get('narrative')))
            if not command.get('export_name') and not set(permitted) - {'research_sources'}:
                raise AgentDenied('agent_format_not_authorized')
            if requested['research_required'] and not command.get('export_name'):
                from .research import available as research_available
                from .report_contract import sources_for_artifact
                prior_sources = sources_for_artifact(base) if base and base.verification.get('narrative') else {}
                research_status = research_available(context)['status']
                if not prior_sources and research_status != 'available':
                    raise AgentDenied('agent_research_' + research_status)
            if rows is not None and len(rows) < context[2].min_group_size:
                raise AgentDenied('aggregate_group_too_small')
            run.authorization_digest = context[-1]
            run.status = 'queued'
            run.expires_at = timezone.now() + timedelta(seconds=300)
            run.job = {'source': str(asset.pk) if asset else None, 'logical_id': str(base.logical_id if base else uuid.uuid4()),
                'base': str(base.pk) if base else None, 'kind': 'rename' if base else 'build' if asset else
                    'mock' if requested['formats'] == ['xlsx'] and requested['allow_mock'] else 'create',
                'request': requested}
            if command.get('_skill_snapshot') is not None:
                run.job['skills'] = command['_skill_snapshot']
            conversation.auto_skills = selection['auto']
            conversation.save(update_fields=['auto_skills'])
            if command.get('export_name'):
                if not base or 'save_revision' not in context[2].tools:
                    raise AgentDenied('export_base_required')
                run.job.update(kind='export', export_name=command['export_name'])
            run.save()
            run.authorization_digest = _context(prompt, profile_id)[-1]
            run.save(update_fields=['authorization_digest'])
            prompt.status = 'received'
            prompt.save(update_fields=['status'])
            event(run, 'queued')
            return accepted(run)
    except AgentDenied as error:
        from .capacity import CapacityDenied
        if isinstance(error, CapacityDenied):
            result = error_result(error.code, 429)
            result.data['retry_after'] = error.retry_after
            return result
        if error.code == 'agent_source_required' or error.code.startswith('agent_research_'):
            return error_result(error.code, 422)
        return error_result(error.code, 409 if 'stale' in error.code else 403)
    except ValueError as error:
        from .skill_bundles import SkillError
        if isinstance(error, SkillError):
            return error_result(error.code, 409)
        from front.routing import RoutingError
        if isinstance(error, RoutingError):
            return error_result(error.code, 422)
        code = str(error)
        if code in ('agent_multiple_formats_unsupported', 'agent_page_limit', 'agent_language_unsupported', 'artifact_format_unsupported'):
            return error_result(code, 422)
        return error_result('agent_professional_input_invalid' if professional else 'agent_input_invalid')
    except (TypeError, KeyError, UnicodeError, zipfile.BadZipFile, ET.ParseError, OSError):
        return error_result('agent_professional_input_invalid' if professional else 'agent_input_invalid')


def accepted(run):
    from front.chat_service import request_result
    run.prompt.refresh_from_db()
    result = request_result(run.prompt)
    result.data.update(success=True, mode='agent', agent=run_data(run))
    if run.status in LIVE:
        result.data['status'] = 'accepted'
        result.http_status = 202
    return result


def run_data(run):
    from .checkpoints import resumable
    return {'id': str(run.pk), 'request_id': str(run.prompt.request_id),
        'skills': {**{key: (run.job.get('skills') or {}).get(key) for key in ('selected', 'auto')},
            'selected_aliases': [entry['alias'] for entry in (run.job.get('skills') or {}).get('catalog', [])
                if entry['installation_id'] in (run.job.get('skills') or {}).get('selected', [])]},
        'professional': run.job.get('kind') == 'professional', 'resumable': resumable(run),
        'resume_url': f'/chat/agent/runs/{run.pk}/resume/',
        'status': run.status, 'request': run.job.get('request', {}),
        # Server timestamps let the viewer show measured durations only.
        'created_at': run.created_at.isoformat() if run.created_at else None,
        'started_at': run.started_at.isoformat() if run.started_at else None,
        'finished_at': run.finished_at.isoformat() if run.finished_at else None,
        'events_url': f'/chat/agent/runs/{run.pk}/events/',
        'status_url': f'/chat/agent/runs/{run.pk}/',
        'cancel_url': f'/chat/agent/runs/{run.pk}/cancel/'}


def worker_authorized(token):
    expected = getattr(settings, 'REGULAY_AGENT_WORKER_TOKEN', '')
    if (not getattr(settings, 'REGULAY_AGENT_ENABLED', False)
            or len(expected) < 32 or not hmac.compare_digest(token, expected)):
        raise AgentDenied('worker_unauthorized')
    if connection.vendor != 'postgresql':
        raise AgentDenied('agent_postgresql_required')


def claim(token, payload):
    worker_authorized(token)
    if set(payload) not in ({'worker_id', 'claim_id'}, {'worker_id', 'claim_id', 'worker_protocol'}) or payload.get('worker_protocol', 1) not in (1, 2):
        raise ValueError('Invalid claim')
    worker, claim_id = uuid.UUID(payload['worker_id']), uuid.UUID(payload['claim_id'])
    reap()
    from .capacity import admission_lock, claim_available, queue_expired
    with admission_lock():
        for expired in queue_expired().select_for_update():
            _terminal(expired, 'interrupted')
        run = AgentExecution.objects.select_for_update().filter(claim_id=claim_id).first()
        if run:
            if run.worker_id != worker or run.status != 'active' or run.expires_at <= timezone.now():
                raise AgentDenied('claim_no_longer_valid')
        else:
            run = next((candidate for candidate in AgentExecution.objects.select_for_update(skip_locked=True).filter(
                status='queued', conversation__isnull=False).select_related('prompt').order_by('created_at')
                if (candidate.job.get('version', 1) < 2 or payload.get('worker_protocol', 1) == 2)
                and claim_available(candidate.prompt.company_id)), None)
            if not run:
                return {'status': 'idle'}
            try:
                context = _context(run.prompt, run.profile_id)
                if not hmac.compare_digest(context[-1], run.authorization_digest):
                    raise AgentDenied()
            except AgentDenied:
                _terminal(run, 'interrupted')
                return {'status': 'idle'}
            run.attempt = uuid.uuid4()
            run.claim_id, run.worker_id = claim_id, worker
            run.started_at = run.started_at or timezone.now()
            run.expires_at = timezone.now() + timedelta(seconds=LEASE_SECONDS)
            run.status = 'active'
            run.job['worker_protocol'] = payload.get('worker_protocol', 1)
            event(run, 'claimed', interval={'category': 'queue', 'started_at': run.created_at.isoformat(),
                'completed_at': timezone.now().isoformat()}, duration_ms=max(0, round((timezone.now() - run.created_at).total_seconds() * 1000)))
        # Replaying the same claim after a lost HTTP response yields the same
        # credential; it cannot extend the lease or reclaim an old attempt.
        credential = hmac.new(token.encode(), f'{run.pk}:{run.attempt}:{claim_id}'.encode(), hashlib.sha256).hexdigest()
        run.token_digest = sha256(credential.encode())
        run.save()
        Prompt.objects.filter(pk=run.prompt_id).update(status='processing', updated_at=timezone.now())
        return {'status': 'claimed', 'execution': str(run.pk), 'attempt': str(run.attempt),
                'token': credential, 'lease_seconds': LEASE_SECONDS}


@contextmanager
def locked(token, attempt):
    first, _ = authenticate(token, attempt)
    with transaction.atomic():
        run = AgentExecution.objects.select_for_update().get(pk=first.pk)
        fresh, context = authenticate(token, attempt)
        if fresh.status != 'active' or run.status != 'active':
            raise AgentDenied('attempt_not_active')
        yield run, context


def renew(token, attempt, payload):
    if payload:
        raise ValueError('Invalid renewal')
    with locked(token, attempt) as (run, _):
        deadline = run.job.get('limits', {}).get('run_seconds', MAX_RUN_SECONDS)
        if not run.started_at or timezone.now() >= run.started_at + timedelta(seconds=deadline):
            raise AgentDenied('execution_deadline')
        # Never renew expired credentials. No worker/master credential is accepted
        # here, and a lost/old attempt has no recovery path back to authority.
        run.expires_at = min(timezone.now() + timedelta(seconds=LEASE_SECONDS),
                             run.started_at + timedelta(seconds=deadline))
        run.save(update_fields=['expires_at'])
        return {'status': 'authorized', 'lease_seconds': LEASE_SECONDS}


def bootstrap(token, attempt, payload):
    if payload:
        raise ValueError('Invalid bootstrap')
    with locked(token, attempt) as (run, context):
        from .skill_context import bootstrap as skill_bootstrap
        skill_data = skill_bootstrap(run)
        if run.job.get('kind') == 'professional':
            from .professional import bootstrap as professional_bootstrap
            return professional_bootstrap(run, context)
        from .aliases import alias_text, alias_value
        if run.job['kind'] == 'mock':
            return {'status': 'authorized', 'input': None, 'base': None,
                'model_context': {'operation': 'mock', 'request': run.job.get('request', {}), 'data_origin': 'invented_sample_data',
                    'min_rows': context[2].min_group_size, 'max_rows': 1000,
                    'columns': ['item', 'amount_cents']},
                'message': alias_text(run, run.prompt.content), 'execution': str(run.pk), 'skills': skill_data,
                'tools': ['create_mock_excel'] + (['read_file'] if 'read_file' in context[2].tools and skill_data else [])}
        asset = AgentInput.objects.get(pk=run.job['source'], execution=run) if run.job.get('source') else None
        rows = input_rows(_decode(asset), asset.kind) if asset and asset.kind in ('csv', 'xlsx') else []
        # Originals travel only through this private executor operation, never
        # through a model/tool result. The SDK receives just model_context below.
        model_context = {'operation': run.job['kind'], 'input_reference': str(asset.pk) if asset else '',
            'request': run.job.get('request', {}),
            'logical_id': run.job['logical_id'], 'base_revision': run.job['base'], 'rows': len(rows),
            'columns': [alias_value(run, 'FIELD', name) for name in ('item', 'amount_cents')] if rows else [],
            'data_origin': 'user_source' if rows else 'narrative_without_dataset'}
        base = _base(run.conversation, run.job['logical_id'], run.job['base']) if run.job['base'] else None
        if run.job['kind'] == 'export':
            return {'status': 'authorized', 'execution': str(run.pk),
                'checkpoint_ready': bool(run.job.get('checkpoint_ready')), 'model_context': {
                'operation': 'export', 'artifact_reference': str(base.pk), 'sha256': base.sha256,
                'name': alias_text(run, run.job['export_name'])},
                'message': alias_text(run, run.prompt.content), 'tools': ['save_revision']}
        model_context['base_format'] = base.format if base else None
        if base and base.verification.get('narrative'):
            from .report_contract import source_content
            # The protected text view re-enters the same alias/masking gateway.
            model_context['base_content'] = json.loads(alias_text(run, json.dumps(source_content(base), ensure_ascii=False)))
        from .research import available as research_available
        model_context['research'] = research_available(context)
        companion = None
        if base and base.format in ('docx', 'pdf') and base.render_bundle:
            from .document_jobs import source_document
            companion = base64.b64encode(source_document(base)).decode()
        return {'status': 'authorized', 'input': {'path': asset.path, 'base64': asset.original,
            'sha256': asset.digest, 'kind': asset.kind} if asset else None,
            'base': base64.b64encode(_bytes(base)).decode() if base else None,
            'base_format': base.format if base else None, 'base_docx': companion,
            'execution': str(run.pk), 'skills': skill_data,
            'model_context': model_context, 'message': alias_text(run, run.prompt.content),
            'tools': allowed_tools(run.job.get('request') or interpret(run.prompt.content, uploaded=bool(asset), base_format=base.format if base else None),
                context[2].tools, base=bool(base), source=bool(asset), narrative=bool(base and base.verification.get('narrative')))}


def step(token, attempt, payload):
    from .data_views import authorize_tool
    if set(payload) != {'call', 'phase'} or payload['phase'] not in ('input', 'calculate', 'rename', 'recalculate', 'verify', 'compose', 'render'):
        raise ValueError('Invalid step')
    with locked(token, attempt) as (run, _):
        _, _, call = authorize_tool(token, attempt, payload['call'])
        if call.name not in ('create_mock_excel', 'build_excel', 'rename_excel', 'build_document', 'edit_document', 'export_pdf', 'build_presentation', 'edit_presentation'):
            raise AgentDenied('tool_not_allowed')
        if run.events.filter(kind=payload['phase'], data__call_id=call.id).exists():
            raise AgentDenied('step_already_started')
        event(run, payload['phase'], call_id=call.id)
        return {'status': 'authorized'}


def candidate(token, attempt, payload):
    from .data_views import authorize_tool
    from .aliases import resolve_for_operation, TOKEN as TOKEN_RE
    if 'document_bundle' in payload:
        from .document_jobs import candidate as document_candidate
        return document_candidate(token, attempt, payload)
    if set(payload) != {'operation_id', 'call', 'base64'}:
        raise ValueError('Invalid candidate')
    operation_id = uuid.UUID(payload['operation_id'])
    run, context, call = authorize_tool(token, attempt, payload['call'])
    if call.name not in ('create_mock_excel', 'build_excel', 'rename_excel') or len(payload['base64']) > MAX_BYTES * 2:
        raise AgentDenied('candidate_denied')
    raw = base64.b64decode(payload['base64'], validate=True)
    title = call.args['title']
    # Resolve only registered references for this concrete local document field.
    tokens = [] if call.name == 'create_mock_excel' else [match.group(0) for match in TOKEN_RE.finditer(title)]
    if tokens:
        for alias, original in resolve_for_operation(run, tokens, operation='local_document_fields').items():
            title = title.replace(alias, original)
    title = valid_title(title)
    if call.name == 'create_mock_excel':
        from .excel_contract import mock_title
        title = mock_title(title)
        if not run.job.get('source'):
            raise AgentDenied('mock_source_required')
    asset = AgentInput.objects.get(pk=run.job['source'], execution=run)
    base = _base(run.conversation, run.job['logical_id'], run.job['base']) if run.job['base'] else None
    try:
        proof, _ = verify(raw, _decode(asset), asset.kind, title=title, base=_bytes(base) if base else None)
        check_delivery(run.job.get('request'), 'xlsx', proof)
        proof['request_checked'] = bool(run.job.get('request'))
        proof['automated_passed'] = True
        verified = True
    except Exception:
        proof, verified = {'code': 'excel_verification_failed', 'sha256': sha256(raw)}, False
    with locked(token, attempt) as (run, _):
        prior = AgentArtifact.objects.filter(execution=run, operation_id=operation_id).first()
        if prior:
            if prior.sha256 != sha256(raw) or prior.verification.get('call_id') != call.id:
                raise AgentDenied('candidate_id_conflict')
            return {'status': 'approved' if prior.status == 'verified' else 'withheld', 'reference': str(prior.pk)}
        if run.job['base']:
            _base(run.conversation, run.job['logical_id'], run.job['base'])
        revision = (AgentArtifact.objects.filter(logical_id=run.job['logical_id']).aggregate(n=Max('revision'))['n'] or 0) + 1
        if run.job['kind'] == 'mock' or (base and base.verification.get('data_origin') == 'invented_sample_data'):
            proof['data_origin'] = 'invented_sample_data'
        artifact = AgentArtifact.objects.create(execution=run, logical_id=run.job['logical_id'], revision=revision,
            base=base, source=asset, operation_id=operation_id, content=base64.b64encode(raw).decode(),
            sha256=sha256(raw), status='verified' if verified else 'draft',
            verification={**proof, 'call_id': call.id})
        event(run, 'verified' if verified else 'draft', reference=str(artifact.pk))
        return {'status': 'approved' if verified else 'withheld', 'reference': str(artifact.pk)}


def local_fields(token, attempt, payload):
    """Reviewed tool preparation; neither this response nor its raw fields enter the graph."""
    from .data_views import authorize_tool
    from .aliases import resolve_for_operation, TOKEN as TOKEN_RE
    run, _, call = authorize_tool(token, attempt, payload)
    if call.name == 'create_mock_excel':
        from .excel_contract import mock_source, mock_title
        raw = mock_source(call.args['rows'])
        title = mock_title(call.args['title'])
        with locked(token, attempt) as (run, context):
            # One immutable source per execution; retries must name identical data.
            if len(call.args['rows']) < context[2].min_group_size:
                raise AgentDenied('aggregate_group_too_small')
            if run.job.get('source'):
                asset = AgentInput.objects.get(pk=run.job['source'], execution=run)
                if asset.digest != sha256(raw):
                    raise AgentDenied('mock_source_immutable')
            else:
                asset = AgentInput.objects.create(execution=run, kind='csv', path='/workspace/input/mock.csv',
                    original=base64.b64encode(raw).decode(), digest=sha256(raw))
                run.job['source'] = str(asset.pk)
                # Evaluate generated data with the same policy before allowing execution.
                run.authorization_digest = _context(run.prompt, run.profile_id)[-1]
                run.save(update_fields=['job', 'authorization_digest'])
            return {'status': 'authorized', 'title': title, 'source_base64': asset.original,
                'source_sha256': asset.digest}
    if call.name in ('build_document', 'edit_document', 'export_pdf', 'build_presentation', 'edit_presentation'):
        from .document_jobs import local_fields as document_fields
        return document_fields(run, call)
    title = call.args.get('title')
    valid_title(title)
    aliases = [m.group(0) for m in TOKEN_RE.finditer(title)]
    if aliases:
        for alias, original in resolve_for_operation(run, aliases, operation='local_document_fields').items():
            title = title.replace(alias, original)
    return {'status': 'authorized', 'title': valid_title(title)}


def complete(token, attempt, payload):
    # Completion may have committed before the worker received its response.
    # A terminal replay reads the same receipt; it never recreates a message.
    previous = AgentExecution.objects.filter(token_digest=sha256(token.encode()), attempt=attempt,
        status__in=['completed', 'failed', 'interrupted']).select_related('prompt__user', 'conversation').first()
    if previous and previous.job.get('kind') == 'professional':
        authorized_run(previous.prompt.user, previous.pk)
        recorded = previous.job.get('completion_attempt', {})
        if previous.status != 'completed':
            if set(payload) == {'final_call_id'} and payload['final_call_id'] == recorded.get('call_id'):
                return recorded['result']
            raise AgentDenied('final_inference_required')
        last = AgentInference.objects.filter(execution=previous, status='completed').order_by('-id').first()
        if set(payload) != {'final_call_id'} or not last or str(last.call_id) != payload['final_call_id']:
            raise AgentDenied('final_inference_required')
        return {'status': 'completed', 'completed': True,
                'delivery': previous.prompt.decision.get('delivery', {})}
    run, _ = authenticate(token, attempt)
    if run.job.get('kind') == 'professional':
        from .professional import complete as professional_complete
        return professional_complete(token, attempt, payload)
    if payload:
        raise ValueError('Invalid completion')
    with locked(token, attempt) as (run, _):
        artifact = run.artifacts.order_by('-revision').first()
        if not artifact or artifact.status != 'verified' or run.active_call:
            raise AgentDenied('verified_artifact_required')
        _bytes(artifact)
        try:
            check_delivery(run.job.get('request'), artifact.format, artifact.verification)
        except ValueError as error:
            raise AgentDenied(str(error)) from None
        if run.job['base']:
            _base(run.conversation, run.job['logical_id'], run.job['base'])
        message = Message.objects.create(conversation=run.conversation, role='assistant',
            content=('Excel disponible. Fórmulas y totales comprobados; consulta el alcance de las demás comprobaciones.'
                if artifact.format == 'xlsx' else 'Documento disponible. Integridad, paginación y revisión visual registradas. Consulta las fuentes y los límites de verificación.'))
        Response.objects.create(prompt=run.prompt, assistant_message=message, content=message.content,
            evidence={'artifact': str(artifact.pk), 'sha256': artifact.sha256})
        prompt = run.prompt
        prompt.decision['verification'] = {'status': 'partial', 'checks': verification_checks(artifact),
            'sha256': artifact.sha256, 'artifact': str(artifact.pk)}
        prompt.save(update_fields=['decision'])
        _terminal(run, 'completed')
        return {'status': 'completed'}


def fail(token, attempt, payload):
    if payload:
        raise ValueError('Invalid failure')
    with locked(token, attempt) as (run, _):
        uncertain_export = run.job.get('kind') == 'export' and hasattr(run, 'export') and run.export.status in ('intent', 'uncertain')
        if not run.active_call and not uncertain_export:
            # The professional agent reads the open web; only the document agent uses the catalogue.
            professional = run.job.get('kind') == 'professional'
            if professional:
                from .web_tools import consulted_sources
            else:
                from .research import consulted_sources
            from front.chat_service import ERRORS
            last = AgentInference.objects.filter(execution=run).order_by('-id').first()
            rejected = last.response.get('code') if last and last.status == 'rejected' else None
            if rejected == 'security_check_failed':
                # Stopped by Regulay's own check on content read or produced mid-run.
                run.prompt.decision['error_type'] = 'agent_security_check_failed'
                run.prompt.save(update_fields=['decision'])
            elif rejected in ERRORS:
                run.prompt.decision['error_type'] = rejected
                run.prompt.save(update_fields=['decision'])
            elif run.job.get('request', {}).get('research_required') and not consulted_sources(run) and not run.job.get('base'):
                run.prompt.decision['error_type'] = 'agent_research_no_sources_web' if professional else 'agent_research_no_sources'
                run.prompt.save(update_fields=['decision'])
        _terminal(run, 'interrupted' if run.active_call or uncertain_export else 'failed')
    return {'status': 'completed'}


def authorized_run(actor, run_id):
    # Re-evaluate membership on each SSE batch, read and download, including after
    # a user changes company or an administrator revokes the profile/connection.
    run = AgentExecution.objects.select_related('prompt__user', 'conversation').filter(pk=run_id,
        prompt__user=actor, conversation__in=authorized_conversations(actor)).first()
    if not run or run.job.get('expired') or development_profile(actor, allow_disabled=True) != run.profile_id:
        raise AgentDenied('agent_not_found')
    _context(run.prompt, run.profile_id, allow_disabled=True)
    return run


def cancel(actor, run_id):
    authorized_run(actor, run_id)
    with transaction.atomic():
        run = AgentExecution.objects.select_for_update().get(pk=run_id)
        if run.status in LIVE:
            _terminal(run, 'cancelled')
    return run_data(run)


def artifact_data(artifact):
    if artifact.verification.get('contract') in ('professional-v1', 'professional-v2'):
        from .professional_artifacts import artifact_data as professional_data
        from .artifact_preview import TEXT_FORMATS
        value = professional_data(artifact)
        if (getattr(settings, 'REGULAY_ARTIFACT_PREVIEW', False) and artifact.status == 'verified'
                and artifact.format in TEXT_FORMATS):
            value['preview_url'] = f'/chat/agent/artifacts/{artifact.pk}/preview/'
        return value
    if artifact.format != 'xlsx':
        from .document_jobs import artifact_data as document_data
        return document_data(artifact)
    raw = _bytes(artifact)
    from .excel_contract import workbook
    book = workbook(raw)
    title = book.active['A1'].value
    book.close()
    _, preview = verify(raw, _decode(artifact.source), artifact.source.kind, title=title)
    preview.update(title=title, sheet_count=1)
    return {'id': str(artifact.pk), 'logical_id': str(artifact.logical_id), 'revision': artifact.revision,
        'sha256': artifact.sha256, 'format': 'xlsx', 'status': artifact.status, 'preview': preview,
        'data_mode': 'mock' if artifact.verification.get('data_origin') == 'invented_sample_data' else 'source',
        'verification_checks': verification_checks(artifact),
        'download_url': f'/chat/agent/artifacts/{artifact.pk}/download/'}
