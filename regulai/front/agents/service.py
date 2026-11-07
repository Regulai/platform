"""Trusted application side of the private agent protocol. No executor imports."""
from collections import OrderedDict
from dataclasses import asdict
from copy import deepcopy
from datetime import timedelta
from decimal import Decimal
import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from types import SimpleNamespace
import uuid

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from front.access import authorized_conversations
from front.chat_service import authorized_history, _candidate, _safe_jev_error_code
from front import jev
from front.classification import decide
from front.connectors import ChatMessage, get_connector
from front.governance import GovernedCalls, PipelineStop, destination_identity
from front.masking import mask_cost_bounds, mask_identity, valid_masks
from front.models import (AgentExecution, AgentInference, AgentInput, AgentModelProfile,
    AgentToolResult, CompanyEngine, EngineModel, ObfuscationConfig, Profile, Prompt)
from front.policy import AIConfig, digest, evaluate_policy
from front.routing import route, RoutingError
from .aliases import alias_text, alias_value, preserve_aliases
from .protocol import InferenceRequest, ToolCall, TOOL_PARAMETERS, tool_schema, validate_arguments

class AgentDenied(ValueError):
    """Only fixed codes may cross the internal boundary."""
    def __init__(self, code='agent_authorization_changed'):
        self.code = code
        super().__init__(code)


def _context(prompt, profile_id, *, allow_disabled=False):
    if not allow_disabled and not getattr(settings, 'REGULAY_AGENT_ENABLED', False):
        raise AgentDenied('agent_disabled')
    actor = prompt.user
    profile = Profile.objects.select_related('company', 'department', 'user').get(user=actor)
    actor.profile = profile
    if prompt.conversation and prompt.conversation.mode == 'agent':
        from .jobs import development_profile
        if development_profile(actor, allow_disabled=allow_disabled) != profile_id:
            raise AgentDenied('agent_profile_unavailable')
    if (not profile.user.is_active or profile.company_id != prompt.company_id
            or not authorized_conversations(actor).filter(pk=prompt.conversation_id).exists()):
        raise AgentDenied()
    agent = AgentModelProfile.objects.filter(pk=profile_id, company_id=prompt.company_id, enabled=True).first()
    if not agent or not isinstance(agent.tools, list) or any(t not in TOOL_PARAMETERS for t in agent.tools):
        raise AgentDenied('agent_profile_unavailable')
    if not agent.professional and prompt.conversation and prompt.conversation.mode == 'agent' and (
            not agent.tools or set(agent.tools) - {'create_mock_excel', 'build_excel', 'rename_excel', 'build_document', 'edit_document', 'export_pdf', 'build_presentation', 'edit_presentation', 'save_revision', 'research_sources', 'read_file'}):
        raise AgentDenied('agent_profile_unavailable')
    from .capabilities import limits, grant_binding, GENERAL
    if agent.professional and (not agent.tools or set(agent.tools) - GENERAL):
        raise AgentDenied('agent_profile_unavailable')
    resource_limits = limits(agent)
    if not 2 <= agent.min_group_size <= 1000:
        raise AgentDenied('agent_profile_unavailable')
    engine = CompanyEngine.objects.filter(pk=agent.connection_id, company_id=prompt.company_id,
        active=True).select_related('engine').first()
    model = EngineModel.objects.filter(pk=agent.model_id, active=True,
        engine_id=engine.engine_id if engine else None).first()
    if (not engine or not engine.api_key or not model
            or engine.engine.connector_type not in ('openai', 'openai_compatible', 'vercel_gateway')):
        raise AgentDenied('agent_profile_unavailable')
    cfg = AIConfig.model_validate(profile.company.ai_config)
    # A classifier is not an independent semantic review of the final artifact.
    # Mandatory artifact verification we cannot meet still blocks explicitly.
    if cfg.verification.mode != 'local':
        raise AgentDenied('agent_policy_incompatible')
    masks = list(ObfuscationConfig.objects.filter(company_id=prompt.company_id, active=True).order_by('created_at', 'pk'))
    if not valid_masks(masks):
        raise AgentDenied('masking_required')
    try:
        mask_cost_bounds(masks, cfg.masking.max_call_cost)
    except ValueError:
        raise AgentDenied('agent_policy_incompatible') from None
    destinations = [f'engine:{engine.pk}'] + [f'obfuscation:{m.pk}' for m in masks]
    if cfg.classification == 'required':
        destinations.append('jev')
    texts = [('prompts', prompt.content), ('prompts', profile.company.system_prompt or ''),
             ('prompts', profile.department.system_prompt if profile.department else '')]
    if prompt.conversation and prompt.conversation.mode == 'agent':
        from .jobs import _decode
        from .excel_contract import input_rows
        for asset in AgentInput.objects.filter(execution__prompt=prompt, kind__in=['csv', 'xlsx', 'narrative', 'policy_text']):
            if asset.kind == 'policy_text':
                if digest(asset.original) != asset.digest:
                    raise AgentDenied('input_digest_changed')
                extracted = json.loads(asset.original)
                if extracted.get('artifact_id'):
                    from .file_continuity import validate_policy_reference
                    validate_policy_reference(extracted, asset.execution)
                texts.append(('files', extracted['text']))
                continue
            # Policy may inspect local originals. This list is never model context.
            raw = _decode(asset)
            texts.append(('files', raw.decode('utf-8') if asset.kind == 'narrative'
                else json.dumps(input_rows(raw, asset.kind), ensure_ascii=False)))
    from .history import for_prompt
    history = for_prompt(actor, prompt)
    texts += [('prompts', m.content) for m in history]
    decision = evaluate_policy(actor, texts, destinations=destinations)
    if decision.status != 'allow':
        raise AgentDenied('agent_policy_denied')
    binding = digest([prompt.user_id, prompt.company_id, prompt.conversation_id, profile.department_id,
        decision.fingerprint, texts, destination_identity(engine, model),
        [(m.pk, mask_identity(m)) for m in masks], agent.pk, agent.compaction, agent.vision,
        agent.tools, agent.min_group_size, agent.professional, resource_limits, agent.limits, digest(agent.search_config),
        grant_binding(actor, agent.pk), digest(profile.company.jev_api_key)])
    run = AgentExecution.objects.filter(prompt=prompt).select_related('prompt').first()
    if run and run.job.get('skills'):
        from .skill_context import binding as skill_binding
        binding = digest([binding, skill_binding(run)])
    if run and run.job.get('version') == 2:
        binding = digest([binding, {key: run.job.get(key) for key in (
            'history', 'request', 'inference', 'work_profile', 'limits', 'references_manifest', 'references_digest')}])
    return actor, profile, agent, cfg, engine, model, masks, destinations, texts, history, decision, binding


def begin_execution(prompt, profile_id, *, lifetime=timedelta(minutes=15)):
    """Trusted orchestration seam for task 50; no public start endpoint in 49."""
    if prompt.status != 'processing' or hasattr(prompt, 'response'):
        raise AgentDenied('invalid_execution_prompt')
    context = _context(prompt, profile_id)
    token = secrets.token_urlsafe(32)
    if not timedelta(0) < lifetime <= timedelta(minutes=15):
        raise AgentDenied('invalid_attempt_lifetime')
    _initialize_receipt(prompt, context)
    prompt.save(update_fields=['decision', 'updated_at'])
    execution = AgentExecution.objects.create(prompt=prompt, profile_id=profile_id,
        token_digest=hashlib.sha256(token.encode()).hexdigest(), authorization_digest=context[-1],
        expires_at=timezone.now() + lifetime)
    return execution, token


def authenticate(token, attempt, *, allow_uncertain=False):
    if not isinstance(token, str) or len(token) > 128:
        raise AgentDenied('invalid_execution_credential')
    execution = AgentExecution.objects.select_related('prompt__user', 'prompt__conversation', 'profile').filter(
        token_digest=hashlib.sha256(token.encode()).hexdigest()).first()
    if (execution is None or str(execution.attempt) != str(attempt) or execution.expires_at <= timezone.now()
            or execution.status not in (('active', 'outcome_unknown') if allow_uncertain else ('active',))):
        raise AgentDenied('invalid_execution_credential')
    context = _context(execution.prompt, execution.profile_id)
    if not hmac.compare_digest(execution.authorization_digest, context[-1]):
        raise AgentDenied()
    return execution, context


def _jev_receipt(profile, cfg):
    required = cfg.classification == 'required'
    configured = bool(profile.company.jev_api_key)
    return {'status': 'pending' if required and configured else 'not_consulted' if configured else 'disabled',
        'consulted': False, 'purpose': 'classification', 'consulted_at': None, 'completed_at': None,
        'model_requested': cfg.jev.model, 'model_effective': None, 'transport': cfg.jev.transport,
        'decision': None, 'signals': {}, 'reasons': [], 'recommendations': [],
        # The actual Jev contract contains structured signals, not prose reasons,
        # recommendations, or the model's private reasoning.
        'explanation_available': False, 'scope': 'protected_text_and_tool_context',
        'policy': {'source': 'regulay_policy', 'revision': cfg.revision,
            'classification': cfg.classification, 'threshold': cfg.jev.threshold,
            'signal_threshold': cfg.classification_policy.signal_threshold,
            'on_ambiguity': cfg.classification_policy.on_ambiguity},
        'effect': 'pending' if required else 'not_required',
        'reason_codes': [] if required and configured else [
            'classification_local' if configured else 'jev_not_configured']}


def _initialize_receipt(prompt, context):
    _, profile, agent, cfg, engine, model, _, _, _, _, decision, _ = context
    prompt.decision.setdefault('calls', [])
    prompt.decision['schema_version'] = 1
    prompt.decision['policy'] = {**decision.as_dict(), 'source': 'local_policy'}
    prompt.decision.setdefault('jev', _jev_receipt(profile, cfg))
    prompt.decision['route'] = {'mode': 'agent_profile', 'profile_id': agent.pk,
        'company_engine_id': engine.pk, 'model': model.model_id,
        'reason': 'explicit_agent_profile', 'fallback': 'disabled'}
    prompt.decision['limits'] = {'provider_managed': cfg.limits.provider_managed,
        'max_output_tokens': None if cfg.limits.provider_managed else cfg.routing.max_output_tokens}


def _metadata_identifier(value):
    """Only bounded identifiers enter receipts, never arbitrary provider text."""
    if (not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}', value)
            or re.match(r'(?i)(sk-|AIza|ghp_|github_pat_|xox[baprs]-|Bearer)', value)):
        return None
    return value


def _save_decision(prompt, *, update_fields=None):
    """Settle late calls without overwriting a concurrent terminal receipt.

    Cancellation/termination owns the execution lock and its delivery/history
    metadata. The provider callback owns only the call ledger and totals after
    that transition. This short lock never spans provider or protection I/O.
    """
    with transaction.atomic():
        run = AgentExecution.objects.select_for_update().filter(prompt_id=prompt.pk).first()
        if run is not None and run.status not in ('queued', 'active'):
            terminal = Prompt.objects.values_list('decision', flat=True).get(pk=prompt.pk)
            prompt.decision = {**terminal, **{key: prompt.decision[key]
                for key in ('calls', 'total') if key in prompt.decision}}
        prompt.save(update_fields=update_fields or ['decision', 'updated_at'])


class AgentGovernedCalls(GovernedCalls):
    """Add receipts to the shared boundary without changing its authorization."""

    def save_decision(self):
        _save_decision(self.prompt)

    def current_history(self):
        if getattr(self, 'execution', None) and self.execution.job.get('kind') == 'professional':
            from .history import for_prompt
            return for_prompt(self.actor, self.prompt)
        return super().current_history()

    def mask_timeout(self, mask):
        value = super().mask_timeout(mask)
        remaining = self.remaining()
        if remaining is None:
            return value
        return min(value, remaining) if value is not None else remaining

    def remaining(self):
        inherited = super().remaining()
        if getattr(self, 'execution', None) and self.execution.job.get('kind') == 'professional':
            from .capabilities import call_timeout
            return call_timeout(self.execution, self.execution.profile,
                min(inherited, self.cfg.limits.call_timeout_seconds) if inherited is not None else self.cfg.limits.call_timeout_seconds)
        return inherited

    def start_call(self, purpose, destination, model, *args, **kwargs):
        call, started = super().start_call(purpose, destination, model, *args, **kwargs)
        if destination == 'jev':
            connector = 'vercel_gateway' if self.cfg.jev.transport == 'vercel' else 'typesafe'
            mode, upstream = 'company_jev_policy', 'typesafe-ai'
        elif destination.startswith('engine:'):
            row = self.rows[(int(destination.split(':')[1]), kwargs['model_pk'])]
            connector, mode = row[0].engine.connector_type, 'agent_profile'
            upstream = model.split('/', 1)[0] if connector == 'vercel_gateway' else None
        elif destination.startswith('research:'):
            connector, mode, upstream = 'public_https', 'primary_source_read', None
        else:
            connector, mode, upstream = call['transport'], 'required_masking', None
        call.update(sequence=len(self.prompt.decision['calls']), started_at=timezone.now().isoformat(),
            completed_at=None, model_requested=model, provider_name=connector,
            route={'mode': mode, 'destination': destination, 'connector': connector, 'upstream_provider': upstream},
            fallback={'status': 'not_used', 'reason': 'agent_profile_pinned' if mode == 'agent_profile' else 'single_authorized_destination'})
        self.save_decision()
        return call, started

    def complete_call(self, call, started, result):
        if result is not None:
            # The shared ledger must not persist unbounded model IDs, request IDs
            # or arbitrary usage keys supplied by a compatible provider.
            safe = SimpleNamespace(
                model=_metadata_identifier(getattr(result, 'model', None) or getattr(result, 'effective_model', None)),
                input_tokens=result.input_tokens, output_tokens=result.output_tokens,
                provider_request_id=_metadata_identifier(getattr(result, 'provider_request_id', None) or getattr(result, 'request_id', None)),
                usage={key: value for key, value in result.usage.items() if key in (
                    'input_tokens', 'output_tokens', 'total_tokens', 'prompt_tokens', 'completion_tokens',
                    'cached_tokens', 'reasoning_tokens')},
                provider_metadata=getattr(result, 'provider_metadata', {}))
        else:
            safe = None
        call['completed_at'] = timezone.now().isoformat()
        value = super().complete_call(call, started, safe)
        if getattr(self, 'execution', None):
            from .event_store import append_event
            category = 'provider' if call['purpose'] in ('generation', 'compaction', 'vision') else 'protection' if call['purpose'] in ('obfuscation', 'classification') else 'network'
            append_event(self.execution, 'interval', **{
                'category': category, 'attempt': str(self.execution.attempt), 'call_id': call.get('call_id'),
                'started_at': call.get('started_at'), 'completed_at': call['completed_at'],
                'duration_ms': call.get('duration_ms'), 'purpose': call['purpose']})
        return value


def _government(execution, context, token, attempt, call_id):
    actor, profile, _, cfg, engine, model, masks, destinations, _, history, decision, _ = context
    prompt = execution.prompt
    prompt._started = time.monotonic()
    prompt._call_observer, prompt._observer_tokens = None, []
    _initialize_receipt(prompt, context)
    government = AgentGovernedCalls(actor, prompt, profile, cfg, decision, destinations,
        {(engine.pk, model.pk): (engine, model, None)}, masks, history,
        authorize=lambda: authenticate(token, attempt), call_context={
            'execution_id': str(execution.pk), 'attempt': str(execution.attempt), 'call_id': call_id})
    government.execution = execution
    return government


def _classify(execution, context, government, messages, policy_texts):
    actor, profile, _, cfg, _, _, _, _, _, _, local, _ = context
    if cfg.classification != 'required':
        return
    receipt = _jev_receipt(profile, cfg)
    execution.prompt.decision['jev'] = receipt
    if not profile.company.jev_api_key:
        receipt.update(effect='block', reason_codes=['jev_unavailable'])
        raise AgentDenied('jev_unavailable')
    # Inspect exactly the protected text and structured tool context about to be
    # sent. Opaque approved image references do not imply visual review by Jev.
    state = {'request': next((message.content for message in reversed(messages) if message.role == 'user'), ''),
        'context': [asdict(message) for message in messages]}
    questions = {**jev.classification_questions(), **jev.task_questions()}
    serialized = json.dumps(state, ensure_ascii=False)
    if not cfg.limits.provider_managed and len(serialized.encode('utf-8')) > jev.MAX_STATE_BYTES:
        receipt.update(status='not_consulted', effect='block', reason_codes=['evaluation_input_too_large'])
        raise AgentDenied('evaluation_input_too_large')
    prices = {key: getattr(cfg.jev, key) for key in ('input_price', 'output_price', 'currency', 'price_date')}
    bound = (Decimal(cfg.jev.max_call_cost) if cfg.jev.max_call_cost is not None
        and cfg.jev.input_price is not None and cfg.jev.output_price is not None else None)
    call, started = government.start_call('classification', 'jev', cfg.jev.model,
        policy_texts + [('prompts', serialized)], bound, prices)
    receipt.update(consulted=True, consulted_at=call['started_at'])
    call['jev'] = receipt
    _save_decision(execution.prompt)
    timeout = None
    remaining = government.remaining()
    if remaining is not None:
        seconds = min(120, remaining)
        connect = min(seconds / 2, max(3, seconds - 60))
        timeout = (connect, seconds - connect)
    try:
        result = jev.evaluate(profile.company.jev_api_key, cfg.jev.model, state, questions,
            timeout=timeout, transport=cfg.jev.transport, provider_managed=cfg.limits.provider_managed)
    except jev.JevError as error:
        code = _safe_jev_error_code(error.code)
        completed_at = timezone.now().isoformat()
        receipt.update(status='no_response' if code in ('timeout', 'connection_error') else 'failed',
            completed_at=completed_at, effect='block', reason_codes=[code])
        call.update(status='outcome_unknown' if error.outcome_unknown else 'failed',
            provider_error_code=code, completed_at=completed_at,
            duration_ms=round((time.monotonic() - started) * 1000))
        if error.outcome_unknown:
            raise
        raise AgentDenied('jev_failed') from None
    classification = decide(result.answers, cfg, local.sensitivity)
    valid_answers = {} if classification.stop_code == 'security_check_failed' else deepcopy(result.answers)
    receipt.update(status='consulted', completed_at=timezone.now().isoformat(),
        model_effective=_metadata_identifier(result.effective_model), signals=valid_answers,
        decision={key: valid_answers[key]['choice'] for key in ('category', 'task', 'difficulty')} if valid_answers else None,
        applied={'source': 'regulay_policy', 'sensitivity': classification.sensitivity,
            'task': classification.task, 'difficulty': classification.difficulty},
        reason_codes=classification.notices, effect='continue')
    call.update(rubric_version=jev.CLASSIFICATION_RUBRIC_VERSION, task_rubric_version=jev.TASK_RUBRIC_VERSION)
    try:
        government.complete_call(call, started, result)
    except PipelineStop as error:
        receipt.update(effect='block', reason_codes=[error.code])
        raise
    government.sensitivity = classification.sensitivity
    if classification.stop_code:
        receipt.update(effect='block', reason_codes=[classification.stop_code, *classification.notices])
        execution.prompt.decision['policy'] = {**local.as_dict(), 'source': 'regulay_policy',
            'inputs': ['local_policy', 'jev_signals'], 'sensitivity': classification.sensitivity,
            'status': 'block' if classification.stop_status == 'blocked' else 'unavailable',
            'reason_codes': receipt['reason_codes']}
        raise AgentDenied(classification.stop_code)
    classified = evaluate_policy(actor, policy_texts, sensitivity=classification.sensitivity,
        destinations=government.destinations)
    classified.allowed_destinations = sorted(set(classified.allowed_destinations) & set(local.allowed_destinations))
    execution.prompt.decision['policy'] = {**classified.as_dict(), 'source': 'regulay_policy',
        'inputs': ['local_policy', 'jev_signals'], 'rubric_version': jev.CLASSIFICATION_RUBRIC_VERSION}
    government.destinations = sorted(set(government.destinations) & set(classified.allowed_destinations))
    if classified.status != 'allow':
        receipt.update(effect='block', reason_codes=classified.reason_codes)
        raise AgentDenied(classified.reason_codes[0])


def _protect_tree(execution, value):
    if isinstance(value, str):
        return alias_text(execution, value)
    if isinstance(value, list):
        return [_protect_tree(execution, item) for item in value]
    if isinstance(value, dict):
        from front.local_masking import _SECRET_KEY
        fields = {'nombre': 'PERSON', 'full_name': 'PERSON', 'titular': 'PERSON',
            'email': 'EMAIL', 'correo': 'EMAIL', 'telefono': 'PHONE', 'dni': 'ID', 'iban': 'ACCOUNT'}
        return {alias_text(execution, key): ('[[REGULAI_SECRET]]' if _SECRET_KEY.fullmatch(key)
                else alias_value(execution, fields[key.lower()], item)
                if key.lower() in fields and isinstance(item, str) else _protect_tree(execution, item))
                for key, item in value.items()}
    return value


def _reference_shields(execution, message, content, calls):
    """Preserve only typed references already issued within this execution."""
    if not calls and message.role != 'tool' and not message.reference_context:
        return content, calls, {}
    from front.models import AgentArtifact
    inputs = {str(row.pk) for row in AgentInput.objects.filter(execution=execution,
        kind__in=['csv', 'xlsx', 'narrative', 'research', 'web_source', 'model_image'])}
    artifacts = list(AgentArtifact.objects.filter(execution=execution))
    base = execution.job.get('base')
    if base:
        item = AgentArtifact.objects.filter(pk=base,
            execution__prompt__conversation_id=execution.prompt.conversation_id).first()
        if item:
            artifacts.append(item)
    references = inputs | {str(row.pk) for row in artifacts}
    logical = {str(row.logical_id) for row in artifacts}
    if execution.job.get('logical_id'):
        logical.add(str(execution.job['logical_id']))
    results = list(AgentToolResult.objects.filter(execution=execution))
    call_ids = {row.call_id for row in results}
    revisions = {entry['revision_id'] for entry in (execution.job.get('skills') or {}).get('catalog', [])}
    installations = {entry['installation_id'] for entry in (execution.job.get('skills') or {}).get('catalog', [])}
    digests = {row.sha256 for row in artifacts}
    for row in results:
        try:
            result = json.loads(row.protected_view) if row.protected_view else row.view
        except ValueError:
            continue
        for key in ('sha256', 'instruction_digest'):
            value = result.get(key) if isinstance(result, dict) else None
            if isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value):
                digests.add(value)
    registry = {}

    def shield(value, known):
        if not isinstance(value, str) or value not in known:
            return value
        marker = '[[REGULAY_REFERENCE_' + ''.join(chr(65 + int(c, 16)) for c in secrets.token_hex(20)) + ']]'
        registry[marker] = value
        return marker

    def fields(value, specs):
        for key, known in specs.items():
            if key in value:
                value[key] = ([shield(item, known) for item in value[key]] if isinstance(value[key], list)
                    else shield(value[key], known))

    for call in calls:
        args, name = call['args'], call['name']
        specs = {}
        if name in ('build_excel', 'build_document', 'build_presentation'):
            specs['input_reference'] = inputs
        if name in ('rename_excel', 'edit_document', 'export_pdf', 'edit_presentation'):
            specs.update(logical_id=logical, base_revision=references)
        if name == 'save_revision':
            specs.update(artifact_reference=references, sha256=digests)
        if name == 'publish_artifact':
            specs.update(base_revision=references, sources=inputs)
        if name == 'web_find':
            specs['reference'] = inputs
        if name == 'read_output':
            specs['call_id'] = call_ids
        if name in ('edit_file', 'replace_file'):
            specs['expected_sha256'] = digests
        fields(args, specs)
    if (message.role == 'tool' or message.reference_context) and isinstance(content, str):
        try:
            value = json.loads(content)
        except ValueError:
            value = None
        if isinstance(value, dict):
            fields(value, {'reference': references, 'input_reference': inputs, 'logical_id': logical,
                'base_revision': references, 'image_reference': inputs, 'call_id': call_ids,
                'output_ref': call_ids, 'revision_id': revisions, 'installation_id': installations,
                'sha256': digests, 'instruction_digest': digests})
            content = json.dumps(value, ensure_ascii=False)
    return content, calls, registry


def _protect_message(execution, government, message, policy_texts):
    # Structural role, ID and name stay separate from mutable user/model content.
    raw = json.dumps(message.model_dump(), ensure_ascii=False)
    for mask in government.masks:
        government.preflight(f'obfuscation:{mask.pk}', policy_texts + [('prompts', raw)])
    original_content = message.model_dump()['content']
    image_references = {}
    if isinstance(original_content, list):
        for index, part in enumerate(original_content):
            if part.get('type') == 'image_ref':
                image_references[index] = part['reference']
                part['reference'] = ''  # Opaque IDs are structure, not maskable prose.
    try:
        calls = [call.model_dump() for call in message.tool_calls]
        original_content, calls, references = _reference_shields(execution, message, original_content, calls)
        content = _protect_tree(execution, original_content)
        for call in calls:
            call['args'] = _protect_tree(execution, call['args'])
    except ValueError:
        raise AgentDenied('invalid_agent_content') from None
    # A JSON scalar string is indistinguishable from plain text to some masking
    # backends. A one-element array preserves escaping when a secret occurs next
    # to an embedded quote in an approved tool result.
    parts = [json.dumps([content], ensure_ascii=False), *[json.dumps(c['args'], ensure_ascii=False) for c in calls]]
    protected = preserve_aliases(parts, lambda values: government.protect_texts(values, policy_texts))
    for marker, value in references.items():
        if sum(text.count(marker) for text in protected) != 1:
            raise AgentDenied('masked_reference_changed')
        protected = [text.replace(marker, value) for text in protected]
    envelope = json.loads(protected[0])
    if not isinstance(envelope, list) or len(envelope) != 1:
        raise AgentDenied('invalid_masked_agent_content')
    content = envelope[0]
    for index, reference in image_references.items():
        if (not isinstance(content, list) or index >= len(content)
                or not isinstance(content[index], dict) or content[index].get('type') != 'image_ref'):
            raise AgentDenied('invalid_masked_agent_content')
        content[index]['reference'] = reference
    for call, value in zip(calls, protected[1:]):
        call['args'] = json.loads(value)
        validate_arguments(ToolCall.model_validate(call))
    return ChatMessage(message.role, content, calls, message.tool_call_id, message.name)


class ProtectedHistory:
    """Protected messages reused across the inferences of one execution.

    Every inference resends the whole conversation. Protecting each message again
    cost two policy checks, a masking call and two receipt writes per message, so
    a long run slowed down quadratically. Entries live in process memory only,
    are bounded, and are keyed by the exact message plus everything that
    authorized its protection: a policy, rule, mask, grant or attempt change
    protects it again. The generation call still checks the whole payload.
    """

    def __init__(self, limit):
        self.limit, self.size, self.items, self.lock = limit, 0, OrderedDict(), threading.Lock()

    def get(self, key):
        with self.lock:
            value = self.items.get(key)
            if value is not None:
                self.items.move_to_end(key)
            return value

    def put(self, key, value):
        with self.lock:
            if key in self.items:
                self.size -= len(self.items.pop(key))
            if len(value) > self.limit:
                return
            self.items[key] = value
            self.size += len(value)
            while self.size > self.limit:
                self.size -= len(self.items.popitem(last=False)[1])

    def forget(self, execution_id):
        with self.lock:
            for key in [key for key in self.items if key[0] == str(execution_id)]:
                self.size -= len(self.items.pop(key))


PROTECTED_HISTORY = ProtectedHistory(32_000_000)


def _protection_key(execution, context, government, message):
    return (str(execution.pk), digest({'attempt': str(execution.attempt), 'authorization': context[-1],
        'policy': government.decision.fingerprint,
        'masks': {str(pk): value for pk, value in government.mask_identities.items()},
        'message': message.model_dump()}))


def _protected_message(execution, context, government, message, policy_texts, counts):
    key = _protection_key(execution, context, government, message)
    cached = PROTECTED_HISTORY.get(key)
    if cached is not None:
        counts['reused'] += 1
        return ChatMessage(**json.loads(cached))  # A fresh copy: callers may rewrite content.
    protected = _protect_message(execution, government, message, policy_texts)
    PROTECTED_HISTORY.put(key, json.dumps(asdict(protected), ensure_ascii=False))
    counts['protected'] += 1
    return protected


def _within_command_limit(tool, budget):
    """The sandbox caps commands at the profile limit; issue that value rather than a call the tool gate refuses."""
    timeout = tool.args.get('timeout') if tool.name == 'execute' else None
    if not isinstance(timeout, int) or isinstance(timeout, bool) or 1 <= timeout <= budget['command_seconds']:
        return tool
    return ToolCall(id=tool.id, name=tool.name, args={**tool.args, 'timeout': max(1, min(timeout, budget['command_seconds']))})


def _validate_tool_history(execution, request):
    from .general_tools import result_view
    issued = {}
    for inference in AgentInference.objects.filter(execution=execution, status='completed'):
        for call in inference.response.get('tool_calls', []):
            issued[call['id']] = call
    # One query per inference, not one per tool message (unique per execution and call).
    results = {row.call_id: row for row in AgentToolResult.objects.filter(execution=execution)}
    pending, seen = {}, set()
    for message in request.messages:
        if pending and message.role != 'tool':
            raise AgentDenied('missing_tool_result')
        for call in message.tool_calls:
            if call.id in seen or issued.get(call.id) != call.model_dump():
                raise AgentDenied('unissued_tool_call')
            pending[call.id] = call.name
            seen.add(call.id)
        if message.role == 'tool':
            result = results.get(message.tool_call_id)
            if (not result or pending.pop(message.tool_call_id, None) != message.name
                    or message.content != json.dumps(result_view(result), sort_keys=True, ensure_ascii=False)):
                raise AgentDenied('unapproved_tool_result')
    if pending:
        raise AgentDenied('missing_tool_result')


def _images(execution, messages, profile, model, cfg):
    for message in messages:
        if not isinstance(message.content, list):
            continue
        converted = []
        for part in message.content:
            if part['type'] == 'text':
                converted.append(part)
                continue
            # Opaque references only; no caller-chosen URLs, bytes or filesystem paths.
            if not profile.vision or not model.supports_vision or not cfg.limits.provider_managed:
                raise AgentDenied('agent_vision_unavailable')
            asset = AgentInput.objects.filter(pk=part['reference'], execution=execution, kind='model_image').first()
            if not asset or digest(asset.original) != asset.digest:
                raise AgentDenied('unapproved_model_image')
            data = json.loads(asset.original)
            if set(data) != {'mime', 'base64'} or data['mime'] not in ('image/png', 'image/jpeg'):
                raise AgentDenied('unapproved_model_image')
            base64.b64decode(data['base64'], validate=True)
            converted.append({'type': 'image_url', 'image_url': {
                'url': f"data:{data['mime']};base64,{data['base64']}"}})
        message.content = converted


def _totals(prompt):
    calls = prompt.decision['calls']
    known = sum((Decimal(c['cost']) for c in calls if c.get('cost') is not None), Decimal(0))
    complete = all(c.get('cost') is not None for c in calls)
    prompt.decision['total'] = {'known_cost': str(known), 'cost': str(known) if complete else None,
        'currency': 'USD', 'complete': complete, 'attempts': sum(c['purpose'] in ('generation', 'compaction', 'vision') for c in calls)}
    _save_decision(prompt)


def infer(token, attempt, payload):
    request = InferenceRequest.model_validate(payload)
    execution, context = authenticate(token, attempt, allow_uncertain=True)
    if request.purpose == 'compaction' and execution.job.get('worker_protocol') == 2:
        from .runtime_contract import compaction_call_id
        if str(request.call_id) != str(compaction_call_id(execution.pk,
                [m.model_dump() for m in request.messages], execution.job.get('effective_options', {}), request.tools)):
            raise AgentDenied('compaction_identity_invalid')
    request_digest = digest(request.model_dump())
    if context[2].professional and not AgentInference.objects.filter(execution=execution, call_id=request.call_id).exists():
        from .capabilities import execution_limits, remaining_seconds
        from .jobs import stop_budget
        budget = execution_limits(execution, context[2])
        if remaining_seconds(execution, context[2]) <= 0:
            return stop_budget(token, attempt, 'deadline_exceeded')
        if AgentInference.objects.filter(execution=execution).count() >= budget['model_calls']:
            return stop_budget(token, attempt, 'budget_exhausted')
    # A uniqueness constraint and an atomic per-execution claim serialize money
    # and receipts on SQLite AND PostgreSQL. Never hold a transaction over HTTP.
    with transaction.atomic():
        if context[2].professional:
            from .capabilities import execution_limits
            budget = execution_limits(execution, context[2])
            if (not AgentInference.objects.filter(execution=execution, call_id=request.call_id).exists()
                    and AgentInference.objects.filter(execution=execution).count() >= budget['model_calls']):
                raise AgentDenied('agent_model_budget_exhausted')
            if execution.started_at and (timezone.now() - execution.started_at).total_seconds() >= budget['run_seconds']:
                raise AgentDenied('execution_deadline')
        record, created = AgentInference.objects.get_or_create(execution=execution, call_id=request.call_id,
            defaults={'attempt': execution.attempt, 'request_digest': request_digest})
        if record.request_digest != request_digest:
            raise AgentDenied('inference_id_conflict')
        if not created:
            # Capacity reservations populate response before a result exists.
            # Only a terminal ledger receipt can be replayed as that result.
            if record.status in ('completed', 'rejected', 'outcome_unknown') and record.response.get('status') == record.status:
                return record.response
            return {'status': 'outcome_unknown', 'code': 'inference_in_progress_or_uncertain'}
        if not AgentExecution.objects.filter(pk=execution.pk, status='active', active_call__isnull=True,
                attempt=execution.attempt).update(active_call=request.call_id):
            raise AgentDenied('execution_busy_or_uncertain')
        record.status = 'processing'
        record.save(update_fields=['status'])
    # The claim may have waited. Reload the ledger only after acquiring it.
    execution.prompt.refresh_from_db()
    government = None
    stream = None
    transport_finished = False
    dispatch_started = False
    try:
        execution, context = authenticate(token, attempt)
        _, profile, agent, cfg, engine, model, _, destinations, policy_texts, _, _, _ = context
        government = _government(execution, context, token, attempt, request.call_id)
        if request.purpose == 'compaction' and not agent.compaction:
            raise AgentDenied('agent_compaction_disabled')
        if request.purpose == 'vision' and not agent.vision:
            raise AgentDenied('agent_vision_unavailable')
        if set(request.tools) - set(agent.tools):
            raise AgentDenied('tool_not_allowed')
        _validate_tool_history(execution, request)
        from .skill_context import inference_messages
        worker_messages, skill_instructions = inference_messages(execution, request)
        if cfg.classification == 'required' and not profile.company.jev_api_key:
            _classify(execution, context, government, [], policy_texts)
        # Company and department instructions are sourced in the application.
        from .protocol import WireMessage
        instructions = [WireMessage(role='system', content=value) for value in (
            profile.company.system_prompt, profile.department.system_prompt if profile.department else '') if value]
        effective_tools = request.tools
        if execution.job.get('skills', {}).get('catalog'):
            effective_tools = [name for name in effective_tools if name != 'install_packages']
        if agent.professional:
            if execution.job.get('network_sealed'):
                from .capabilities import WEB
                effective_tools = [name for name in effective_tools if name not in WEB | {'install_packages'}]
                instructions.append(WireMessage(role='system', content=(
                    'La red de esta tarea está cerrada porque ya se ha procesado un archivo privado. '
                    'Trabaja con el archivo y la evidencia disponibles; no consultes URLs ni instales paquetes. '
                    'Puedes generar, comprobar y publicar archivos con las herramientas locales.')))
            if 'web_open' in effective_tools and 'web_search' not in effective_tools:
                # Without a search provider, research only succeeds by opening known addresses.
                instructions.append(WireMessage(role='system', content=(
                    'No hay buscador web configurado en esta instalación. Para investigar, abre con web_open '
                    'direcciones de referencia que conozcas con seguridad (por ejemplo, artículos de es.wikipedia.org, '
                    'enciclopedias, universidades u organismos oficiales) y usa web_find para localizar pasajes. '
                    'Si una dirección falla, prueba otra fuente fiable; no atribuyas contenido a páginas que no hayas abierto.')))
            # Keep the agent on the shortest path: no file or research the user did not ask for.
            instructions.append(WireMessage(role='system', content=(
                f'Cada comando puede durar como máximo {budget["command_seconds"]} segundos: diseña el código '
                'para que termine mucho antes.')))
            asked = execution.job.get('request', {})
            if not asked.get('delivery_required', bool(asked.get('formats') or asked.get('pages'))):
                instructions.append(WireMessage(role='system', content=(
                    'La petición no pide ningún archivo: entrega el resultado en el chat, breve y claro. '
                    'No generes informes ni documentos; añade un gráfico solo si aclara el resultado.')))
            if not asked.get('research_required'):
                instructions.append(WireMessage(role='system', content=(
                    'La petición no pide fuentes: no navegues ni añadas fuentes; usa tu conocimiento y el cálculo. '
                    'Consulta la web solo si te falta un dato imprescindible para cumplir la petición.')))
            remaining = budget['model_calls'] - AgentInference.objects.filter(execution=execution).count()
            used = budget['model_calls'] - remaining
            goal = execution.job.get('work_profile', {}).get('model_goal')
            if goal and used >= goal:
                instructions.append(WireMessage(role='system', content=(
                    'Se ha alcanzado el objetivo orientativo de trabajo. Si ya se cumple la petición, concluye. '
                    'Repara únicamente fallos concretos pendientes dentro del presupuesto; no añadas nuevas comparaciones ni comprobaciones opcionales.')))
            if remaining <= 4:
                instructions.append(WireMessage(role='system', content=(
                    f'Quedan {remaining} llamadas después de esta. Reserva la última para responder sin herramientas. '
                    'Prioriza publicar los archivos solicitados. Si ya están publicados y cumplen formato y páginas, '
                    'entrega el resultado ahora; no repitas comprobaciones opcionales. '
                    'Declara cualquier trabajo pendiente con honestidad.')))
            from .capabilities import remaining_seconds
            if remaining == 0 or remaining_seconds(execution, agent) <= 10:
                effective_tools = []
                instructions.append(WireMessage(role='system', content=(
                    'Esta es la última llamada autorizada: responde con los entregables ya verificados y los límites reales. '
                    'No puedes ejecutar más herramientas ni afirmar que terminaste lo que falta.')))
        history_messages = []
        if agent.professional and request.purpose != 'compaction':
            history_messages = [WireMessage(role=m.role, content=m.content) for m in context[9]]
            if execution.job.get('history', {}).get('omitted'):
                instructions.append(WireMessage(role='system', content=(
                    'Hay mensajes anteriores fuera del contexto autorizado. No afirmes que nunca existieron; '
                    'si los necesitas, pide al usuario el fragmento concreto.')))
        raw_messages = instructions + skill_instructions + history_messages + worker_messages
        protection = {'reused': 0, 'protected': 0}
        messages = [_protected_message(execution, context, government, message, policy_texts, protection)
                    for message in raw_messages]
        _classify(execution, context, government, messages, policy_texts)
        schemas = [tool_schema(name) for name in effective_tools]
        # Bound all structured payload bytes, including IDs, args and tool schemas.
        bound_messages = [ChatMessage('user', json.dumps([asdict(m) for m in messages], ensure_ascii=False)
            + json.dumps(schemas, ensure_ascii=False))]
        from .inference_options import options_for_call
        options = options_for_call(execution.job.get('inference', {}), tools=bool(effective_tools)) if agent.professional and execution.job.get('inference') else None
        if agent.professional:
            reserve = options['max_output_tokens'] if options else (model.max_tokens if cfg.limits.provider_managed else min(model.max_tokens or 0, cfg.routing.max_output_tokens))
            route([_candidate(engine, model, None, 'general')], bound_messages,
                allowed_destinations=government.destinations, require_quality=False,
                max_output_tokens=reserve, provider_managed=False, budget=None)
        selected = route([_candidate(engine, model, None, 'general')], bound_messages,
            allowed_destinations=government.destinations, require_quality=False,
            max_output_tokens=options['max_output_tokens'] if options else (None if cfg.limits.provider_managed else cfg.routing.max_output_tokens),
            provider_managed=False if options else cfg.limits.provider_managed)
        _images(execution, messages, agent, model, cfg)
        policy_payload = json.dumps([asdict(m) for m in messages], ensure_ascii=False)
        from .capacity import reserve_provider
        reserve_provider(record, engine)
        call, started = government.start_call(request.purpose, f'engine:{engine.pk}', model.model_id,
            policy_texts + [('prompts', policy_payload)], selected.estimated_cost,
            selected.price_snapshot, model_pk=model.pk)
        call['protection'] = protection
        execution.prompt.model_used = model.model_id
        _save_decision(execution.prompt, update_fields=['decision', 'model_used', 'updated_at'])
        from .skill_context import confirm_inference
        confirm_inference(execution)
        connector = get_connector(engine.engine.connector_type, engine.api_key, engine.engine.base_url or None)
        from .streaming import AgentStream
        stream = AgentStream(execution, context, government, request)
        dispatch_started = True
        from front.connectors import ProviderStreamInvalid
        try:
            response = connector.chat(messages, model=model.model_id, max_tokens=selected.max_output_tokens,
                temperature=0.1, timeout=government.remaining(), reasoning=model.reasoning, tools=schemas,
                **({'inference_options': options} if options else {}), **stream.callbacks())
        except ProviderStreamInvalid as error:
            transport_finished = True
            government.complete_call(call, started, error.receipt)
            raise AgentDenied('invalid_provider_tool_calls') from None
        transport_finished = True
        if options:
            call['inference_options'] = {'requested': execution.job['inference'], 'resolved': options,
                **response.inference_options}
        government.complete_call(call, started, response)
        if call.get('model_effective') and len(call['model_effective']) <= 100:
            execution.prompt.model_used = call['model_effective']
            execution.prompt.save(update_fields=['model_used', 'updated_at'])
        if response.finish_reason not in ('stop', 'tool_calls'):
            raise AgentDenied('inference_incomplete')
        if (response.finish_reason == 'tool_calls') != bool(response.tool_calls):
            raise AgentDenied('invalid_provider_tool_calls')
        from .protocol import WireMessage
        reply = WireMessage(role='assistant', content=response.content or '', tool_calls=response.tool_calls)
        if agent.professional:
            reply = WireMessage(role='assistant', content=reply.content,
                                tool_calls=[_within_command_limit(tool, budget) for tool in reply.tool_calls])
        ids = set()
        prior_ids = {c['id'] for r in AgentInference.objects.filter(execution=execution, status='completed')
                     for c in r.response.get('tool_calls', [])}
        for tool in reply.tool_calls:
            try:
                validate_arguments(tool)
            except ValueError:
                raise AgentDenied('invalid_provider_tool_calls') from None
            if tool.name not in effective_tools or tool.id in ids | prior_ids:
                raise AgentDenied('invalid_provider_tool_calls')
            ids.add(tool.id)
        clean = _protect_message(execution, government, reply, policy_texts)
        authenticate(token, attempt)  # Revocation during a provider call withholds delivery.
        stream.complete_text(clean.content)
        record.response = {'status': 'completed', 'content': clean.content, 'tool_calls': clean.tool_calls,
            'usage': {'input_tokens': response.input_tokens, 'output_tokens': response.output_tokens},
            'inference': {key: deepcopy(call.get(key)) for key in (
                'sequence', 'call_id', 'purpose', 'provider', 'provider_name', 'model_requested', 'model_effective',
                'route', 'fallback', 'status', 'started_at', 'completed_at', 'duration_ms', 'cost', 'cost_kind', 'currency', 'inference_options')}}
        if agent.professional and request.purpose == 'vision':
            # Exact pixels actually dispatched through this inference, not a
            # worker assertion that an image was reviewed.
            record.response['image_sha256'] = []
            for message in request.messages:
                for part in message.content if isinstance(message.content, list) else []:
                    if part.type == 'image_ref':
                        asset = AgentInput.objects.get(pk=part.reference, execution=execution, kind='model_image')
                        image_data = json.loads(asset.original)
                        record.response['image_sha256'].append(hashlib.sha256(base64.b64decode(image_data['base64'])).hexdigest())
        record.status = 'completed'
    except (AgentDenied, PipelineStop, RoutingError) as error:
        record.status = 'rejected'
        record.response = {'status': 'rejected', 'code': error.code}
        receipt = execution.prompt.decision.get('jev', {})
        if receipt.get('status') == 'pending':
            receipt.update(status='not_consulted', effect='block', reason_codes=[error.code])
    except Exception:
        # Once dispatched, timeout/connection loss/invalid response cannot prove
        # non-execution. No SDK or transport fallback is allowed to resubmit it.
        record.status = 'outcome_unknown'
        record.response = {'status': 'outcome_unknown', 'code': 'inference_outcome_unknown'}
    if government is not None:
        if stream is not None:
            stream.watch.closed()
        for call in execution.prompt.decision['calls']:
            if call['status'] == 'started':
                call['status'] = 'outcome_unknown'
                call['completed_at'] = timezone.now().isoformat()
                if call.get('call_id') == request.call_id:
                    call['duration_ms'] = max(0, round((time.monotonic() - execution.prompt._call_started) * 1000))
                if call.get('jev'):
                    call['jev'].update(status='no_response', effect='block',
                        completed_at=call['completed_at'], reason_codes=['inference_outcome_unknown'])
                record.status = 'outcome_unknown'
                record.response = {'status': 'outcome_unknown', 'code': 'inference_outcome_unknown'}
        _totals(execution.prompt)
    # A crash before settlement leaves the durable claim; replay returns uncertain.
    from .capacity import finish_provider
    finish_provider(record, transport_finished=transport_finished or not dispatch_started)
    with transaction.atomic():
        record.save(update_fields=['status', 'response'])
        AgentExecution.objects.filter(pk=execution.pk, active_call=request.call_id,
            attempt=execution.attempt, status='active').update(
            active_call=None, **({'status': 'outcome_unknown'} if record.status == 'outcome_unknown' else {}))
        if record.status == 'completed' and record.response.get('image_sha256'):
            from .professional_artifacts import record_visual_receipts
            record_visual_receipts(execution)
    if stream is not None:
        stream.finish(record)
    return record.response
