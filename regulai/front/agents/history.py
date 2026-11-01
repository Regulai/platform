"""Immutable selection of authorized conversation pairs; no second memory store."""
import json

from front.chat_service import authorized_history, _candidate
from front.connectors import ChatMessage
from front.models import AgentExecution
from front.routing import route, RoutingError
from .protocol import tool_schema


def _identity(pair):
    return {key: pair[key] for key in ('prompt_id', 'user_id', 'assistant_id', 'digest')}


def select(actor, conversation, text, context, *, max_output_tokens=None):
    """Reserve model output, instructions/tools and complete recent pairs."""
    _, profile, agent, cfg, engine, model, _, destinations, *_ = context
    selection = authorized_history(actor, conversation, provenance=True, professional=True)
    pairs = selection['pairs']
    output = model.max_tokens
    if type(output) is not int or output <= 0:
        raise RoutingError('unknown_capacity')
    if not cfg.limits.provider_managed:
        output = min(output, cfg.routing.max_output_tokens)
    if max_output_tokens is not None:
        output = min(output, max_output_tokens)
    # Reserve bounded server/runtime instructions in addition to the actual
    # configured system prompts and tools. infer checks the complete wire again.
    fixed = [ChatMessage('user', text), ChatMessage('system',
        (profile.company.system_prompt or '') + (profile.department.system_prompt if profile.department else '')
        + json.dumps([tool_schema(name) for name in agent.tools], ensure_ascii=False))]
    omitted = selection['omitted']
    while True:
        prefix = [m for pair in pairs for m in pair['messages']]
        try:
            capacity = route([_candidate(engine, model, None, 'general')], fixed + prefix,
                allowed_destinations=destinations, max_output_tokens=output,
                provider_managed=False, budget=None, require_quality=False, overhead_tokens=1024)
            break
        except RoutingError as error:
            if error.code != 'context_overflow' or not pairs:
                raise
            pairs.pop(0)
            omitted += 1
    prefix_bytes = sum(len(m.content.encode('utf-8')) + 256 for m in prefix)
    return {'version': 2, 'pairs': [_identity(pair) for pair in pairs], 'omitted': omitted,
            'prefix_tokens_bound': prefix_bytes,
            'model_profile': {'max_input_tokens': model.context_window - output - prefix_bytes,
                              'max_output_tokens': output}}


def for_prompt(actor, prompt):
    from .service import AgentDenied
    run = AgentExecution.objects.filter(prompt=prompt).only('job').first()
    snapshot = run.job.get('history') if run else None
    if snapshot is None:
        return authorized_history(actor, prompt.conversation, professional=bool(run and run.job.get('kind') == 'professional'))
    available = authorized_history(actor, prompt.conversation, window=False, provenance=True, professional=True)
    by_id = {p['prompt_id']: p for p in available['pairs']}
    messages = []
    for selected in snapshot['pairs']:
        pair = by_id.get(selected['prompt_id'])
        if not pair or _identity(pair) != selected:
            raise AgentDenied('history_authorization_changed')
        messages.extend(pair['messages'])
    return messages
