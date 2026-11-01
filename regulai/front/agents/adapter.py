"""Executor-only SDK adapter. Uses the task 48 lock, never provider credentials."""
import asyncio
import json
import os
import threading
import uuid
from typing import Any
from urllib.parse import urlsplit

import httpx
from deepagents import create_deep_agent
from deepagents.profiles import GeneralPurposeSubagentProfile, HarnessProfile, register_harness_profile
from langchain.agents.middleware import AgentMiddleware
from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.utils.function_calling import convert_to_openai_tool
from langgraph.types import Command
from pydantic import Field

from .protocol import InferenceRequest, ToolCall, TOOL_PARAMETERS
from .runtime_contract import canonical_digest, compaction_call_id, summary_content

MODEL_NAME = 'regulay-internal:agent-v1'


class InternalOperationError(RuntimeError):
    pass


class InternalClient:
    def __init__(self, endpoint, token, attempt, *, transport=None):
        parsed = urlsplit(endpoint)
        if parsed.scheme not in ('http', 'https') or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError('Invalid internal endpoint')
        self.endpoint = endpoint.rstrip('/') + '/'
        self.token, self.attempt = token, str(attempt)
        self.execution, self.effective_options = None, {}
        self.compactions = {}
        self.skills = None
        self.client = httpx.Client(transport=transport, follow_redirects=False, trust_env=False,
            timeout=httpx.Timeout(660, connect=10, write=30, pool=10))

    def configure(self, granted):
        self.execution = granted.get('execution')
        self.effective_options = json.loads(json.dumps(granted.get('effective_options', {})))
        self.skills = granted.get('skills')

    def close(self):
        self.client.close()

    def operation(self, name, payload):
        if name not in ('inference', 'tool-results', 'authorize-tool', 'run/renew', 'run/bootstrap',
                'run/step', 'run/candidate', 'run/local-fields', 'run/research', 'run/complete', 'run/fail', 'run/review-status',
                'run/propose-export', 'run/approval-state', 'run/save-revision', 'run/export-complete', 'run/reconcile-export',
                'run/web', 'run/packages', 'run/publish', 'run/image', 'run/output', 'run/browser-fetch', 'run/browser-result', 'run/checkpoint', 'run/sandbox', 'run/skills', 'run/skill-resource'):
            raise InternalOperationError('Unknown internal operation')
        # Retry only the SAME identified application operation after a transport
        # failure. The durable server record decides whether inference ever ran.
        encoded = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode()
        for transport_attempt in range(2):
            try:
                response = self.client.post(self.endpoint + name + '/', content=encoded,
                    headers={'Authorization': 'Bearer ' + self.token, 'X-Regulay-Attempt': self.attempt,
                             'Content-Type': 'application/json'},
                    **({'timeout': 15} if name in ('run/renew', 'run/sandbox') else {}))
                if response.status_code != 200:
                    try:
                        code = response.json().get('code', 'internal_operation_denied')
                    except (ValueError, AttributeError):
                        code = 'internal_operation_denied'
                    raise InternalOperationError(str(code)[:120])
                value = response.json()
                if not isinstance(value, dict) or value.get('status') not in ('completed', 'authorized', 'approved', 'withheld'):
                    code = value.get('code') if isinstance(value, dict) else None
                    raise InternalOperationError(str(code)[:120] if isinstance(code, str) else 'Internal operation did not complete')
                return value
            except httpx.TransportError:
                if transport_attempt:
                    raise InternalOperationError('Internal transport outcome unknown') from None
            except (ValueError, TypeError):
                raise InternalOperationError('Invalid internal response') from None
        raise InternalOperationError('Internal transport unavailable')


def _wire(message):
    role = {'human': 'user', 'ai': 'assistant', 'system': 'system', 'tool': 'tool'}.get(message.type)
    metadata = message.additional_kwargs
    skills = metadata.get('regulay_skill_catalog') if isinstance(metadata, dict) else None
    if role is None or (metadata and metadata != {'lc_source': 'summarization'}
            and not (role == 'system' and set(metadata) == {'regulay_skill_catalog'})
            and not (role == 'user' and metadata == {'regulay_context': 'bootstrap'})):
        raise InternalOperationError('Unsupported model message')
    value = {'role': role, 'content': message.content}
    if skills:
        value['skill_catalog'] = skills
    if metadata == {'regulay_context': 'bootstrap'}:
        value['reference_context'] = 'bootstrap'
    if isinstance(message, AIMessage):
        if message.invalid_tool_calls:
            raise InternalOperationError('Invalid native tool call')
        value['tool_calls'] = [{k: c[k] for k in ('id', 'name', 'args')} for c in message.tool_calls]
    if isinstance(message, ToolMessage):
        if message.artifact is not None:
            raise InternalOperationError('Unapproved tool artifact')
        value.update(tool_call_id=message.tool_call_id, name=message.name)
    return value


class RegulayModel(BaseChatModel):
    model_name: str = MODEL_NAME
    internal: Any = Field(exclude=True, repr=False)
    allowed_tools: list[str] | None = None

    @property
    def _llm_type(self):
        return 'regulay-internal'

    def bind_tools(self, tools, *, tool_choice=None, **kwargs):
        if kwargs or tool_choice not in (None, 'auto'):
            raise InternalOperationError('Unsupported model options')
        names = [convert_to_openai_tool(t)['function']['name'] for t in tools]
        if self.allowed_tools is not None:
            names = [name for name in names if name in self.allowed_tools]
        if set(names) - set(TOOL_PARAMETERS):
            raise InternalOperationError('Unsupported tool catalogue')
        # Tool descriptions/schemas from the executor are not forwarded. Regulay
        # owns the schemas and the current profile owns the permitted subset.
        return self.bind(tools=names)

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        if stop or set(kwargs) - {'tools'}:
            raise InternalOperationError('Unsupported model options')
        metadata = getattr(run_manager, 'metadata', {}) or {}
        purpose = 'compaction' if metadata.get('lc_source') == 'summarization' else 'generation'
        wire = [_wire(m) for m in messages]
        # Only opaque, application-issued references can add pixels. Tool output
        # is still a data message; no raw URL/base64 is accepted from the model.
        for message in reversed(messages):
            if not isinstance(message, ToolMessage):
                break
            try:
                view = json.loads(message.content)
            except (ValueError, TypeError):
                continue
            if message.name == 'inspect_image' and view.get('image_reference'):
                wire.append({'role': 'user', 'content': [{'type': 'text', 'text': view['question']},
                    {'type': 'image_ref', 'reference': view['image_reference']}]})
        if any(isinstance(m['content'], list) and any(p.get('type') == 'image_ref' for p in m['content']) for m in wire):
            purpose = 'vision'
        call_id = str(uuid.uuid4())
        if purpose == 'compaction':
            if not getattr(self.internal, 'execution', None):
                raise InternalOperationError('Compaction execution identity unavailable')
            call_id = compaction_call_id(self.internal.execution, wire,
                self.internal.effective_options, kwargs.get('tools', []))
        request = InferenceRequest(call_id=call_id, purpose=purpose, messages=wire, tools=kwargs.get('tools', []))
        result = self.internal.operation('inference', request.model_dump())
        if purpose == 'compaction':
            summary = result['content'].strip()
            self.internal.compactions[canonical_digest(summary_content(summary))] = {
                'compaction_call_id': call_id, 'summary_digest': canonical_digest(summary)}
        calls = [ToolCall.model_validate(c).model_dump() for c in result['tool_calls']]
        # The model's public alias remains internal. The application's receipt
        # carries the actual provider/model of this invocation, including when a
        # graph made earlier generation, compaction, or vision calls.
        reply = AIMessage(content=result['content'], tool_calls=calls,
            response_metadata={'regulay': result['inference']} if result.get('inference') else {})
        return ChatResult(generations=[ChatGeneration(message=reply)])

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        return await asyncio.to_thread(self._generate, messages, stop, run_manager, **kwargs)


def _raw(value):
    if isinstance(value, BaseMessage):
        return value.model_dump(mode='json')
    if isinstance(value, Command):
        return {'update': _raw(value.update)}
    if isinstance(value, dict):
        return {str(key): _raw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_raw(item) for item in value]
    return value


class ResultGate(AgentMiddleware):
    def __init__(self, internal, prepare_tool=None):
        self.internal, self.prepare_tool = internal, prepare_tool
        self.tool_lock = threading.RLock()

    def _call(self, request):
        return {k: request.tool_call[k] for k in ('id', 'name', 'args')}

    def _result(self, call, raw, failed=False):
        view = self.internal.operation('tool-results', {'call': call, 'raw': _raw(raw), 'failed': failed})
        # Never apply Command.update or metadata. Only the server's protected
        # projection (including permitted diagnostics) becomes a data message.
        return ToolMessage(content=json.dumps(view, sort_keys=True, ensure_ascii=False),
            tool_call_id=call['id'], name=call['name'])

    def wrap_tool_call(self, request, handler):
        with self.tool_lock:
            call = self._call(request)
            grant = self.internal.operation('authorize-tool', call)
            if 'replay' in grant:
                return ToolMessage(content=json.dumps(grant['replay'], sort_keys=True, ensure_ascii=False),
                    tool_call_id=call['id'], name=call['name'])
            try:
                if self.prepare_tool:
                    self.prepare_tool(call, grant)
                raw = handler(request)
            except Exception as error:
                return self._result(call, {'exception': str(error)}, True)
            return self._result(call, raw)

    async def awrap_tool_call(self, request, handler):
        # Run the sync gate on one thread so both SDK paths share the same lock.
        # The actual async handler stays on its caller's event loop.
        loop = asyncio.get_running_loop()
        def handle(value):
            return asyncio.run_coroutine_threadsafe(handler(value), loop).result()
        return await asyncio.to_thread(self.wrap_tool_call, request, handle)


register_harness_profile(MODEL_NAME, HarnessProfile(
    general_purpose_subagent=GeneralPurposeSubagentProfile(enabled=False)))


def build_agent(backend, internal, *, tools=(), model_profile=None, system_prompt=None, allowed_tools=None,
                checkpointer=None, interrupt_on=None, middleware=(), prepare_tool=None):
    # Fail closed if an executor was launched with provider or external tracing
    # credentials. Actual egress enforcement belongs to the host network policy.
    if any(os.environ.get(key) for key in ('OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'GOOGLE_API_KEY',
            'DEEPSEEK_API_KEY', 'LANGSMITH_API_KEY', 'LANGCHAIN_API_KEY')):
        raise InternalOperationError('Executor environment contains external credentials')
    os.environ['LANGSMITH_TRACING'] = 'false'
    os.environ['LANGCHAIN_TRACING_V2'] = 'false'
    model = RegulayModel(internal=internal, profile=model_profile, cache=False, allowed_tools=allowed_tools)
    if getattr(internal, 'skills', None):
        from .skill_backend import compose
        backend, skill_backend, skill_middleware = compose(backend, internal, internal.skills)
        internal.skill_backend = skill_backend
        middleware = [*middleware, skill_middleware]
    return create_deep_agent(model=model, tools=list(tools), backend=backend,
        middleware=[ResultGate(internal, prepare_tool), *middleware], subagents=[], memory=None, skills=None,
        store=None, checkpointer=checkpointer, interrupt_on=interrupt_on,
        system_prompt=system_prompt or 'Use only authorized local operations and approved views.')
