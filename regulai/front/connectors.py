"""
AI Provider Connectors

This module provides a unified interface for different AI providers (OpenAI, Anthropic, etc.)
Each connector implements the same interface for sending chat messages.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Literal
from dataclasses import dataclass, field


DOCUMENT_RESPONSE_SCHEMA = {
    'type': 'object', 'required': ['claims'], 'additionalProperties': False,
    'properties': {'claims': {'type': 'array', 'items': {
        'type': 'object', 'required': ['text', 'citations'], 'additionalProperties': False,
        'properties': {
            'text': {'type': 'string'},
            'citations': {'type': 'array', 'items': {
                'type': 'object', 'required': ['id', 'quote'], 'additionalProperties': False,
                'properties': {'id': {'type': 'string'}, 'quote': {'type': 'string'}},
            }},
        },
    }}},
}


@dataclass
class ChatMessage:
    """Represents a chat message."""
    role: str  # 'user', 'assistant', 'system'
    content: Any  # str or list (for multimodal content)
    tool_calls: list[dict] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None


@dataclass
class ChatResponse:
    """Represents a response from the AI provider."""
    content: str
    tokens_used: int = 0
    model: str = ""
    finish_reason: str | None = ""
    input_tokens: int | None = None
    output_tokens: int | None = None
    provider_request_id: str | None = None
    usage: dict = field(default_factory=dict)
    tool_calls: list[dict] = field(default_factory=list)
    inference_options: dict = field(default_factory=dict)


@dataclass(frozen=True)
class ProviderStreamEvent:
    """Internal provider events. Arguments are never public progress text."""
    kind: Literal['text', 'tool_arguments', 'finish', 'usage']
    text: str = ''
    index: int | None = None
    call_id: str | None = None
    name: str | None = None
    finish_reason: str | None = None
    usage: dict = field(default_factory=dict)


class ProviderStreamInvalid(ValueError):
    """A fully read response may have valid usage while its tools are unusable."""

    def __init__(self, code, receipt):
        super().__init__(code)
        self.receipt = receipt


class StreamToolAccumulator:
    """Assemble complete tool calls without ever handing partial JSON to a worker."""

    def __init__(self, *, max_bytes=512_000, max_calls=32):
        self.max_bytes, self.max_calls = max_bytes, max_calls
        self.calls, self.ids, self.size = {}, {}, 0

    def add(self, fragment):
        index = fragment.index
        if type(index) is not int or not 0 <= index < self.max_calls:
            raise ValueError('invalid_stream_tool_index')
        state = self.calls.setdefault(index, {'id': None, 'name': '', 'arguments': ''})
        identifier = getattr(fragment, 'id', None)
        if identifier:
            if state['id'] not in (None, identifier) or self.ids.get(identifier, index) != index:
                raise ValueError('inconsistent_stream_tool_id')
            self.ids[identifier], state['id'] = index, identifier
        if getattr(fragment, 'type', None) not in (None, 'function'):
            raise ValueError('invalid_stream_tool_type')
        function = getattr(fragment, 'function', None)
        name = getattr(function, 'name', None) or ''
        arguments = getattr(function, 'arguments', None) or ''
        if not isinstance(name, str) or not isinstance(arguments, str):
            raise ValueError('invalid_stream_tool_fragment')
        self.size += len((name + arguments + (identifier or '')).encode('utf-8'))
        if self.size > self.max_bytes:
            raise ValueError('stream_tools_too_large')
        state['name'] += name
        state['arguments'] += arguments
        if len(state['name']) > 64 or len(state['arguments'].encode('utf-8')) > self.max_bytes:
            raise ValueError('stream_tool_too_large')
        return ProviderStreamEvent('tool_arguments', text=arguments, index=index,
                                   call_id=state['id'], name=state['name'])

    def finish(self, reason):
        if reason != 'tool_calls':
            if self.calls:
                raise ValueError('incomplete_stream_tools')
            return []
        if not self.calls or set(self.calls) != set(range(len(self.calls))):
            raise ValueError('incomplete_stream_tools')
        import json
        from .agents.protocol import ToolCall, validate_arguments
        calls = []
        for index in sorted(self.calls):
            state = self.calls[index]
            def reject_constant(value):
                raise ValueError('nonfinite_stream_arguments')
            def unique_object(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError('duplicate_stream_argument')
                    result[key] = value
                return result
            value = json.loads(state['arguments'], parse_constant=reject_constant, object_pairs_hook=unique_object)
            call = ToolCall.model_validate({'id': state['id'], 'name': state['name'], 'args': value})
            validate_arguments(call)
            calls.append(call.model_dump())
        return calls


class BaseConnector(ABC):
    """Base class for AI provider connectors."""

    def __init__(self, api_key: str, base_url: Optional[str] = None):
        self.api_key = api_key
        self.base_url = base_url

    @abstractmethod
    def chat(
        self,
        messages: List[ChatMessage],
        model: str,
        max_tokens: int = 1000,
        temperature: float = 0.6,
        *, supports_json: bool = False, reasoning: bool = False,
        **kwargs
    ) -> ChatResponse:
        """Send a chat request and return the response."""
        pass

    @abstractmethod
    def supports_vision(self) -> bool:
        """Return whether this connector supports vision/image inputs."""
        pass


class OpenAIConnector(BaseConnector):
    """Connector for OpenAI and OpenAI-compatible APIs."""

    def __init__(self, api_key: str, base_url: Optional[str] = None):
        super().__init__(api_key, base_url)
        self.connector_type = 'openai'
        from openai import OpenAI, DefaultHttpxClient
        self.client = OpenAI(api_key=api_key, base_url=base_url, max_retries=0, timeout=30,
                            http_client=DefaultHttpxClient(follow_redirects=False))

    def chat(
        self,
        messages: List[ChatMessage],
        model: str,
        max_tokens: int = 1000,
        temperature: float = 0.6,
        *, supports_json: bool = False, reasoning: bool = False,
        **kwargs
    ) -> ChatResponse:
        """Use explicit model capabilities; supports_json requests JSON output.

        A missing finish_reason is preserved: compatible providers must report
        an explicit completion signal before the response can pass verification.
        """
        # Convert ChatMessage objects to dict format
        api_messages = []
        for msg in messages:
            wire = {"role": msg.role, "content": msg.content}
            if msg.tool_calls:
                from .agents.protocol import ToolCall
                wire['tool_calls'] = [ToolCall.model_validate(call).openai() for call in msg.tool_calls]
            if msg.tool_call_id is not None:
                wire['tool_call_id'] = msg.tool_call_id
            if msg.name is not None:
                wire['name'] = msg.name
            api_messages.append(wire)

        explicit = kwargs.get('inference_options')
        options = {}
        if explicit is not None:
            from .agents.inference_options import wire_options
            if 'extra_body' in kwargs:
                raise ValueError('Explicit inference options cannot be mixed with arbitrary extra_body.')
            expected = {'openai': 'openai', 'deepseek': 'openai_compatible', 'vercel_gateway': 'vercel_gateway'}
            if expected.get(explicit.get('dialect')) != self.connector_type:
                raise ValueError('inference_dialect_mismatch')
            options = wire_options(explicit, model=model, tools=bool(kwargs.get('tools')))
        request = dict(
            model=model,
            messages=api_messages,
            **(options if explicit is not None else {} if max_tokens is None else
               {'max_completion_tokens': max_tokens} if reasoning else {'max_tokens': max_tokens}),
            **({} if reasoning or explicit is not None else {'temperature': temperature}),
            **({'response_format': {'type': 'json_object'}} if supports_json else {}),
            timeout=kwargs.get('timeout', 30),
            **({'tools': kwargs['tools']} if kwargs.get('tools') else {}),
            **({'extra_body': kwargs['extra_body']} if 'extra_body' in kwargs else {}),
        )
        if isinstance(self, VercelGatewayConnector):
            # The only gateway extras are derived here; caller-provided routes
            # and fallbacks cannot replace the pinned upstream.
            request['extra_body'] = {**options.get('extra_body', {}),
                'providerOptions': {'gateway': {'only': [model.split('/', 1)[0]]}}}
        if kwargs.get('on_delta') is not None or kwargs.get('on_event') is not None:
            result = self._stream(request, model, kwargs.get('on_delta'), kwargs.get('on_open'),
                on_event=kwargs.get('on_event'), on_close=kwargs.get('on_close'),
                max_bytes=kwargs.get('stream_max_bytes', 512_000))
            result.inference_options = {'sent': request.get('extra_body', {}) | {key: value for key, value in options.items()
                if key != 'extra_body'}, 'observed_thinking_mode': 'unknown'} if explicit else {}
            return result
        response = self.client.chat.completions.create(**request)

        tool_calls = []
        for call in getattr(response.choices[0].message, 'tool_calls', None) or []:
            import json
            from .agents.protocol import ToolCall
            tool_calls.append(ToolCall.model_validate({'id': call.id, 'name': call.function.name,
                'args': json.loads(call.function.arguments)}).model_dump())
        return ChatResponse(
            content=response.choices[0].message.content,
            tokens_used=response.usage.total_tokens if response.usage else 0,
            model=response.model if hasattr(response, 'model') else model,
            finish_reason=response.choices[0].finish_reason if response.choices else "",
            input_tokens=response.usage.prompt_tokens if response.usage else None,
            output_tokens=response.usage.completion_tokens if response.usage else None,
            provider_request_id=getattr(response, 'id', None),
            usage=response.usage.model_dump() if response.usage else {},
            tool_calls=tool_calls,
            inference_options={'sent': request.get('extra_body', {}) | {key: value for key, value in options.items()
                if key != 'extra_body'}, 'observed_thinking_mode': 'unknown'} if explicit else {},
        )

    def _stream(self, request, model, on_delta=None, on_open=None, *, on_event=None,
                on_close=None, max_bytes=512_000):
        """Server-sent chunks; on_delta sees each text fragment as it arrives.

        An exception from on_delta closes the HTTP stream, which stops reading
        and lets the provider end the generation. on_open receives a callable
        that closes the stream from another thread (a user's stop). Usage
        arrives in the final chunk only when the endpoint honours
        stream_options.include_usage.
        """
        parts, finish, usage, effective, identifier, size = [], None, None, model, None, 0
        calls = StreamToolAccumulator(max_bytes=max_bytes)
        try:
            stream = self.client.chat.completions.create(**request, stream=True,
                                                         stream_options={'include_usage': True})
            with stream:
                if on_open is not None:
                    on_open(stream.close)
                for chunk in stream:
                    chunk_id = getattr(chunk, 'id', None)
                    if identifier and chunk_id and identifier != chunk_id:
                        raise ValueError('inconsistent_stream_response_id')
                    identifier = identifier or chunk_id
                    effective = getattr(chunk, 'model', None) or effective
                    if getattr(chunk, 'usage', None):
                        usage = chunk.usage
                        if on_event:
                            on_event(ProviderStreamEvent('usage', usage=usage.model_dump()))
                    for choice in chunk.choices or []:
                        if getattr(choice, 'index', 0) != 0:
                            raise ValueError('unexpected_stream_choice')
                        delta = choice.delta
                        text = getattr(delta, 'content', None) if delta else None
                        fragments = getattr(delta, 'tool_calls', None) if delta else None
                        if finish and (text or fragments or choice.finish_reason):
                            raise ValueError('content_after_stream_finish')
                        if text:
                            size += len(text.encode('utf-8'))
                            if size + calls.size > max_bytes:
                                raise ValueError('stream_response_too_large')
                            parts.append(text)
                            if on_delta:
                                on_delta(text)
                            if on_event:
                                on_event(ProviderStreamEvent('text', text=text))
                        for fragment in fragments or []:
                            event = calls.add(fragment)
                            if size + calls.size > max_bytes:
                                raise ValueError('stream_response_too_large')
                            if on_event:
                                on_event(event)
                        if choice.finish_reason:
                            finish = choice.finish_reason
                            if on_event:
                                on_event(ProviderStreamEvent('finish', finish_reason=finish))
        finally:
            if on_close is not None:
                on_close()
        # An explicit terminal tool reason and valid complete schema are mandatory.
        # A parseable prefix followed by length/EOF still authorizes no tools.
        response = ChatResponse(
            content=''.join(parts),
            tokens_used=usage.total_tokens if usage else 0,
            model=effective,
            finish_reason=finish,
            input_tokens=usage.prompt_tokens if usage else None,
            output_tokens=usage.completion_tokens if usage else None,
            provider_request_id=identifier,
            usage=usage.model_dump() if usage else {},
        )
        try:
            response.tool_calls = calls.finish(finish)
        except ValueError as error:
            # Preserve only the known receipt; malformed content never reaches
            # the worker and a known usage record must not become unknown cost.
            response.content = ''
            raise ProviderStreamInvalid(str(error), response) from None
        return response

    def supports_vision(self) -> bool:
        return True


class AnthropicConnector(BaseConnector):
    """Connector for Anthropic Claude API."""

    def __init__(self, api_key: str, base_url: Optional[str] = None):
        super().__init__(api_key, base_url)
        try:
            import anthropic
            self.client = anthropic.Anthropic(api_key=api_key, base_url=base_url, max_retries=0, timeout=30,
                http_client=anthropic.DefaultHttpxClient(follow_redirects=False))
            self._available = True
        except ImportError:
            self._available = False
            self.client = None

    def chat(
        self,
        messages: List[ChatMessage],
        model: str,
        max_tokens: int = 1000,
        temperature: float = 0.6,
        *, supports_json: bool = False, reasoning: bool = False,
        **kwargs
    ) -> ChatResponse:
        """Send a chat request using Anthropic API."""
        if not self._available:
            raise ImportError("anthropic package is not installed. Install with: pip install anthropic")
        if kwargs.get('inference_options') is not None:
            raise ValueError('Explicit agent inference options are unavailable for Anthropic.')
        if kwargs.get('tools') or any(m.tool_calls or m.tool_call_id is not None for m in messages):
            raise ValueError('Native tool messages require the OpenAI-compatible agent protocol.')

        # Anthropic has different message format
        # System messages are passed separately
        system_messages = []
        api_messages = []

        for msg in messages:
            if msg.role == 'system':
                system_messages.append(msg.content if isinstance(msg.content, str) else str(msg.content))
            else:
                # Handle multimodal content for Anthropic
                if isinstance(msg.content, list):
                    # Convert OpenAI format to Anthropic format
                    anthropic_content = []
                    for item in msg.content:
                        if isinstance(item, dict):
                            if item.get('type') == 'text':
                                anthropic_content.append({
                                    "type": "text",
                                    "text": item.get('text', '')
                                })
                            elif item.get('type') == 'image_url':
                                # Convert OpenAI image_url format to Anthropic format
                                image_url = item.get('image_url', {})
                                url = image_url.get('url', '') if isinstance(image_url, dict) else str(image_url)

                                # Extract base64 data from data URL
                                if url.startswith('data:'):
                                    # Format: data:image/png;base64,<data>
                                    parts = url.split(',', 1)
                                    if len(parts) == 2:
                                        media_type_part = parts[0].replace('data:', '').replace(';base64', '')
                                        anthropic_content.append({
                                            "type": "image",
                                            "source": {
                                                "type": "base64",
                                                "media_type": media_type_part,
                                                "data": parts[1]
                                            }
                                        })
                                else:
                                    # URL-based image (Anthropic also supports this)
                                    anthropic_content.append({
                                        "type": "image",
                                        "source": {
                                            "type": "url",
                                            "url": url
                                        }
                                    })
                        else:
                            anthropic_content.append({
                                "type": "text",
                                "text": str(item)
                            })
                    content = anthropic_content
                else:
                    content = msg.content

                api_messages.append({
                    "role": msg.role,
                    "content": content
                })

        # Build request kwargs
        request_kwargs = {
            "model": model,
            "messages": api_messages,
            "max_tokens": max_tokens,
            "timeout": kwargs.get('timeout', 30),
        }
        if not reasoning:
            request_kwargs['temperature'] = temperature
        if supports_json:
            request_kwargs['output_config'] = {'format': {
                'type': 'json_schema', 'schema': DOCUMENT_RESPONSE_SCHEMA}}

        # Add system message if present
        if system_messages:
            request_kwargs["system"] = '\n\n'.join(system_messages)

        if kwargs.get('on_delta') is not None:
            # Same request as create(); the final message carries usage and stop reason.
            with self.client.messages.stream(**request_kwargs) as stream:
                if kwargs.get('on_open') is not None:
                    kwargs['on_open'](stream.close)
                for text in stream.text_stream:
                    kwargs['on_delta'](text)
                response = stream.get_final_message()
        else:
            response = self.client.messages.create(**request_kwargs)

        # Extract text from Anthropic response
        content_text = ""
        if response.content:
            for block in response.content:
                if hasattr(block, 'text'):
                    content_text += block.text

        return ChatResponse(
            content=content_text,
            tokens_used=(response.usage.input_tokens + response.usage.output_tokens) if response.usage else 0,
            model=response.model if hasattr(response, 'model') else model,
            finish_reason=response.stop_reason if hasattr(response, 'stop_reason') else "",
            input_tokens=response.usage.input_tokens if response.usage else None,
            output_tokens=response.usage.output_tokens if response.usage else None,
            provider_request_id=getattr(response, 'id', None),
            usage=response.usage.model_dump() if response.usage else {},
        )

    def supports_vision(self) -> bool:
        return True


class VercelGatewayConnector(OpenAIConnector):
    """Fixed gateway and one upstream provider per requested model."""

    def __init__(self, api_key: str, base_url: Optional[str] = None):
        endpoint = 'https://ai-gateway.vercel.sh/v1'
        if base_url and base_url.rstrip('/') != endpoint:
            raise ValueError('Vercel AI Gateway requires its official endpoint.')
        super().__init__(api_key, endpoint)
        self.connector_type = 'vercel_gateway'

    def chat(self, messages, model, max_tokens=1000, temperature=0.6, **kwargs):
        provider, separator, identifier = model.partition('/')
        if provider not in {'anthropic', 'mistral', 'google', 'openai'} or not separator or not identifier:
            raise ValueError('Unsupported Vercel AI Gateway chat model.')
        # Do not allow a caller to add destinations or model fallbacks.
        # Legacy callers may not supply gateway fallbacks either. Explicit
        # options are translated and merged with this pin in the parent.
        kwargs.pop('extra_body', None)
        return super().chat(messages, model, max_tokens, temperature, **kwargs)


def get_connector(connector_type: str, api_key: str, base_url: Optional[str] = None) -> BaseConnector:
    """
    Factory function to get the appropriate connector based on type.

    Args:
        connector_type: One of 'openai', 'anthropic', 'openai_compatible'
        api_key: API key for the provider
        base_url: Optional custom base URL

    Returns:
        BaseConnector instance
    """
    connectors = {
        'openai': OpenAIConnector,
        'openai_compatible': OpenAIConnector,
        'anthropic': AnthropicConnector,
        'vercel_gateway': VercelGatewayConnector,
    }

    connector_class = connectors.get(connector_type)
    if not connector_class:
        raise ValueError(f"Unknown connector type: {connector_type}. Available: {list(connectors.keys())}")

    connector = connector_class(api_key=api_key, base_url=base_url)
    connector.connector_type = connector_type
    return connector
