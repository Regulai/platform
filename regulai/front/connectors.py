"""
AI Provider Connectors

This module provides a unified interface for different AI providers (OpenAI, Anthropic, etc.)
Each connector implements the same interface for sending chat messages.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Iterator, Union
from dataclasses import dataclass, field


@dataclass
class ChatMessage:
    """Represents a chat message."""
    role: str  # 'user', 'assistant', 'system', 'tool'
    content: Any  # str or list (for multimodal content)
    tool_call_id: Optional[str] = None  # For tool response messages


@dataclass
class ToolCall:
    """Represents a tool call from the AI."""
    id: str
    name: str
    arguments: Dict[str, Any]


@dataclass
class ChatResponse:
    """Represents a response from the AI provider."""
    content: str
    tokens_used: int = 0
    model: str = ""
    finish_reason: str = ""
    tool_calls: List[ToolCall] = field(default_factory=list)


@dataclass
class ModelInfo:
    """Represents an AI model."""
    model_id: str
    name: str
    description: str = ""
    supports_vision: bool = False
    max_tokens: int = 4096


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
        tools: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> ChatResponse:
        """Send a chat request and return the response."""
        pass

    @abstractmethod
    def chat_stream(
        self,
        messages: List[ChatMessage],
        model: str,
        max_tokens: int = 1000,
        temperature: float = 0.6,
        **kwargs
    ) -> Iterator[str]:
        """Send a chat request and yield response tokens as they arrive."""
        pass

    def chat_with_tools(
        self,
        messages: List[ChatMessage],
        model: str,
        tools: List[Dict[str, Any]],
        max_tokens: int = 1000,
        temperature: float = 0.6,
        **kwargs
    ) -> ChatResponse:
        """Send a chat request with tools and return the response."""
        return self.chat(messages, model, max_tokens, temperature, tools=tools, **kwargs)

    @abstractmethod
    def supports_vision(self) -> bool:
        """Return whether this connector supports vision/image inputs."""
        pass

    @abstractmethod
    def list_models(self) -> List[ModelInfo]:
        """Fetch available models from the provider API."""
        pass

    def supports_tools(self) -> bool:
        """Return whether this connector supports tool use."""
        return False


class OpenAIConnector(BaseConnector):
    """Connector for OpenAI and OpenAI-compatible APIs."""

    def __init__(self, api_key: str, base_url: Optional[str] = None):
        super().__init__(api_key, base_url)
        from openai import OpenAI
        if base_url:
            self.client = OpenAI(api_key=api_key, base_url=base_url)
        else:
            self.client = OpenAI(api_key=api_key)

    def chat(
        self,
        messages: List[ChatMessage],
        model: str,
        max_tokens: int = 1000,
        temperature: float = 0.6,
        tools: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> ChatResponse:
        """Send a chat request using OpenAI API."""
        import json

        # Convert ChatMessage objects to dict format
        api_messages = []
        for msg in messages:
            msg_dict = {
                "role": msg.role,
                "content": msg.content
            }
            # Handle tool response messages
            if msg.role == 'tool' and msg.tool_call_id:
                msg_dict['tool_call_id'] = msg.tool_call_id
            api_messages.append(msg_dict)

        # Build request kwargs
        request_kwargs = {
            "model": model,
            "messages": api_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        # Add tools if provided
        if tools:
            request_kwargs["tools"] = tools
            request_kwargs["tool_choice"] = "auto"

        response = self.client.chat.completions.create(**request_kwargs)

        # Extract tool calls if present
        tool_calls = []
        message = response.choices[0].message
        if hasattr(message, 'tool_calls') and message.tool_calls:
            for tc in message.tool_calls:
                try:
                    arguments = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    arguments = {}
                tool_calls.append(ToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    arguments=arguments
                ))

        return ChatResponse(
            content=message.content or "",
            tokens_used=response.usage.total_tokens if response.usage else 0,
            model=response.model if hasattr(response, 'model') else model,
            finish_reason=response.choices[0].finish_reason if response.choices else "",
            tool_calls=tool_calls
        )

    def supports_tools(self) -> bool:
        return True

    def chat_stream(
        self,
        messages: List[ChatMessage],
        model: str,
        max_tokens: int = 1000,
        temperature: float = 0.6,
        **kwargs
    ) -> Iterator[str]:
        """Send a chat request and yield response tokens as they arrive."""
        # Convert ChatMessage objects to dict format
        api_messages = []
        for msg in messages:
            api_messages.append({
                "role": msg.role,
                "content": msg.content
            })

        stream = self.client.chat.completions.create(
            model=model,
            messages=api_messages,
            max_tokens=max_tokens,
            temperature=temperature,
            stream=True,
        )

        for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

    def supports_vision(self) -> bool:
        return True

    def list_models(self) -> List[ModelInfo]:
        """Fetch available models from OpenAI API."""
        try:
            response = self.client.models.list()
            models = []
            for model in response.data:
                # Filter to chat models only
                model_id = model.id
                if any(x in model_id for x in ['gpt-4', 'gpt-3.5', 'o1', 'o3']):
                    # Determine if model supports vision
                    supports_vision = any(x in model_id for x in ['gpt-4o', 'gpt-4-turbo', 'gpt-4-vision', 'o1', 'o3'])
                    models.append(ModelInfo(
                        model_id=model_id,
                        name=model_id,
                        description=f"OpenAI {model_id}",
                        supports_vision=supports_vision,
                        max_tokens=4096
                    ))
            # Sort by model name
            models.sort(key=lambda x: x.model_id)
            return models
        except Exception as e:
            return []


class AnthropicConnector(BaseConnector):
    """Connector for Anthropic Claude API."""

    def __init__(self, api_key: str, base_url: Optional[str] = None):
        super().__init__(api_key, base_url)
        try:
            import anthropic
            if base_url:
                self.client = anthropic.Anthropic(api_key=api_key, base_url=base_url)
            else:
                self.client = anthropic.Anthropic(api_key=api_key)
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
        tools: Optional[List[Dict[str, Any]]] = None,
        **kwargs
    ) -> ChatResponse:
        """Send a chat request using Anthropic API."""
        if not self._available:
            raise ImportError("anthropic package is not installed. Install with: pip install anthropic")

        # Anthropic has different message format
        # System messages are passed separately
        system_message = None
        api_messages = []

        for msg in messages:
            if msg.role == 'system':
                system_message = msg.content if isinstance(msg.content, str) else str(msg.content)
            elif msg.role == 'tool':
                # Handle tool result messages for Anthropic
                api_messages.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": msg.tool_call_id,
                        "content": msg.content
                    }]
                })
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
            "temperature": temperature,
        }

        # Add system message if present
        if system_message:
            request_kwargs["system"] = system_message

        # Add tools if provided (convert from OpenAI format to Anthropic format)
        if tools:
            anthropic_tools = []
            for tool in tools:
                if tool.get('type') == 'function':
                    func = tool.get('function', {})
                    anthropic_tools.append({
                        "name": func.get('name'),
                        "description": func.get('description'),
                        "input_schema": func.get('parameters', {})
                    })
            if anthropic_tools:
                request_kwargs["tools"] = anthropic_tools

        response = self.client.messages.create(**request_kwargs)

        # Extract text and tool calls from Anthropic response
        content_text = ""
        tool_calls = []
        if response.content:
            for block in response.content:
                if hasattr(block, 'text'):
                    content_text += block.text
                elif hasattr(block, 'type') and block.type == 'tool_use':
                    tool_calls.append(ToolCall(
                        id=block.id,
                        name=block.name,
                        arguments=block.input if hasattr(block, 'input') else {}
                    ))

        return ChatResponse(
            content=content_text,
            tokens_used=(response.usage.input_tokens + response.usage.output_tokens) if response.usage else 0,
            model=response.model if hasattr(response, 'model') else model,
            finish_reason=response.stop_reason if hasattr(response, 'stop_reason') else "",
            tool_calls=tool_calls
        )

    def supports_tools(self) -> bool:
        return True

    def chat_stream(
        self,
        messages: List[ChatMessage],
        model: str,
        max_tokens: int = 1000,
        temperature: float = 0.6,
        **kwargs
    ) -> Iterator[str]:
        """Send a chat request and yield response tokens as they arrive."""
        if not self._available:
            raise ImportError("anthropic package is not installed. Install with: pip install anthropic")

        # Anthropic has different message format
        # System messages are passed separately
        system_message = None
        api_messages = []

        for msg in messages:
            if msg.role == 'system':
                system_message = msg.content if isinstance(msg.content, str) else str(msg.content)
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
                                    # URL-based image
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
            "temperature": temperature,
            "stream": True,
        }

        # Add system message if present
        if system_message:
            request_kwargs["system"] = system_message

        with self.client.messages.stream(**request_kwargs) as stream:
            for text in stream.text_stream:
                yield text

    def supports_vision(self) -> bool:
        return True

    def list_models(self) -> List[ModelInfo]:
        """Fetch available models from Anthropic API."""
        if not self._available:
            return []
        try:
            response = self.client.models.list()
            models = []
            for model in response.data:
                model_id = model.id
                # All Claude 3+ models support vision
                supports_vision = 'claude-3' in model_id or 'claude-sonnet-4' in model_id or 'claude-opus-4' in model_id
                # Get display name
                display_name = model.display_name if hasattr(model, 'display_name') else model_id
                models.append(ModelInfo(
                    model_id=model_id,
                    name=display_name,
                    description=f"Anthropic {display_name}",
                    supports_vision=supports_vision,
                    max_tokens=8192 if 'opus' in model_id or 'sonnet' in model_id else 4096
                ))
            # Sort by model name
            models.sort(key=lambda x: x.model_id, reverse=True)
            return models
        except Exception as e:
            return []


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
    }

    connector_class = connectors.get(connector_type)
    if not connector_class:
        raise ValueError(f"Unknown connector type: {connector_type}. Available: {list(connectors.keys())}")

    return connector_class(api_key=api_key, base_url=base_url)
