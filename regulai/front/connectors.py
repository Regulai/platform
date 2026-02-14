"""
AI Provider Connectors

This module provides a unified interface for different AI providers (OpenAI, Anthropic, etc.)
Each connector implements the same interface for sending chat messages.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class ChatMessage:
    """Represents a chat message."""
    role: str  # 'user', 'assistant', 'system'
    content: Any  # str or list (for multimodal content)


@dataclass
class ChatResponse:
    """Represents a response from the AI provider."""
    content: str
    tokens_used: int = 0
    model: str = ""
    finish_reason: str = ""


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
        **kwargs
    ) -> ChatResponse:
        """Send a chat request using OpenAI API."""
        # Convert ChatMessage objects to dict format
        api_messages = []
        for msg in messages:
            api_messages.append({
                "role": msg.role,
                "content": msg.content
            })

        response = self.client.chat.completions.create(
            model=model,
            messages=api_messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )

        return ChatResponse(
            content=response.choices[0].message.content,
            tokens_used=response.usage.total_tokens if response.usage else 0,
            model=response.model if hasattr(response, 'model') else model,
            finish_reason=response.choices[0].finish_reason if response.choices else ""
        )

    def supports_vision(self) -> bool:
        return True


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
            finish_reason=response.stop_reason if hasattr(response, 'stop_reason') else ""
        )

    def supports_vision(self) -> bool:
        return True


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
