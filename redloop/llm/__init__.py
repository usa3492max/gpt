"""Model clients and factory."""

from __future__ import annotations

from collections.abc import Callable

from ..config import Config
from .anthropic import AnthropicClient
from .base import (
    AuthError,
    BadRequestError,
    Completion,
    ContextOverflowError,
    LLMClient,
    LLMError,
    Message,
    NetworkError,
    RateLimitError,
    ServerError,
    Usage,
)
from .mock import MockClient
from .openai import OpenAIClient
from .retry import RetryingClient


def build_client(
    config: Config,
    *,
    on_retry: Callable[[int, float, str], None] | None = None,
    transport=None,
) -> LLMClient:
    preset = config.preset
    model = config.effective_model

    if preset.kind == "mock":
        return MockClient(target=config.target, model=model)

    if preset.kind == "anthropic":
        inner: LLMClient = AnthropicClient(
            api_key=config.effective_api_key,
            model=model,
            base_url=config.effective_base_url,
            timeout=config.request_timeout,
            use_cache=config.prompt_cache,
            transport=transport,
        )
    else:
        inner = OpenAIClient(
            model=model,
            base_url=config.effective_base_url,
            api_key=config.effective_api_key,
            timeout=config.request_timeout,
            label=preset.key,
            transport=transport,
        )
    return RetryingClient(inner, max_attempts=config.max_retries, on_retry=on_retry)


def describe(client: LLMClient) -> str:
    return f"{client.name}:{client.model}"


__all__ = [
    "AnthropicClient",
    "AuthError",
    "BadRequestError",
    "Completion",
    "ContextOverflowError",
    "LLMClient",
    "LLMError",
    "Message",
    "MockClient",
    "NetworkError",
    "OpenAIClient",
    "RateLimitError",
    "RetryingClient",
    "ServerError",
    "Usage",
    "build_client",
    "describe",
]
