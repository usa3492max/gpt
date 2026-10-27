"""Provider-agnostic chat interface."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Message:
    role: str  # "user" | "assistant"
    content: str

    def to_dict(self) -> dict[str, Any]:
        return {"role": self.role, "content": self.content}


@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0

    def __add__(self, other: Usage) -> Usage:
        return Usage(
            input_tokens=self.input_tokens + other.input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            cache_read_tokens=self.cache_read_tokens + other.cache_read_tokens,
            cache_write_tokens=self.cache_write_tokens + other.cache_write_tokens,
        )

    def __iadd__(self, other: Usage) -> Usage:
        self.input_tokens += other.input_tokens
        self.output_tokens += other.output_tokens
        self.cache_read_tokens += other.cache_read_tokens
        self.cache_write_tokens += other.cache_write_tokens
        return self

    @property
    def total(self) -> int:
        return self.input_tokens + self.output_tokens

    def to_dict(self) -> dict[str, int]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens,
        }


@dataclass
class Completion:
    text: str
    usage: Usage = field(default_factory=Usage)
    stop_reason: str = ""
    model: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


class LLMError(Exception):
    """A model call failed. ``retryable`` drives the retry wrapper."""

    retryable = False
    kind = "error"

    def __init__(self, message: str, *, retryable: bool = False, retry_after: float = 0.0) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.retry_after = retry_after


class AuthError(LLMError):
    kind = "auth"


class RateLimitError(LLMError):
    kind = "rate_limit"
    retryable = True


class NetworkError(LLMError):
    kind = "network"
    retryable = True


class ServerError(LLMError):
    kind = "server"
    retryable = True


class BadRequestError(LLMError):
    kind = "bad_request"


class ContextOverflowError(LLMError):
    kind = "context_overflow"


class LLMClient:
    """Minimal surface the agent needs."""

    name: str = "base"
    model: str = ""

    async def complete(
        self,
        system: str,
        messages: list[Message],
        *,
        max_tokens: int = 2048,
        temperature: float = 0.7,
    ) -> Completion:  # pragma: no cover - interface
        raise NotImplementedError

    async def aclose(self) -> None:
        return None

    @property
    def supports_prompt_cache(self) -> bool:
        return False
