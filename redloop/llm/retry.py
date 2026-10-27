"""Exponential-backoff retry wrapper that also reports progress to the UI."""

from __future__ import annotations

import asyncio
import random
from collections.abc import Callable

from .base import Completion, LLMClient, LLMError, Message


class RetryingClient(LLMClient):
    def __init__(
        self,
        inner: LLMClient,
        *,
        max_attempts: int = 5,
        base_delay: float = 2.0,
        max_delay: float = 60.0,
        on_retry: Callable[[int, float, str], None] | None = None,
    ) -> None:
        self.inner = inner
        self.name = inner.name
        self.model = inner.model
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.on_retry = on_retry

    @property
    def supports_prompt_cache(self) -> bool:
        return self.inner.supports_prompt_cache

    async def complete(
        self,
        system: str,
        messages: list[Message],
        *,
        max_tokens: int = 2048,
        temperature: float = 0.7,
    ) -> Completion:
        attempt = 0
        while True:
            attempt += 1
            try:
                return await self.inner.complete(
                    system, messages, max_tokens=max_tokens, temperature=temperature
                )
            except LLMError as exc:
                if not exc.retryable or attempt >= self.max_attempts:
                    raise
                delay = exc.retry_after or min(
                    self.max_delay, self.base_delay * (2 ** (attempt - 1))
                )
                delay += random.uniform(0, min(2.0, delay * 0.25))
                if self.on_retry:
                    self.on_retry(attempt, delay, str(exc))
                await asyncio.sleep(delay)

    async def aclose(self) -> None:
        await self.inner.aclose()
