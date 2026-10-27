"""Anthropic Messages API client."""

from __future__ import annotations

import json
from typing import Any

import httpx

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

ANTHROPIC_VERSION = "2023-06-01"


class AnthropicClient(LLMClient):
    name = "anthropic"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str = "https://api.anthropic.com",
        timeout: float = 180.0,
        use_cache: bool = True,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.model = model
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.use_cache = use_cache
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(timeout, connect=20.0),
            transport=transport,
            headers={
                "x-api-key": api_key,
                "anthropic-version": ANTHROPIC_VERSION,
                "content-type": "application/json",
                "user-agent": "redloop/0.1",
            },
        )

    @property
    def supports_prompt_cache(self) -> bool:
        return self.use_cache

    async def complete(
        self,
        system: str,
        messages: list[Message],
        *,
        max_tokens: int = 2048,
        temperature: float = 0.7,
    ) -> Completion:
        system_blocks: list[dict[str, Any]] = [{"type": "text", "text": system}]
        if self.use_cache:
            system_blocks[0]["cache_control"] = {"type": "ephemeral"}
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max(256, int(max_tokens)),
            "temperature": max(0.0, min(2.0, float(temperature))),
            "system": system_blocks,
            "messages": [m.to_dict() for m in messages if m.content.strip()],
        }
        try:
            response = await self._client.post("/v1/messages", json=payload)
        except httpx.TimeoutException as exc:
            raise NetworkError(f"Anthropic request timed out: {exc}", retryable=True) from exc
        except httpx.HTTPError as exc:
            raise NetworkError(f"Anthropic connection failed: {exc}", retryable=True) from exc

        if response.status_code != 200:
            raise _error_from_response(response)

        data = response.json()
        text_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        for block in data.get("content", []):
            if block.get("type") == "text":
                text_parts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                tool_calls.append({"tool": block.get("name"), "args": block.get("input", {})})
            elif block.get("type") == "thinking":
                # Keep reasoning out of the protocol; the visible text is enough.
                continue
        text = "".join(text_parts).strip()
        if tool_calls:
            call = tool_calls[-1]
            text = (text + "\n\n" if text else "") + "```json\n" + json.dumps(call) + "\n```"

        usage_raw = data.get("usage", {}) or {}
        usage = Usage(
            input_tokens=int(usage_raw.get("input_tokens", 0) or 0),
            output_tokens=int(usage_raw.get("output_tokens", 0) or 0),
            cache_read_tokens=int(usage_raw.get("cache_read_input_tokens", 0) or 0),
            cache_write_tokens=int(usage_raw.get("cache_creation_input_tokens", 0) or 0),
        )
        return Completion(
            text=text,
            usage=usage,
            stop_reason=str(data.get("stop_reason", "")),
            model=str(data.get("model", self.model)),
            raw=data,
        )

    async def aclose(self) -> None:
        await self._client.aclose()


def _error_from_response(response: httpx.Response) -> LLMError:
    try:
        body = response.json()
        message = body.get("error", {}).get("message") or json.dumps(body)[:400]
    except (ValueError, AttributeError):
        message = response.text[:400] or f"HTTP {response.status_code}"
    status = response.status_code
    retry_after = _retry_after(response)

    if status in (401, 403):
        return AuthError(
            f"Anthropic rejected the API key (HTTP {status}): {message}. "
            "Check ANTHROPIC_API_KEY."
        )
    if status == 429:
        return RateLimitError(f"Anthropic rate limit: {message}", retryable=True,
                              retry_after=retry_after)
    if status == 400 and any(
        token in message.lower()
        for token in ("prompt is too long", "context length", "too many tokens", "exceed")
    ):
        return ContextOverflowError(f"Anthropic context limit hit: {message}")
    if status == 404:
        return BadRequestError(
            f"Anthropic returned 404: {message}. Is the model name correct for this account?"
        )
    if status in (408, 409, 500, 502, 503, 504, 529):
        return ServerError(f"Anthropic server error (HTTP {status}): {message}", retryable=True,
                           retry_after=retry_after)
    if status == 400:
        return BadRequestError(f"Anthropic rejected the request (HTTP 400): {message}")
    return LLMError(f"Anthropic error (HTTP {status}): {message}", retryable=status >= 500)


def _retry_after(response: httpx.Response) -> float:
    header = response.headers.get("retry-after", "")
    try:
        return max(0.0, float(header))
    except ValueError:
        return 0.0
