"""OpenAI-compatible chat-completions client.

One implementation covers OpenAI, Ollama, LM Studio, vLLM, llama.cpp's server,
OpenRouter, Groq and anything else that speaks ``POST /v1/chat/completions``.
"""

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


class OpenAIClient(LLMClient):
    name = "openai"

    def __init__(
        self,
        *,
        model: str,
        base_url: str,
        api_key: str = "",
        timeout: float = 300.0,
        label: str = "openai",
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.name = label
        headers = {"content-type": "application/json", "user-agent": "redloop/0.1"}
        if api_key:
            headers["authorization"] = f"Bearer {api_key}"
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(timeout, connect=20.0),
            transport=transport,
            headers=headers,
        )

    async def complete(
        self,
        system: str,
        messages: list[Message],
        *,
        max_tokens: int = 2048,
        temperature: float = 0.7,
    ) -> Completion:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, *[m.to_dict() for m in messages]],
            "stream": False,
        }
        # Reasoning models reject temperature and the max_tokens spelling.
        reasoning = self.model.lower().startswith(("o1", "o3", "o4", "gpt-5"))
        if reasoning:
            payload["max_completion_tokens"] = max(256, int(max_tokens))
        else:
            payload["max_tokens"] = max(256, int(max_tokens))
            payload["temperature"] = max(0.0, min(2.0, float(temperature)))

        try:
            response = await self._client.post("/chat/completions", json=payload)
        except httpx.TimeoutException as exc:
            raise NetworkError(
                f"{self.name} request timed out: {exc}. Local models can be slow — raise "
                "REDLOOP_REQUEST_TIMEOUT or lower --max-output.",
                retryable=True,
            ) from exc
        except httpx.HTTPError as exc:
            raise NetworkError(
                f"{self.name} connection failed: {exc}. Is the endpoint reachable from the "
                f"container ({self.base_url})?",
                retryable=True,
            ) from exc

        if response.status_code != 200:
            raise _error_from_response(response, self.name, self.base_url)

        # Some local servers answer /chat/completions with SSE even when asked not to.
        if response.headers.get("content-type", "").startswith("text/event-stream"):
            data = _parse_sse(response.text)
        else:
            try:
                data = response.json()
            except ValueError as exc:
                raise LLMError(
                    f"{self.name} returned a non-JSON body: {response.text[:300]}"
                ) from exc

        choices = data.get("choices") or []
        if not choices:
            raise LLMError(f"{self.name} returned no choices: {json.dumps(data)[:300]}")
        message = choices[0].get("message", {}) or {}
        text = _content_to_text(message.get("content"))
        tool_calls = message.get("tool_calls") or []
        if tool_calls:
            call = tool_calls[0].get("function", {})
            arguments = call.get("arguments") or {}
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except ValueError:
                    arguments = {"command": arguments}
            text = (text + "\n\n" if text else "") + "```json\n" + json.dumps(
                {"tool": call.get("name"), "args": arguments}
            ) + "\n```"

        usage_raw = data.get("usage") or {}
        details = usage_raw.get("prompt_tokens_details") or {}
        usage = Usage(
            input_tokens=int(usage_raw.get("prompt_tokens", 0) or 0),
            output_tokens=int(usage_raw.get("completion_tokens", 0) or 0),
            cache_read_tokens=int(details.get("cached_tokens", 0) or 0),
        )
        return Completion(
            text=text.strip(),
            usage=usage,
            stop_reason=str(choices[0].get("finish_reason", "")),
            model=str(data.get("model", self.model)),
            raw=data,
        )

    async def aclose(self) -> None:
        await self._client.aclose()


def _content_to_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                parts.append(item.get("text") or item.get("content") or "")
            elif isinstance(item, str):
                parts.append(item)
        return "".join(parts)
    return str(content)


def _parse_sse(text: str) -> dict[str, Any]:
    """Fold a streamed completion back into one response object."""
    chunks: list[str] = []
    usage: dict[str, Any] = {}
    model = ""
    finish = ""
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if payload in {"", "[DONE]"}:
            continue
        try:
            event = json.loads(payload)
        except ValueError:
            continue
        model = event.get("model", model)
        if event.get("usage"):
            usage = event["usage"]
        for choice in event.get("choices", []):
            delta = choice.get("delta", {}) or {}
            piece = delta.get("content")
            if isinstance(piece, str):
                chunks.append(piece)
            finish = choice.get("finish_reason") or finish
    return {
        "model": model,
        "choices": [{"message": {"content": "".join(chunks)}, "finish_reason": finish}],
        "usage": usage,
    }


def _error_from_response(response: httpx.Response, name: str, base_url: str) -> LLMError:
    try:
        body = response.json()
        error = body.get("error")
        if isinstance(error, dict):
            message = error.get("message") or json.dumps(error)[:400]
        elif isinstance(error, str):
            message = error
        else:
            message = json.dumps(body)[:400]
    except ValueError:
        message = response.text[:400] or f"HTTP {response.status_code}"
    status = response.status_code
    retry_after = 0.0
    try:
        retry_after = max(0.0, float(response.headers.get("retry-after", "0") or 0))
    except ValueError:
        pass

    lowered = message.lower()
    if status in (401, 403):
        return AuthError(f"{name} rejected the credential (HTTP {status}): {message}")
    if status == 429:
        return RateLimitError(f"{name} rate limited: {message}", retryable=True,
                              retry_after=retry_after)
    if status == 400 and any(
        token in lowered
        for token in ("context length", "context_length_exceeded", "too many tokens", "maximum context")
    ):
        return ContextOverflowError(f"{name} context limit hit: {message}")
    if status == 404:
        return BadRequestError(
            f"{name} returned 404 for {base_url}/chat/completions: {message}. "
            "Check --base-url (it usually ends in /v1) and that the model name exists."
        )
    if status in (408, 409, 500, 502, 503, 504):
        return ServerError(f"{name} server error (HTTP {status}): {message}", retryable=True,
                           retry_after=retry_after)
    if status == 400:
        return BadRequestError(f"{name} rejected the request (HTTP 400): {message}")
    return LLMError(f"{name} error (HTTP {status}): {message}", retryable=status >= 500)
