"""Provider clients, error mapping and retry behaviour (no network required)."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from redloop.llm import (
    AnthropicClient,
    AuthError,
    ContextOverflowError,
    LLMError,
    Message,
    MockClient,
    OpenAIClient,
    RateLimitError,
    RetryingClient,
    ServerError,
)
from redloop.llm.openai import _parse_sse
from redloop.protocol import parse_action


def run(coro):
    return asyncio.run(coro)


def transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


MESSAGES = [Message("user", "hello")]


# --------------------------------------------------------------------------- #
# Anthropic
# --------------------------------------------------------------------------- #
def make_anthropic(handler, **kwargs):
    return AnthropicClient(
        api_key="sk-ant-test", model="claude-sonnet-4-5",
        transport=transport(handler), **kwargs
    )


def test_anthropic_request_shape_and_response_parsing():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "content": [{"type": "text", "text": "scanning now"}],
                "usage": {"input_tokens": 120, "output_tokens": 30,
                          "cache_read_input_tokens": 100, "cache_creation_input_tokens": 5},
                "stop_reason": "end_turn",
                "model": "claude-sonnet-4-5",
            },
        )

    completion = run(make_anthropic(handler).complete("SYSTEM", MESSAGES))
    assert completion.text == "scanning now"
    assert completion.usage.input_tokens == 120
    assert completion.usage.cache_read_tokens == 100
    assert captured["url"].endswith("/v1/messages")
    assert captured["headers"]["x-api-key"] == "sk-ant-test"
    assert captured["headers"]["anthropic-version"] == "2023-06-01"
    assert captured["body"]["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert captured["body"]["messages"] == [{"role": "user", "content": "hello"}]


def test_anthropic_tool_use_becomes_the_action_protocol():
    def handler(request):
        return httpx.Response(200, json={
            "content": [
                {"type": "text", "text": "I'll scan."},
                {"type": "tool_use", "name": "shell", "input": {"command": "nmap -sV x"}},
            ],
            "usage": {"input_tokens": 1, "output_tokens": 1},
        })

    completion = run(make_anthropic(handler).complete("S", MESSAGES))
    parsed = parse_action(completion.text)
    assert parsed.ok
    assert parsed.action.tool == "shell"
    assert parsed.action.args["command"] == "nmap -sV x"


@pytest.mark.parametrize(
    "status,body,expected",
    [
        (401, {"error": {"message": "invalid x-api-key"}}, AuthError),
        (429, {"error": {"message": "rate limited"}}, RateLimitError),
        (400, {"error": {"message": "prompt is too long: 250000 tokens"}}, ContextOverflowError),
        (500, {"error": {"message": "oops"}}, ServerError),
        (529, {"error": {"message": "overloaded"}}, ServerError),
    ],
)
def test_anthropic_errors_are_mapped(status, body, expected):
    client = make_anthropic(lambda request: httpx.Response(status, json=body))
    with pytest.raises(expected):
        run(client.complete("S", MESSAGES))


def test_anthropic_rate_limit_exposes_retry_after():
    client = make_anthropic(
        lambda request: httpx.Response(429, json={"error": {"message": "slow down"}},
                                       headers={"retry-after": "7"})
    )
    with pytest.raises(RateLimitError) as excinfo:
        run(client.complete("S", MESSAGES))
    assert excinfo.value.retry_after == 7.0
    assert excinfo.value.retryable


def test_anthropic_connection_error_is_retryable():
    def handler(request):
        raise httpx.ConnectError("no route to host", request=request)

    client = make_anthropic(handler)
    with pytest.raises(LLMError) as excinfo:
        run(client.complete("S", MESSAGES))
    assert excinfo.value.retryable
    assert "timed out" in str(excinfo.value) or "connection" in str(excinfo.value).lower()


# --------------------------------------------------------------------------- #
# OpenAI-compatible (Ollama, LM Studio, vLLM, ...)
# --------------------------------------------------------------------------- #
def make_openai(handler, base_url="http://localhost:11434/v1", api_key=""):
    return OpenAIClient(model="qwen2.5-coder:14b", base_url=base_url, api_key=api_key,
                        transport=transport(handler))


def test_openai_compatible_request_shape():
    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7},
            "model": "qwen2.5-coder:14b",
        })

    completion = run(make_openai(handler).complete("SYS", MESSAGES))
    assert completion.text == "ok"
    assert completion.usage.input_tokens == 11
    assert captured["url"] == "http://localhost:11434/v1/chat/completions"
    assert captured["body"]["messages"][0] == {"role": "system", "content": "SYS"}
    assert "authorization" not in captured["headers"]  # local model, no key


def test_openai_bearer_token_when_key_present():
    captured = {}

    def handler(request):
        captured["headers"] = dict(request.headers)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    run(make_openai(handler, base_url="https://api.openai.com/v1", api_key="sk-123")
        .complete("S", MESSAGES))
    assert captured["headers"]["authorization"] == "Bearer sk-123"


def test_openai_tool_calls_are_converted():
    def handler(request):
        return httpx.Response(200, json={"choices": [{"message": {
            "content": None,
            "tool_calls": [{"function": {"name": "shell", "arguments": '{"command": "id"}'}}],
        }}]})

    completion = run(make_openai(handler).complete("S", MESSAGES))
    parsed = parse_action(completion.text)
    assert parsed.ok
    assert parsed.action.args["command"] == "id"


def test_reasoning_models_use_max_completion_tokens():
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    client = OpenAIClient(model="o4-mini", base_url="https://api.openai.com/v1",
                          api_key="k", transport=transport(handler))
    run(client.complete("S", MESSAGES, max_tokens=1000, temperature=0.5))
    assert captured["body"]["max_completion_tokens"] == 1000
    assert "temperature" not in captured["body"]


def test_openai_404_explains_the_base_url():
    client = make_openai(lambda request: httpx.Response(
        404, json={"error": {"message": "model 'x' not found"}}))
    with pytest.raises(LLMError) as excinfo:
        run(client.complete("S", MESSAGES))
    assert "base-url" in str(excinfo.value).lower()
    assert not excinfo.value.retryable


def test_openai_context_overflow_detected():
    client = make_openai(lambda request: httpx.Response(400, json={
        "error": {"message": "This model's maximum context length is 8192 tokens"}}))
    with pytest.raises(ContextOverflowError):
        run(client.complete("S", MESSAGES))


def test_openai_401_maps_to_auth_error():
    client = make_openai(lambda request: httpx.Response(
        401, json={"error": {"message": "invalid api key"}}), api_key="bad")
    with pytest.raises(AuthError):
        run(client.complete("S", MESSAGES))


def test_sse_response_is_folded_into_one_completion():
    def handler(request):
        body = (
            'data: {"model":"m","choices":[{"delta":{"content":"Hel"}}]}\n\n'
            'data: {"model":"m","choices":[{"delta":{"content":"lo"},"finish_reason":"stop"}]}\n\n'
            "data: [DONE]\n\n"
        )
        return httpx.Response(200, text=body, headers={"content-type": "text/event-stream"})

    completion = run(make_openai(handler).complete("S", MESSAGES))
    assert completion.text == "Hello"


def test_parse_sse_helper_ignores_garbage():
    assert _parse_sse("data: not-json\n\ndata: [DONE]\n")["choices"][0]["message"]["content"] == ""


# --------------------------------------------------------------------------- #
# retry wrapper
# --------------------------------------------------------------------------- #
class FlakyClient:
    name = "flaky"
    model = "flaky-1"

    def __init__(self, failures: int, error: Exception | None = None) -> None:
        self.failures = failures
        self.error = error or ServerError("boom", retryable=True)
        self.calls = 0

    async def complete(self, system, messages, *, max_tokens=0, temperature=0):
        self.calls += 1
        if self.calls <= self.failures:
            raise self.error
        from redloop.llm.base import Completion

        return Completion(text="recovered")

    async def aclose(self):
        return None


def test_retry_wrapper_recovers_from_transient_errors():
    inner = FlakyClient(failures=2)
    retries = []
    client = RetryingClient(inner, base_delay=0, max_delay=0,
                            on_retry=lambda attempt, delay, err: retries.append(attempt))
    completion = run(client.complete("S", MESSAGES))
    assert completion.text == "recovered"
    assert inner.calls == 3
    assert retries == [1, 2]


def test_retry_wrapper_gives_up_eventually():
    inner = FlakyClient(failures=10)
    client = RetryingClient(inner, max_attempts=3, base_delay=0, max_delay=0)
    with pytest.raises(ServerError):
        run(client.complete("S", MESSAGES))
    assert inner.calls == 3


def test_retry_wrapper_does_not_retry_auth_errors():
    inner = FlakyClient(failures=5, error=AuthError("bad key"))
    client = RetryingClient(inner, base_delay=0, max_delay=0)
    with pytest.raises(AuthError):
        run(client.complete("S", MESSAGES))
    assert inner.calls == 1


# --------------------------------------------------------------------------- #
# offline mock model
# --------------------------------------------------------------------------- #
def test_mock_client_emits_a_parseable_action():
    client = MockClient(target="10.0.0.5")
    completion = run(client.complete("S", [Message("user", "=== ENGAGEMENT BRIEF === target 10.0.0.5")]))
    parsed = parse_action(completion.text)
    assert parsed.ok
    assert parsed.action.tool == "shell"
    assert "10.0.0.5" in parsed.action.args["command"]
    assert parsed.thought


def test_mock_client_submits_a_flag_when_it_sees_one():
    client = MockClient(target="10.0.0.5")
    messages = [
        Message("user", "brief"),
        Message("assistant", "```json\n{\"tool\": \"http\", \"args\": {\"url\": \"http://x/\"}}\n```"),
        Message("user", "=== OBSERVATION (step 2, http, ok) ===\n<p>flag{mock_win}</p>\n"
                        "=== END OBSERVATION ==="),
    ]
    completion = run(client.complete("S", messages))
    parsed = parse_action(completion.text)
    assert parsed.action.tool == "submit_flag"
    assert parsed.action.args["flag"] == "flag{mock_win}"


def test_mock_client_ignores_the_format_hint_in_the_brief():
    client = MockClient(target="10.0.0.5")
    messages = [Message("user", "brief: flags look like flag{...} and CTF{example}")]
    parsed = parse_action(run(client.complete("S", messages)).text)
    assert parsed.action.tool != "submit_flag"
