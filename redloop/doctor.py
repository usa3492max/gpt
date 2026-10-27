"""``redloop --doctor``: check the environment before wasting a run."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import httpx

from .config import Config, _inside_container
from .safety import ScopeGuard

OK = "✓"
BAD = "✗"
WARN = "!"
INFO = "·"


class Report:
    def __init__(self) -> None:
        self.failures = 0
        self.warnings = 0

    def ok(self, text: str) -> None:
        print(f"  {OK} {text}")

    def fail(self, text: str) -> None:
        self.failures += 1
        print(f"  {BAD} {text}")

    def warn(self, text: str) -> None:
        self.warnings += 1
        print(f"  {WARN} {text}")

    def info(self, text: str) -> None:
        print(f"  {INFO} {text}")

    def section(self, title: str) -> None:
        print(f"\n{title}")


TOOLCHAIN = [
    ("nmap", "port scanning"),
    ("curl", "HTTP requests"),
    ("nc", "raw sockets / shells"),
    ("python3", "python tool"),
    ("gobuster", "directory brute force"),
    ("ffuf", "web fuzzing"),
    ("sqlmap", "SQL injection"),
    ("hydra", "credential attacks"),
    ("openssl", "crypto"),
    ("strings", "binary triage"),
]


def doctor(config: Config, *, check_model: bool = False, as_json: bool = False) -> int:
    report = Report()
    print("redloop doctor")
    print("=" * 60)

    report.section("Runtime")
    report.ok(f"python {sys.version.split()[0]} on {sys.platform}")
    for module in ("httpx", "rich", "dotenv"):
        if importlib.util.find_spec(module):
            report.ok(f"python package: {module}")
        else:
            (report.warn if module == "dotenv" else report.fail)(f"python package missing: {module}")
    report.info(f"running inside a container: {_inside_container()}")
    report.info(f"working directory: {Path.cwd()}")

    report.section("Configuration")
    errors = config.validate()
    if errors:
        for error in errors:
            report.fail(error)
    else:
        report.ok("configuration is valid")
    preset = config.preset
    report.info(f"provider: {preset.key} ({preset.label})")
    report.info(f"model: {config.effective_model}")
    report.info(f"endpoint: {config.effective_base_url or '<none>'}")
    key = config.effective_api_key
    if key:
        report.ok(f"credential: {key[:6]}…{key[-4:]} ({len(key)} chars)")
    elif preset.env_key:
        report.warn(f"no credential set (expected {preset.env_key})")
    else:
        report.info("credential: not required for this provider")

    report.section("Endpoint reachability")
    _check_endpoint(config, report)

    report.section("Toolchain")
    missing = []
    for binary, purpose in TOOLCHAIN:
        path = shutil.which(binary)
        if path:
            report.ok(f"{binary:<10} {path}")
        else:
            missing.append(binary)
            report.warn(f"{binary:<10} not found ({purpose})")
    if missing:
        report.info(
            "Missing tools can still be replaced by the python/http tools, but the image is "
            "meant to have them. Rebuild with `make build`."
        )
    wordlists = [Path("/usr/share/wordlists"), Path("/usr/share/seclists")]
    found = [str(p) for p in wordlists if p.exists()]
    if found:
        report.ok(f"wordlists: {', '.join(found)}")
    else:
        report.warn("no wordlist directory found (/usr/share/wordlists)")

    report.section("Guardrails")
    guard = ScopeGuard(
        target=config.target,
        scope=config.scope,
        enabled=config.scope_check,
        allow_private=config.allow_private_networks,
        allow_loopback=config.allow_loopback,
    )
    if config.target:
        decision = guard.authorize(config.target)
        (report.ok if decision.allowed else report.fail)(
            f"target {config.target}: {'allowed' if decision.allowed else decision.reason}"
        )
    report.info(f"scope: {guard.describe()}")
    blocked = guard.check_command("curl http://example.com/")
    if not blocked.allowed:
        report.ok("out-of-scope public host correctly refused")
    elif config.scope_check:
        report.warn("out-of-scope public host was NOT refused — check the scope configuration")
    else:
        report.info("scope checking disabled (--no-scope-check)")

    if check_model:
        report.section("Model round-trip")
        _check_model(config, report)

    print()
    print("=" * 60)
    if report.failures:
        print(f"{BAD} {report.failures} problem(s), {report.warnings} warning(s)")
    elif report.warnings:
        print(f"{OK} ready with {report.warnings} warning(s)")
    else:
        print(f"{OK} everything looks ready")
    if as_json:
        print(json.dumps({"failures": report.failures, "warnings": report.warnings}))
    return 0 if report.failures == 0 else 1


def _check_endpoint(config: Config, report: Report) -> None:
    if config.preset.kind == "mock":
        report.info("offline demo model selected — no network call needed")
        return
    base = config.effective_base_url
    if not base:
        report.fail("no endpoint configured")
        return
    headers = {}
    if config.effective_api_key:
        if config.preset.kind == "anthropic":
            headers = {"x-api-key": config.effective_api_key, "anthropic-version": "2023-06-01"}
        else:
            headers = {"authorization": f"Bearer {config.effective_api_key}"}
    path = "/v1/models" if config.preset.kind == "anthropic" else "/models"
    try:
        with httpx.Client(timeout=8.0, headers=headers) as client:
            response = client.get(base + path)
    except httpx.HTTPError as exc:
        report.fail(f"cannot reach {base}: {type(exc).__name__}: {exc}")
        if config.provider == "ollama":
            report.info(
                "Is Ollama running on the host? Inside Docker use "
                "--base-url http://host.docker.internal:11434/v1 "
                "(and make sure `ollama serve` is listening on 0.0.0.0)."
            )
        return
    if response.status_code in (200, 401, 403, 404):
        report.ok(f"{base} reachable (HTTP {response.status_code})")
        if config.provider == "ollama" and response.status_code == 200:
            _list_models(response, config, report)
        if response.status_code in (401, 403):
            report.warn("the endpoint rejected the credential — check the API key")
    else:
        report.warn(f"{base} answered HTTP {response.status_code}")


def _list_models(response: httpx.Response, config: Config, report: Report) -> None:
    try:
        models = [item.get("id", "") for item in response.json().get("data", [])]
    except (ValueError, AttributeError):
        return
    if not models:
        report.warn("the local model server reports no downloaded models — try `ollama pull <model>`")
        return
    report.info("available models: " + ", ".join(models[:12]))
    if config.effective_model not in models:
        report.warn(
            f"model {config.effective_model!r} is not in the list. Pull it with "
            f"`ollama pull {config.effective_model}` or pick one of the above."
        )


def _check_model(config: Config, report: Report) -> None:
    from .llm import build_client
    from .llm.base import Message

    async def run() -> None:
        client = build_client(config)
        try:
            completion = await client.complete(
                "You are a connectivity test. Reply with the single word READY.",
                [Message("user", "Reply with READY.")],
                max_tokens=32,
                temperature=0.0,
            )
            text = completion.text.strip().replace("\n", " ")
            report.ok(f"{client.name}:{client.model} replied in {completion.usage.total} tokens: {text[:120]!r}")
        except Exception as exc:
            report.fail(f"model call failed: {type(exc).__name__}: {exc}")
        finally:
            await client.aclose()

    asyncio.run(run())


def env_hint() -> str:
    """Human-readable list of the environment variables the tool understands."""
    return "\n".join(
        f"  {name:<28} {desc}"
        for name, desc in [
            ("ANTHROPIC_API_KEY", "Claude API credential"),
            ("OPENAI_API_KEY", "OpenAI credential"),
            ("OPENROUTER_API_KEY", "OpenRouter credential"),
            ("GROQ_API_KEY", "Groq credential"),
            ("OLLAMA_HOST", "host:port of an Ollama server (auto-mapped to /v1 inside Docker)"),
            ("REDLOOP_PROVIDER", "default provider"),
            ("REDLOOP_MODEL", "default model"),
            ("REDLOOP_MAX_STEPS", "default step budget"),
            ("REDLOOP_AUTHORIZED", "set to 1 to accept the authorisation notice once"),
            ("REDLOOP_RUNS_DIR", "where run directories are written"),
        ]
    )

