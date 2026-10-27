"""Configuration: CLI flags, environment variables and provider presets."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ProviderPreset:
    """A named place to send prompts.

    ``kind`` selects the wire protocol: ``anthropic`` (``/v1/messages``),
    ``openai`` (``/v1/chat/completions``, which also covers Ollama, LM Studio,
    vLLM, OpenRouter, Groq, ...) or ``mock`` for the offline demo double.
    """

    key: str
    kind: str
    base_url: str
    default_model: str
    env_key: str | None
    label: str


PRESETS: dict[str, ProviderPreset] = {
    "anthropic": ProviderPreset(
        key="anthropic",
        kind="anthropic",
        base_url="https://api.anthropic.com",
        default_model="claude-sonnet-4-5",
        env_key="ANTHROPIC_API_KEY",
        label="Anthropic Claude API",
    ),
    "openai": ProviderPreset(
        key="openai",
        kind="openai",
        base_url="https://api.openai.com/v1",
        default_model="gpt-4.1",
        env_key="OPENAI_API_KEY",
        label="OpenAI API",
    ),
    "ollama": ProviderPreset(
        key="ollama",
        kind="openai",
        base_url="http://localhost:11434/v1",
        default_model="qwen2.5-coder:14b",
        env_key=None,
        label="Ollama (local models)",
    ),
    "lmstudio": ProviderPreset(
        key="lmstudio",
        kind="openai",
        base_url="http://localhost:1234/v1",
        default_model="local-model",
        env_key=None,
        label="LM Studio (local models)",
    ),
    "openrouter": ProviderPreset(
        key="openrouter",
        kind="openai",
        base_url="https://openrouter.ai/api/v1",
        default_model="anthropic/claude-sonnet-4.5",
        env_key="OPENROUTER_API_KEY",
        label="OpenRouter",
    ),
    "groq": ProviderPreset(
        key="groq",
        kind="openai",
        base_url="https://api.groq.com/openai/v1",
        default_model="llama-3.3-70b-versatile",
        env_key="GROQ_API_KEY",
        label="Groq",
    ),
    "mock": ProviderPreset(
        key="mock",
        kind="mock",
        base_url="",
        default_model="mock-rulebased",
        env_key=None,
        label="Offline demo model (rule-based, no API needed)",
    ),
}

#: Rough USD per million tokens (input, output) for cost *estimates* only.
#: Local models cost nothing, so they are absent on purpose.
PRICING: dict[str, tuple[float, float]] = {
    "claude-sonnet-4-5": (3.0, 15.0),
    "claude-sonnet-4": (3.0, 15.0),
    "claude-opus-4-1": (15.0, 75.0),
    "claude-opus-4": (15.0, 75.0),
    "claude-haiku-4-5": (1.0, 5.0),
    "claude-3-7-sonnet": (3.0, 15.0),
    "claude-3-5-sonnet": (3.0, 15.0),
    "claude-3-5-haiku": (0.8, 4.0),
    "gpt-4.1": (2.0, 8.0),
    "gpt-4o": (2.5, 10.0),
    "gpt-4o-mini": (0.15, 0.6),
    "o4-mini": (1.1, 4.4),
}

DEFAULT_FLAG_PATTERNS = [
    r"(?i)\bflag\{[^}\n]{1,200}\}",
    r"(?i)\bctf\{[^}\n]{1,200}\}",
    r"\bHTB\{[^}\n]{1,200}\}",
    r"\bpicoCTF\{[^}\n]{1,200}\}",
    r"\bTHM\{[^}\n]{1,200}\}",
    r"\bDUCTF\{[^}\n]{1,200}\}",
]

#: Hosts the agent may always talk to for its own tooling (package mirrors,
#: model APIs).  These are *not* attack targets; they are infrastructure.
INFRASTRUCTURE_HOSTS = (
    "localhost",
    "127.0.0.1",
    "::1",
    "host.docker.internal",
    "gateway.docker.internal",
    "pypi.org",
    "files.pythonhosted.org",
    "github.com",
    "codeload.github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "api.anthropic.com",
    "api.openai.com",
    "openrouter.ai",
    "api.groq.com",
    "deb.debian.org",
    "security.debian.org",
    "http.kali.org",
    "kali.download",
    "archive.ubuntu.com",
    "registry.npmjs.org",
)


@dataclass
class Config:
    # --- target / engagement -------------------------------------------------
    target: str = ""
    scope: list[str] = field(default_factory=list)
    objective: str = ""
    seed_notes: str = ""

    # --- model ---------------------------------------------------------------
    provider: str = "anthropic"
    model: str = ""
    api_key: str = ""
    base_url: str = ""
    temperature: float = 0.7
    max_tokens: int = 2048
    context_window: int = 200_000
    request_timeout: float = 240.0
    max_retries: int = 5
    prompt_cache: bool = True

    # --- run limits ----------------------------------------------------------
    max_steps: int = 40
    max_minutes: float = 90.0
    max_cost_usd: float = 0.0  # 0 disables the budget
    command_timeout: int = 300
    max_output_chars: int = 6000

    # --- guardrails ----------------------------------------------------------
    scope_check: bool = True
    allow_private_networks: bool = True
    allow_loopback: bool = True
    autonomous: bool = True
    authorized: bool = False
    stop_on_flag: bool = True
    extra_flag_patterns: list[str] = field(default_factory=list)

    # --- presentation / storage ---------------------------------------------
    plain: bool = False
    json_feed: bool = False
    verbose: bool = False
    quiet: bool = False
    no_color: bool = False
    dry_run: bool = False
    runs_dir: Path = field(default_factory=lambda: Path("runs"))

    # ------------------------------------------------------------------ utils
    @property
    def preset(self) -> ProviderPreset:
        # An unknown provider name is treated as the OpenAI-compatible protocol
        # with an explicit --base-url; validation reports the problem.
        return PRESETS.get(self.provider) or ProviderPreset(
            key=self.provider,
            kind="openai",
            base_url=self.base_url,
            default_model=self.model,
            env_key=None,
            label=f"custom ({self.provider})",
        )

    @property
    def effective_model(self) -> str:
        return self.model or self.preset.default_model

    @property
    def effective_base_url(self) -> str:
        return (self.base_url or self.preset.base_url).rstrip("/")

    @property
    def effective_api_key(self) -> str:
        if self.api_key:
            return self.api_key
        env_key = self.preset.env_key
        if env_key:
            return os.environ.get(env_key, "")
        return ""

    @property
    def token_budget(self) -> int:
        """How much history we allow before compacting."""
        return max(2000, int(self.context_window * 0.55))

    def flag_patterns(self) -> list[str]:
        return [*DEFAULT_FLAG_PATTERNS, *self.extra_flag_patterns]

    def price_per_mtok(self) -> tuple[float, float]:
        model = self.effective_model.lower()
        for key, price in PRICING.items():
            if model.startswith(key):
                return price
        return (0.0, 0.0)

    def cost_of(self, input_tokens: int, output_tokens: int) -> float:
        inp, out = self.price_per_mtok()
        return (input_tokens / 1_000_000) * inp + (output_tokens / 1_000_000) * out

    # -------------------------------------------------------------- validation
    def validate(self) -> list[str]:
        errors: list[str] = []
        if not self.target:
            errors.append("no target given (use --target <ip|host|cidr|url>)")
        if self.provider not in PRESETS and not self.base_url:
            errors.append(
                f"unknown provider {self.provider!r}. Use one of {', '.join(PRESETS)} "
                "or pass --base-url for an OpenAI-compatible endpoint."
            )
        if self.preset.kind == "anthropic" and not self.effective_api_key:
            errors.append(
                "ANTHROPIC_API_KEY is not set. Export it, put it in .env, or pass --api-key. "
                "To run without an API key use --provider mock."
            )
        if self.preset.kind == "openai" and self.preset.env_key and not self.effective_api_key:
            errors.append(
                f"{self.preset.env_key} is not set for provider {self.provider!r}. "
                "Set it, pass --api-key, or use --provider ollama for local models."
            )
        if self.provider == "ollama" and not self.base_url and _inside_container():
            errors.append(
                "Inside Docker, Ollama on the host is not localhost. Pass "
                "--base-url http://host.docker.internal:11434/v1 or set OLLAMA_HOST."
            )
        if self.max_steps < 1:
            errors.append("--max-steps must be >= 1")
        if self.max_minutes <= 0:
            errors.append("--max-minutes must be > 0")
        if self.temperature < 0 or self.temperature > 2:
            errors.append("--temperature must be between 0 and 2")
        for pattern in self.extra_flag_patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                errors.append(f"invalid --flag-regex {pattern!r}: {exc}")
        return errors

    # ----------------------------------------------------------------- display
    def redacted(self) -> dict[str, Any]:
        key = self.effective_api_key
        return {
            "target": self.target,
            "scope": self.scope or ["<derived from target>"],
            "objective": self.objective or "<autonomous assessment>",
            "provider": self.provider,
            "model": self.effective_model,
            "base_url": self.effective_base_url or "<none>",
            "api_key": (key[:6] + "..." + key[-4:]) if len(key) > 12 else ("<set>" if key else "<none>"),
            "max_steps": self.max_steps,
            "max_minutes": self.max_minutes,
            "max_cost_usd": self.max_cost_usd or "unlimited",
            "command_timeout": self.command_timeout,
            "scope_check": self.scope_check,
            "allow_private_networks": self.allow_private_networks,
            "stop_on_flag": self.stop_on_flag,
            "runs_dir": str(self.runs_dir),
        }

    def with_env(self) -> Config:
        """Overlay values from ``REDLOOP_*`` environment variables."""
        env = os.environ
        mapping: dict[str, tuple[str, Any]] = {
            "REDLOOP_TARGET": ("target", str),
            "REDLOOP_PROVIDER": ("provider", str),
            "REDLOOP_MODEL": ("model", str),
            "REDLOOP_BASE_URL": ("base_url", str),
            "REDLOOP_API_KEY": ("api_key", str),
            "REDLOOP_MAX_STEPS": ("max_steps", int),
            "REDLOOP_MAX_MINUTES": ("max_minutes", float),
            "REDLOOP_MAX_COST_USD": ("max_cost_usd", float),
            "REDLOOP_COMMAND_TIMEOUT": ("command_timeout", int),
            "REDLOOP_REQUEST_TIMEOUT": ("request_timeout", float),
            "REDLOOP_MAX_OUTPUT_CHARS": ("max_output_chars", int),
            "REDLOOP_CONTEXT_WINDOW": ("context_window", int),
            "REDLOOP_TEMPERATURE": ("temperature", float),
            "REDLOOP_JSON_FEED": ("json_feed", lambda v: v.lower() in {"1", "true", "yes"}),
            "REDLOOP_OBJECTIVE": ("objective", str),
            "REDLOOP_SCOPE": ("scope", _split_list),
            "REDLOOP_FLAG_REGEX": ("extra_flag_patterns", _split_list),
            "REDLOOP_RUNS_DIR": ("runs_dir", Path),
            "OLLAMA_HOST": ("base_url", _ollama_url),
        }
        for env_name, (attr, cast) in mapping.items():
            raw = env.get(env_name)
            if raw is None or raw == "":
                continue
            # A preset lookup beats the generic base_url for Ollama.
            if env_name == "OLLAMA_HOST" and self.provider != "ollama":
                continue
            try:
                value = cast(raw)
            except (TypeError, ValueError):
                continue
            if attr == "base_url" and self.base_url:
                continue
            setattr(self, attr, value)
        if env.get("REDLOOP_AUTHORIZED", "").lower() in {"1", "true", "yes"}:
            self.authorized = True
        return self

    def finalize(self) -> Config:
        """Normalise derived fields before a run starts."""
        if self.target:
            self.target = self.target.strip()
        # Convenience: allow passing a URL as the target.
        m = re.match(r"^(?:https?|ftp)://([^/:]+)(?::(\d+))?", self.target)
        if m:
            self.target = m.group(1)
        self.scope = [s.strip() for s in self.scope if s.strip()]
        if isinstance(self.runs_dir, str):
            self.runs_dir = Path(self.runs_dir)
        if not self.base_url and self.provider == "ollama" and _inside_container():
            self.base_url = "http://host.docker.internal:11434/v1"
        return self


def _split_list(raw: str) -> list[str]:
    return [part.strip() for part in re.split(r"[,\s]+", raw) if part.strip()]


def _ollama_url(raw: str) -> str:
    raw = raw.strip().rstrip("/")
    if raw.startswith("http://") or raw.startswith("https://"):
        return raw if raw.endswith("/v1") else raw + "/v1"
    return f"http://{raw}:11434/v1"


def _inside_container() -> bool:
    return Path("/.dockerenv").exists() or os.environ.get("REDLOOP_IN_DOCKER") == "1"


def load_env_file(path: str | Path = ".env") -> None:
    """Load a ``.env`` file without overwriting real environment variables."""
    try:
        from dotenv import load_dotenv
    except ImportError:  # pragma: no cover
        return
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    if candidate.exists():
        load_dotenv(candidate, override=False)
