"""Shared tool plumbing: result objects, the tool base class and the context."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from ..config import Config
    from ..memory import Memory
    from ..safety import ScopeGuard

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07|\r")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text or "")


def truncate(text: str, limit: int) -> tuple[str, bool]:
    """Keep the head and tail of a long output — the middle is rarely useful."""
    if len(text) <= limit:
        return text, False
    head_len = int(limit * 0.65)
    tail_len = max(200, limit - head_len - 120)
    omitted = len(text) - head_len - tail_len
    head = text[:head_len]
    tail = text[-tail_len:]
    marker = (
        f"\n[... {omitted} characters elided by redloop; "
        f"full output saved to the run directory ...]\n"
    )
    return head + marker + tail, True


def quote(value: str) -> str:
    try:
        return shlex.quote(value)
    except (ValueError, TypeError):
        return str(value)


@dataclass
class ToolResult:
    ok: bool
    output: str
    meta: dict[str, Any] = field(default_factory=dict)
    blocked: bool = False
    truncated: bool = False
    duration: float = 0.0
    exit_code: int | None = None

    def summary(self) -> str:
        if self.blocked:
            return "blocked by guardrail"
        if self.exit_code is not None and not self.ok:
            return f"exit {self.exit_code}"
        return "ok" if self.ok else "failed"


class Tool:
    """Base class for everything the model can call."""

    name: str = ""
    summary: str = ""
    #: argument name -> short description (used to build the prompt + help)
    args: dict[str, str] = {}
    #: argument names that must be present
    required: tuple[str, ...] = ()
    #: execution may take minutes, so the UI shows a spinner
    long_running: bool = False
    #: safe to execute during --dry-run
    side_effect_free: bool = False

    def signature(self) -> str:
        parts = []
        for arg in self.args:
            parts.append(f"{arg}*" if arg in self.required else arg)
        joined = ", ".join(parts)
        return f"{self.name}({joined})"

    def help_text(self) -> str:
        lines = [f"- {self.signature()}: {self.summary}"]
        for arg, description in self.args.items():
            lines.append(f"    {arg}: {description}")
        return "\n".join(lines)

    def coerce(self, args: dict[str, Any]) -> dict[str, Any]:
        """Normalise argument names/types; raises ValueError on bad input."""
        if not isinstance(args, dict):
            raise ValueError("args must be a JSON object")
        cleaned: dict[str, Any] = {}
        for key, value in args.items():
            norm = re.sub(r"[\s\-]+", "_", str(key).lower().strip())
            if norm in cleaned:
                continue
            cleaned[norm] = value
        missing = [arg for arg in self.required if arg not in cleaned or cleaned[arg] in (None, "")]
        if missing:
            raise ValueError(
                f"missing required argument(s) for {self.name}: {', '.join(missing)}. "
                f"Expected {self.signature()}"
            )
        return cleaned

    async def execute(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        """Validate, normalise and run. Always use this rather than ``run``."""
        try:
            coerced = self.coerce(args)
        except ValueError as exc:
            return ToolResult(False, f"invalid tool call: {exc}")
        return await self.run(coerced, ctx)

    async def run(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:  # pragma: no cover
        raise NotImplementedError


@dataclass
class ToolContext:
    config: Config
    guard: ScopeGuard
    memory: Memory
    run_dir: Path
    step: int = 0
    emit: Any = None  # Callable[[str, dict], None]
    confirm: Any = None  # Callable[[str, str], bool]

    @property
    def dry_run(self) -> bool:
        return bool(self.config.dry_run)

    def __post_init__(self) -> None:
        self.run_dir = Path(self.run_dir).expanduser().resolve()

    @property
    def work_dir(self) -> Path:
        path = self.run_dir / "work"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def loot_dir(self) -> Path:
        path = self.run_dir / "loot"
        path.mkdir(parents=True, exist_ok=True)
        return path

    def notify(self, type_: str, **data: Any) -> None:
        if self.emit:
            self.emit(type_, **data)
