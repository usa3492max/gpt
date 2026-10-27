"""The ``shell`` tool: the agent's primary interface to the tooling in the image."""

from __future__ import annotations

import re
import time
from typing import Any

from .base import Tool, ToolContext, ToolResult, strip_ansi, truncate
from .exec import run_process

PROMPT_PREFIX_RE = re.compile(r"^\s*(?:\$|#|>|PS [^>]*>)\s+")


class ShellTool(Tool):
    name = "shell"
    summary = (
        "Run a shell command in the container. This is how you use nmap, curl, gobuster, "
        "sqlmap, hydra, nc, openssl, python scripts and everything else installed."
    )
    args = {
        "command": "the full command line to execute",
        "timeout": "optional seconds before the command is killed (default from config)",
    }
    required = ("command",)
    long_running = True

    async def run(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        started = time.monotonic()
        command = str(args.get("command", "")).strip()
        command = PROMPT_PREFIX_RE.sub("", command)
        if not command:
            return ToolResult(False, "empty command")

        decision = ctx.guard.check_command(command, tool="shell")
        if not decision.allowed:
            return ToolResult(
                False,
                f"BLOCKED: {decision.reason}",
                blocked=True,
                meta={"guardrail": decision.reason},
            )
        if ctx.dry_run:
            return ToolResult(
                True,
                f"[dry-run] would execute: {command}",
                meta={"command": command, "dry_run": True},
            )
        if (
            decision.risky
            and ctx.config.autonomous is False
            and ctx.confirm
            and not ctx.confirm(command, decision.risky)
        ):
            return ToolResult(
                False,
                f"The operator declined to run this command ({decision.risky}). "
                "Choose a different approach.",
                blocked=True,
            )

        timeout = _timeout(args.get("timeout"), ctx.config.command_timeout)
        result = await run_process(command, cwd=ctx.work_dir, timeout=timeout)
        output = _clean(result.output)
        payload, truncated = truncate(output, ctx.config.max_output_chars)
        log_path = _persist(ctx, command, output, truncated)

        header = _header(command, result.exit_code, result.duration, len(output), truncated, log_path)
        text = header + (payload if payload.strip() else "[no output]")
        meta = {
            "command": command,
            "exit_code": result.exit_code,
            "duration": round(result.duration, 2),
            "timed_out": result.timed_out,
            "truncated": truncated,
            "log_path": str(log_path) if log_path else "",
        }
        if result.timed_out:
            text += (
                "\nThe command hit the timeout. If it was scanning, narrow the range, raise "
                "the timeout, or run it in the background with a log file."
            )
        return ToolResult(
            ok=result.exit_code == 0,
            output=text,
            meta=meta,
            truncated=truncated,
            duration=time.monotonic() - started,
            exit_code=result.exit_code,
        )


def _timeout(raw: Any, default: int) -> float:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return float(default)
    if value <= 0:
        return float(default)
    return min(value, float(default) * 4, 3600.0)


def _clean(text: str) -> str:
    text = strip_ansi(text)
    # Collapse the huge blank runs some tools emit.
    text = re.sub(r"\n{4,}", "\n\n\n", text)
    return text.strip("\n")


def _header(
    command: str,
    exit_code: int | None,
    duration: float,
    size: int,
    truncated: bool,
    log_path,
) -> str:
    bits = [f"$ {command}", f"exit={exit_code} time={duration:.1f}s size={size}B"]
    if truncated and log_path:
        bits.append(f"full output: {log_path}")
    return " · ".join(bits) + "\n" + "─" * min(72, max(20, len(command))) + "\n"


def _persist(ctx: ToolContext, command: str, output: str, truncated: bool):
    """Keep the untruncated output so nothing the model saw is ever lost."""
    if not truncated and len(output) < 20_000:
        return None
    try:
        path = ctx.loot_dir / f"step{ctx.step:03d}_output.log"
        suffix = 1
        while path.exists():
            path = ctx.loot_dir / f"step{ctx.step:03d}_output_{suffix}.log"
            suffix += 1
        path.write_text(f"$ {command}\n\n{output}", encoding="utf-8", errors="replace")
        return path
    except OSError:  # pragma: no cover
        return None


__all__ = ["ShellTool"]
