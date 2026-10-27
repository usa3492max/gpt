"""The ``python`` tool: multi-step logic without fighting shell quoting."""

from __future__ import annotations

import sys
import time
from typing import Any

from .base import Tool, ToolContext, ToolResult, strip_ansi, truncate
from .exec import run_process
from .shell import _timeout


class PythonTool(Tool):
    name = "python"
    summary = (
        "Run a Python 3 snippet in the container. Use it for scripting, parsing, "
        "cryptography, exploiting a socket service, or anything that is painful in one shell line. "
        "print() whatever you want to see."
    )
    args = {
        "code": "Python source code to execute",
        "timeout": "optional seconds before execution is killed",
    }
    required = ("code",)
    long_running = True

    async def run(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        started = time.monotonic()
        code = str(args.get("code", ""))
        if not code.strip():
            return ToolResult(False, "empty code")
        code = _strip_fences(code)

        # Arbitrary code could bypass the shell guard, so scan it for destinations.
        decision = ctx.guard.check_code(code)
        if not decision.allowed:
            return ToolResult(False, f"BLOCKED: {decision.reason}", blocked=True)

        if ctx.dry_run:
            return ToolResult(True, "[dry-run] would execute the snippet", meta={"dry_run": True})

        script = (ctx.work_dir / f"step{ctx.step:03d}_snippet.py").resolve()
        try:
            script.write_text(code, encoding="utf-8")
        except OSError as exc:
            return ToolResult(False, f"could not write snippet: {exc}")

        timeout = _timeout(args.get("timeout"), ctx.config.command_timeout)
        result = await run_process(
            [sys.executable, "-u", str(script)],
            cwd=ctx.work_dir,
            timeout=timeout,
            use_shell=False,
        )
        output = strip_ansi(result.output).strip("\n")
        payload, truncated = truncate(output, ctx.config.max_output_chars)
        header = f"python · exit={result.exit_code} time={result.duration:.1f}s\n" + "─" * 40 + "\n"
        text = header + (payload if payload.strip() else "[no output — use print() to see values]")
        if result.timed_out:
            text += (
                "\nExecution hit the timeout and was killed. Avoid blocking reads without a "
                "socket timeout (set .settimeout(...) or use a thread)."
            )
        if truncated:
            log = ctx.loot_dir / f"step{ctx.step:03d}_python.log"
            try:
                log.write_text(output, encoding="utf-8", errors="replace")
                text += f"\n[full output saved to {log}]"
            except OSError:
                pass
        return ToolResult(
            ok=result.exit_code == 0,
            output=text,
            meta={
                "exit_code": result.exit_code,
                "duration": round(result.duration, 2),
                "timed_out": result.timed_out,
                "script": str(script),
            },
            truncated=truncated,
            duration=time.monotonic() - started,
            exit_code=result.exit_code,
        )


def _strip_fences(code: str) -> str:
    code = code.strip()
    if code.startswith("```"):
        lines = code.splitlines()
        if len(lines) >= 2 and lines[-1].strip().startswith("```"):
            lines = lines[1:-1]
        elif len(lines) >= 1:
            lines = lines[1:]
        code = "\n".join(lines)
    return code
