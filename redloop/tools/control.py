"""Control-flow tools: declaring victory, or stopping the run."""

from __future__ import annotations

from typing import Any

from .base import Tool, ToolContext, ToolResult


class SubmitFlagTool(Tool):
    name = "submit_flag"
    summary = (
        "Declare the objective achieved and hand in the flag/captured value. "
        "Call this as soon as you have it, exactly as printed."
    )
    args = {
        "flag": "the flag exactly as captured, e.g. flag{...} or the secret value",
        "evidence": "optional: where it came from (URL, file, exploit)",
    }
    required = ("flag",)

    async def run(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        flag = str(args.get("flag", "")).strip().strip("\"'`")
        if not flag:
            return ToolResult(False, "missing flag")
        if len(flag) > 400:
            return ToolResult(False, "that does not look like a flag (too long); pass just the value")
        record = ctx.memory.add_flag(flag, source=str(args.get("evidence", "")), step=ctx.step)
        ctx.memory.save(ctx.run_dir)
        if record is None:
            return ToolResult(
                True, f"already submitted: {flag}", meta={"control": "flag", "flag": flag}
            )
        ctx.notify("flag", flag=record)
        return ToolResult(
            True,
            f"FLAG ACCEPTED: {flag}\nStopping the run and writing the report.",
            meta={"control": "flag", "flag": flag},
        )


class GiveUpTool(Tool):
    name = "give_up"
    summary = (
        "Stop the run when you are out of viable ideas, or when the remaining time is better "
        "spent reporting. Never use it just because a step failed."
    )
    args = {"reason": "why you are stopping, and what you would try with more time"}
    required = ("reason",)

    async def run(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        reason = str(args.get("reason", "")).strip() or "no reason given"
        return ToolResult(
            True,
            f"Run stopped by the agent: {reason}",
            meta={"control": "give_up", "reason": reason},
        )
