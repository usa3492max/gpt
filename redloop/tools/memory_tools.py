"""Tools for writing to the agent's durable scratchpad."""

from __future__ import annotations

from typing import Any

from .base import Tool, ToolContext, ToolResult


class NoteTool(Tool):
    name = "note_add"
    summary = (
        "Save a durable note (a discovered credential, an idea for later, a dead end to avoid). "
        "Notes survive context compaction and appear in the report, so use this instead of "
        "relying on memory."
    )
    args = {
        "text": "the note itself; be specific (host, port, path, credential, next idea)",
        "title": "optional short label",
    }
    required = ("text",)

    async def run(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        text = str(args.get("text", "")).strip()
        if not text:
            return ToolResult(False, "empty note")
        note = ctx.memory.add_note(text, title=str(args.get("title", "")).strip(), step=ctx.step)
        ctx.memory.save(ctx.run_dir)
        return ToolResult(True, f"noted (step {note.step}): {text[:200]}", meta={"note": text})


class FindingTool(Tool):
    name = "record_finding"
    summary = (
        "Record a confirmed vulnerability for the final report. Call this once you have "
        "evidence, not for guesses."
    )
    args = {
        "title": "short name, e.g. 'SQL injection in /login.php username parameter'",
        "severity": "critical | high | medium | low | info",
        "details": "how it works and where; include the affected host/port/path",
        "evidence": "the request/response or command output that proves it",
        "remediation": "optional fix advice",
    }
    required = ("title",)

    async def run(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        title = str(args.get("title", "")).strip()
        if not title:
            return ToolResult(False, "a finding needs a title")
        finding = ctx.memory.add_finding(
            title=title,
            severity=str(args.get("severity", "info")),
            details=str(args.get("details", "")),
            evidence=str(args.get("evidence", "")),
            remediation=str(args.get("remediation", "")),
            step=ctx.step,
        )
        ctx.memory.save(ctx.run_dir)
        ctx.notify("finding", finding=finding)
        return ToolResult(
            True,
            f"recorded [{finding.severity}] {finding.title}",
            meta={"severity": finding.severity, "title": finding.title},
        )
