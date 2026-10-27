"""End-of-run reporting.

Every run leaves a self-contained directory behind: ``report.md`` (for humans),
``results.json`` (for tooling), ``memory.json`` / ``notes.md`` (the scratchpad),
``feed.txt`` (the live feed, as it was displayed) and ``loot/`` (raw output).
"""

from __future__ import annotations

import json
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .config import Config
from .llm.base import Usage
from .memory import Memory

STATUS_TEXT = {
    "flag": "Objective achieved — flag captured",
    "completed": "Run finished by the agent",
    "exhausted": "Step budget exhausted without a flag",
    "timeout": "Stopped at the time limit",
    "budget": "Stopped at the cost limit",
    "interrupted": "Interrupted by the operator",
    "error": "Run ended on an error",
}


def write_report(
    *,
    run_dir: Path,
    config: Config,
    memory: Memory,
    status: str,
    reason: str,
    steps: int,
    usage: Usage,
    cost_usd: float,
    duration: float,
    guard=None,
) -> Path:
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    (run_dir / "report.md").write_text(
        _markdown(
            config=config,
            memory=memory,
            status=status,
            reason=reason,
            steps=steps,
            usage=usage,
            cost_usd=cost_usd,
            duration=duration,
            generated=generated,
            guard=guard,
        ),
        encoding="utf-8",
    )
    (run_dir / "results.json").write_text(
        json.dumps(
            {
                "tool": "redloop",
                "version": __version__,
                "generated": generated,
                "run": {
                    "target": config.target,
                    "objective": config.objective,
                    "provider": config.provider,
                    "model": config.effective_model,
                    "status": status,
                    "reason": reason,
                    "steps": steps,
                    "duration_seconds": round(duration, 1),
                    "usage": usage.to_dict(),
                    "cost_usd": round(cost_usd, 6),
                },
                "config": config.redacted(),
                "flags": [{"value": f.value, "source": f.source, "step": f.step} for f in memory.flags],
                "findings": [
                    {
                        "id": index + 1,
                        "title": f.title,
                        "severity": f.severity,
                        "details": f.details,
                        "evidence": f.evidence,
                        "remediation": f.remediation,
                        "step": f.step,
                    }
                    for index, f in enumerate(memory.findings)
                ],
                "facts": memory.facts.to_dict(),
                "notes": [{"title": n.title, "text": n.text, "step": n.step} for n in memory.notes],
                "attempts": memory.attempts,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return run_dir / "report.md"


def _markdown(
    *,
    config: Config,
    memory: Memory,
    status: str,
    reason: str,
    steps: int,
    usage: Usage,
    cost_usd: float,
    duration: float,
    generated: str,
    guard,
) -> str:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in memory.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    severity_line = ", ".join(f"{v} {k}" for k, v in counts.items() if v) or "none"

    lines: list[str] = []
    lines.append(f"# redloop assessment — {config.target}")
    lines.append("")
    lines.append(f"*Generated {generated} by redloop {__version__}*")
    lines.append("")
    lines.append("| | |")
    lines.append("|---|---|")
    lines.append(f"| Target | `{config.target}` |")
    lines.append(f"| Objective | {config.objective or 'Autonomous assessment / CTF flag capture'} |")
    lines.append(f"| Status | **{STATUS_TEXT.get(status, status)}** |")
    if reason:
        lines.append(f"| Reason | {reason} |")
    lines.append(f"| Steps | {steps} of {config.max_steps} |")
    lines.append(f"| Duration | {_duration(duration)} |")
    lines.append(f"| Model | {config.provider} · `{config.effective_model}` |")
    lines.append(f"| Tokens | {usage.input_tokens:,} in / {usage.output_tokens:,} out |")
    lines.append(f"| Cost | {f'${cost_usd:.4f}' if cost_usd else 'n/a'} |")
    lines.append(f"| Scope | {guard.describe() if guard else ', '.join(config.scope) or config.target} |")
    lines.append("")

    # -------------------------------------------------------------- summary
    lines.append("## Executive summary")
    lines.append("")
    if memory.flags:
        lines.append(
            f"The agent captured **{len(memory.flags)} flag(s)** against `{config.target}` after "
            f"{steps} action(s): " + ", ".join(f"`{f.value}`" for f in memory.flags) + "."
        )
    else:
        lines.append(
            f"The agent did not capture a flag against `{config.target}` within its budget. "
            "The observations below still describe the attack surface it mapped and any issues "
            "it confirmed."
        )
    if memory.findings:
        lines.append("")
        lines.append(
            f"It recorded **{len(memory.findings)} finding(s)** ({severity_line})."
        )
    if memory.facts.ports:
        ports = ", ".join(sorted(memory.facts.ports))
        lines.append("")
        lines.append(f"Open services observed: {ports}.")
    lines.append("")

    # ---------------------------------------------------------------- flags
    if memory.flags:
        lines.append("## Flags")
        lines.append("")
        for flag in memory.flags:
            lines.append(f"- `{flag.value}`")
            if flag.source:
                lines.append(f"  - source: {flag.source} (step {flag.step})")
        lines.append("")

    # ------------------------------------------------------------- findings
    lines.append("## Findings")
    lines.append("")
    if not memory.findings:
        lines.append("No confirmed findings were recorded during the run.")
        lines.append("")
    else:
        lines.append("| # | Severity | Finding |")
        lines.append("|---|----------|---------|")
        for index, finding in enumerate(memory.findings, start=1):
            lines.append(
                f"| {index} | {finding.severity.upper()} | {_cell(finding.title)} |"
            )
        lines.append("")
        for index, finding in enumerate(memory.findings, start=1):
            lines.append(f"### {index}. {finding.title}")
            lines.append("")
            lines.append(f"**Severity:** {finding.severity.upper()}  ")
            lines.append(f"**Discovered:** step {finding.step}")
            lines.append("")
            if finding.details:
                lines.append(finding.details)
                lines.append("")
            if finding.evidence:
                lines.append("Evidence:")
                lines.append("")
                lines.append("```")
                lines.append(finding.evidence.strip()[:4000])
                lines.append("```")
                lines.append("")
            if finding.remediation:
                lines.append(f"**Remediation:** {finding.remediation}")
                lines.append("")

    # ---------------------------------------------------------------- facts
    facts = memory.facts.digest(max_lines=60)
    lines.append("## Attack surface")
    lines.append("")
    if facts:
        lines.append("```")
        lines.append(facts)
        lines.append("```")
    else:
        lines.append("No structured facts (ports, URLs, credentials) were extracted.")
    lines.append("")

    # ------------------------------------------------------------- timeline
    lines.append("## Actions taken")
    lines.append("")
    if memory.attempts:
        lines.append("The chronological log of every action the agent took, including repeat "
                     "suppressions and guardrail blocks:")
        lines.append("")
        lines.append("```")
        for index, attempt in enumerate(memory.attempts, start=1):
            wrapped = textwrap.wrap(
                attempt.strip().replace("\n", " ; "), width=110, subsequent_indent="      "
            ) or [""]
            lines.append(f"{index:3d}. {wrapped[0]}")
            lines.extend(wrapped[1:])
        lines.append("```")
    else:
        lines.append("No actions were recorded.")
    lines.append("")

    # ---------------------------------------------------------------- notes
    if memory.notes:
        lines.append("## Agent notes")
        lines.append("")
        for note in memory.notes:
            label = f"**{note.title}** — " if note.title else ""
            lines.append(f"- {label}{note.text}")
        lines.append("")

    # ------------------------------------------------------- reproducibility
    lines.append("## Reproduction")
    lines.append("")
    lines.append("Re-run the same engagement with:")
    lines.append("")
    command = (
        f"redloop --target {config.target} --provider {config.provider} "
        f"--model {config.effective_model} --max-steps {config.max_steps}"
    )
    if config.objective:
        command += f' --objective "{config.objective}"'
    if config.scope:
        command += " --scope " + " ".join(config.scope)
    lines.append("```bash")
    lines.append(command)
    lines.append("```")
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    lines.append(
        "- This is an automated assessment. Findings and flags are reported as the agent "
        "observed them and should be validated before any disclosure or remediation work."
    )
    lines.append(
        "- The agent works within the scope it was given; absence of a finding is not "
        "evidence of absence of a vulnerability."
    )
    if steps >= config.max_steps:
        lines.append(
            f"- The step budget ({config.max_steps}) was consumed. Raising `--max-steps` may "
            "allow the agent to continue from a deeper position."
        )
    lines.append("")
    return "\n".join(lines)


def _duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    minutes, secs = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").strip()


def run_timestamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S")
