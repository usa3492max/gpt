"""Live terminal rendering of the agent's loop.

Three renderers:

* :class:`RichRenderer` — the default.  Colour, panels, a spinner while a tool runs.
* :class:`PlainRenderer` — line-oriented and ANSI-free, for ``--plain``, CI, ``docker logs``
  and anything piping the feed into another process.
* :class:`JsonRenderer` — one JSON object per event on stdout, for `jq` or a web front-end.

All three consume the same :class:`~redloop.events.Event` stream, so behaviour is identical
no matter how it is displayed.
"""

from __future__ import annotations

import dataclasses
import json
import sys
import time
from typing import Any

from .config import Config
from .events import Event
from .tools.base import strip_ansi

RICH_AVAILABLE = True
try:  # pragma: no cover - import guard
    from rich.console import Console
    from rich.markup import escape
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    from rich.text import Text
except Exception:  # pragma: no cover
    RICH_AVAILABLE = False


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def fmt_elapsed(seconds: float) -> str:
    seconds = max(0, int(seconds))
    hours, rest = divmod(seconds, 3600)
    minutes, secs = divmod(rest, 60)
    if hours:
        return f"{hours}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def fmt_int(value: float) -> str:
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"{value / 1_000:.1f}k"
    return str(int(value))


def action_preview(tool: str, args: dict[str, Any]) -> str:
    """A one-line, human-readable summary of what the agent is about to do."""
    args = args or {}
    if tool == "shell":
        return str(args.get("command", "")).replace("\n", " ; ")
    if tool == "python":
        first = next((line.strip() for line in str(args.get("code", "")).splitlines() if line.strip()), "")
        lines = len(str(args.get("code", "")).splitlines())
        return f"python ({lines} lines) {first[:80]}"
    if tool == "http":
        method = str(args.get("method") or "GET").upper()
        target = str(args.get("url", ""))
        body = args.get("data") or args.get("json")
        suffix = f"  body={str(body)[:70]}" if body else ""
        return f"{method} {target}{suffix}"
    if tool == "read_file":
        return str(args.get("path", ""))
    if tool == "write_file":
        return f"{args.get('path', '')} ({len(str(args.get('content', '')))}B)"
    if tool == "list_dir":
        return str(args.get("path", "."))
    if tool == "note_add":
        return str(args.get("text", ""))[:160]
    if tool == "record_finding":
        return f"[{str(args.get('severity', 'info')).upper()}] {args.get('title', '')}"
    if tool == "submit_flag":
        return str(args.get("flag", ""))
    if tool == "give_up":
        return str(args.get("reason", ""))[:160]
    return json.dumps(args, ensure_ascii=False)[:160]


def _clip(text: str, limit: int = 200) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _jsonable(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {k: _jsonable(v) for k, v in dataclasses.asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


# --------------------------------------------------------------------------- #
# Rich renderer
# --------------------------------------------------------------------------- #
class RichRenderer:
    max_preview_lines = 12

    def __init__(self, config: Config, console: Any = None, stream=None) -> None:
        if not RICH_AVAILABLE:  # pragma: no cover
            raise RuntimeError("rich is not installed")
        self.config = config
        self.verbose = config.verbose
        self.console = console or Console(
            file=stream or sys.stdout,
            no_color=config.no_color,
            highlight=False,
            soft_wrap=False,
            width=None if sys.stdout.isatty() else 120,
        )
        self.started = time.time()
        self._status = None
        if self.verbose:
            self.max_preview_lines = 40

    # ------------------------------------------------------------- dispatch
    def handle(self, event: Event) -> None:
        handler = getattr(self, f"_on_{event.type}", None)
        if handler is None:
            return
        try:
            handler(event)
        except Exception:  # pragma: no cover - the feed must never kill a run
            self._stop_status()

    # --------------------------------------------------------------- status
    def _start_status(self, text: str) -> None:
        if self.config.quiet or not self.console.is_terminal:
            return
        try:
            self._status = self.console.status(Text(f" {text}", style="cyan"), spinner="dots")
            self._status.start()
        except Exception:  # pragma: no cover
            self._status = None

    def _stop_status(self) -> None:
        if self._status is not None:
            try:
                self._status.stop()
            except Exception:  # pragma: no cover
                pass
            self._status = None

    # --------------------------------------------------------------- events
    def _on_session_start(self, event: Event) -> None:
        data = event.data
        banner = Text()
        banner.append("redloop", style="bold red")
        banner.append("  ·  ", style="grey42")
        banner.append("autonomous offensive-security agent", style="grey62")
        self.console.print()
        self.console.print(Panel(banner, border_style="red", padding=(0, 2), expand=False))

        table = Table.grid(padding=(0, 2))
        table.add_column(style="grey42", no_wrap=True)
        table.add_column(style="grey85")
        table.add_row("target", escape(str(data.get("target", ""))))
        table.add_row("objective", escape(_clip(data.get("objective") or "autonomous assessment", 90)))
        table.add_row("model", escape(f"{data.get('provider', '')} · {data.get('model', '')}"))
        table.add_row("scope", escape(str(data.get("scope", ""))))
        table.add_row(
            "limits",
            escape(
                f"{data.get('max_steps', '?')} steps · {data.get('max_minutes', '?')} min"
                + (f" · ${data.get('max_cost_usd')} budget" if data.get("max_cost_usd") else "")
            ),
        )
        table.add_row("run dir", escape(str(data.get("run_dir", ""))))
        if self.config.dry_run:
            table.add_row("mode", "[yellow]dry run[/yellow]")
        self.console.print(table)
        self.console.print()

    def _on_step_start(self, event: Event) -> None:
        self._stop_status()
        data = event.data
        title = Text()
        title.append(f" STEP {data.get('step')}", style="bold white")
        title.append(f"/{data.get('max_steps')} ", style="grey42")
        title.append(f" {fmt_elapsed(data.get('elapsed', 0))}", style="grey42")
        detail = []
        if data.get("tokens"):
            detail.append(f"{fmt_int(data['tokens'])} tok")
        if data.get("cost_usd"):
            detail.append(f"${data['cost_usd']:.3f}")
        if data.get("findings"):
            detail.append(f"{data['findings']} finding(s)")
        if detail:
            title.append("  ·  " + " · ".join(detail), style="grey35")
        self.console.print(Rule(title, style="grey30", align="left"))

    def _on_thought(self, event: Event) -> None:
        self._stop_status()
        text = str(event.data.get("text", "")).strip()
        if not text or self.config.quiet:
            return
        body = Text(strip_ansi(text), style="italic grey74")
        self.console.print(
            Panel(
                body,
                border_style="grey30",
                padding=(0, 1),
                title=Text(" thinking ", style="grey42"),
                title_align="left",
            )
        )

    def _on_action(self, event: Event) -> None:
        self._stop_status()
        data = event.data
        tool = str(data.get("tool", ""))
        preview = str(data.get("preview", ""))
        line = Text()
        line.append("  ▶ ", style="bold cyan")
        line.append(tool, style="bold cyan")
        line.append("  ", style="")
        line.append(_clip(preview, 240 if self.verbose else 150), style="white")
        self.console.print(line)
        if data.get("spinner"):
            self._start_status(f"{tool} running…")

    def _on_observation(self, event: Event) -> None:
        self._stop_status()
        if self.config.quiet:
            return
        data = event.data
        output = strip_ansi(str(data.get("output", ""))).strip()
        blocked = bool(data.get("blocked"))
        ok = bool(data.get("ok"))
        duration = data.get("duration") or 0
        title_bits = ["output"]
        if duration:
            title_bits.append(f"{duration:.1f}s")
        if blocked:
            title_bits.append("blocked")
        elif not ok:
            title_bits.append("failed")
        body, hidden = self._preview(output)
        style = "red" if blocked else ("grey62" if ok else "yellow")
        self.console.print(
            Panel(
                Text(body, style=style),
                border_style="red" if blocked else "grey23",
                padding=(0, 1),
                title=Text(" " + " · ".join(title_bits) + " ", style="grey42"),
                title_align="left",
                subtitle=Text(hidden, style="grey35") if hidden else None,
                subtitle_align="right",
            )
        )

    def _preview(self, output: str) -> tuple[str, str]:
        lines = output.splitlines() or ["(no output)"]
        limit = self.max_preview_lines
        if len(lines) <= limit:
            return "\n".join(lines), ""
        head = lines[: limit - 3]
        tail = lines[-3:]
        hidden = f"+{len(lines) - len(head) - len(tail)} more lines"
        return "\n".join([*head, "  ⋮", *tail]), hidden

    def _on_finding(self, event: Event) -> None:
        self._stop_status()
        finding = event.data.get("finding")
        title = getattr(finding, "title", str(finding))
        severity = str(getattr(finding, "severity", "info")).upper()
        colour = {
            "CRITICAL": "bright_red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "grey62",
        }.get(severity, "grey62")
        text = Text()
        text.append(f"{severity}  ", style=f"bold {colour}")
        text.append(str(title), style="white")
        self.console.print(Panel(text, border_style=colour, title=Text(" finding ", style=colour),
                                 title_align="left", padding=(0, 1)))

    def _on_flag(self, event: Event) -> None:
        self._stop_status()
        flag = event.data.get("flag")
        value = getattr(flag, "value", str(flag))
        source = getattr(flag, "source", "")
        body = Text()
        body.append("\n  FLAG CAPTURED\n", style="bold green")
        body.append(f"  {value}\n", style="bold white")
        if source:
            body.append(f"  source: {source}\n", style="grey62")
        self.console.print(
            Panel(body, border_style="green", padding=(0, 2), expand=False)
        )

    def _on_blocked(self, event: Event) -> None:
        self._stop_status()
        self.console.print(
            Text.assemble(
                ("  ⛔ guardrail  ", "bold red"),
                (_clip(str(event.data.get("reason", "")), 300), "red"),
            )
        )

    def _on_warning(self, event: Event) -> None:
        self._stop_status()
        self.console.print(
            Text.assemble(("  ⚠  ", "yellow"), (_clip(str(event.data.get("message", "")), 300), "yellow"))
        )

    def _on_error(self, event: Event) -> None:
        self._stop_status()
        self.console.print(
            Text.assemble(("  ✖  ", "bold red"), (_clip(str(event.data.get("message", "")), 400), "red"))
        )

    def _on_retrying(self, event: Event) -> None:
        self._stop_status()
        data = event.data
        self.console.print(
            Text(
                f"  ↻ model call failed ({_clip(str(data.get('error', '')), 120)}); retry "
                f"{data.get('attempt')} in {float(data.get('delay', 0)):.1f}s",
                style="yellow",
            )
        )

    def _on_compaction(self, event: Event) -> None:
        self._stop_status()
        data = event.data
        self.console.print(
            Text(
                f"  ⇣ context compacted: {data.get('removed', 0)} messages summarised, "
                f"~{fmt_int(data.get('tokens', 0))} tokens retained",
                style="grey42",
            )
        )

    def _on_session_end(self, event: Event) -> None:
        self._stop_status()
        if self.console.is_terminal:
            self.console.print()
        data = event.data
        status = str(data.get("status", "finished"))
        colours = {
            "flag": "green",
            "completed": "cyan",
            "exhausted": "yellow",
            "timeout": "yellow",
            "budget": "yellow",
            "interrupted": "yellow",
            "error": "red",
        }
        colour = colours.get(status, "grey62")
        table = Table.grid(padding=(0, 2))
        table.add_column(style="grey42", no_wrap=True)
        table.add_column(style="grey85")
        table.add_row("status", f"[bold {colour}]{status}[/bold {colour}]")
        if data.get("reason"):
            table.add_row("reason", escape(_clip(str(data["reason"]), 160)))
        table.add_row("steps", str(data.get("steps", 0)))
        table.add_row("duration", fmt_elapsed(data.get("duration", 0)))
        usage = data.get("usage") or {}
        if usage:
            table.add_row(
                "tokens",
                f"{fmt_int(usage.get('input_tokens', 0))} in · "
                f"{fmt_int(usage.get('output_tokens', 0))} out"
                + (
                    f" · {fmt_int(usage.get('cache_read_tokens', 0))} cached"
                    if usage.get("cache_read_tokens")
                    else ""
                ),
            )
        if data.get("cost_usd") is not None:
            cost = float(data.get("cost_usd") or 0)
            table.add_row("cost", f"${cost:.4f}" if cost else "$0.00 (local/unknown pricing)")
        flags = data.get("flags") or []
        if flags:
            table.add_row("flags", escape(", ".join(flags)))
        table.add_row("findings", str(data.get("findings", 0)))
        if data.get("report"):
            table.add_row("report", escape(str(data["report"])))
        self.console.print(Panel(table, border_style=colour, title=Text(" run summary ", style=colour),
                                 title_align="left", padding=(0, 1)))


# --------------------------------------------------------------------------- #
# Plain renderer
# --------------------------------------------------------------------------- #
class PlainRenderer:
    def __init__(self, config: Config, stream=None) -> None:
        self.config = config
        self.verbose = bool(config.verbose)
        self.stream = stream or sys.stdout
        self.started = time.time()

    def handle(self, event: Event) -> None:
        handler = getattr(self, f"_on_{event.type}", None)
        if handler is not None:
            handler(event)

    def _write(self, line: str) -> None:
        print(line, file=self.stream, flush=True)

    def _stamp(self) -> str:
        return f"[{fmt_elapsed(time.time() - self.started)}]"

    def _on_session_start(self, event: Event) -> None:
        d = event.data
        self._write("=" * 78)
        self._write("redloop · autonomous offensive-security agent")
        self._write(f"target    : {d.get('target')}")
        self._write(f"objective : {_clip(str(d.get('objective') or 'autonomous assessment'), 100)}")
        self._write(f"model     : {d.get('provider')} · {d.get('model')}")
        self._write(f"scope     : {d.get('scope')}")
        self._write(f"limits    : {d.get('max_steps')} steps · {d.get('max_minutes')} min")
        self._write(f"run dir   : {d.get('run_dir')}")
        self._write("=" * 78)

    def _on_step_start(self, event: Event) -> None:
        d = event.data
        self._write(f"{self._stamp()} STEP {d.get('step')}/{d.get('max_steps')}")

    def _on_thought(self, event: Event) -> None:
        text = str(event.data.get("text", "")).strip()
        if not text or self.config.quiet:
            return
        for line in strip_ansi(text).splitlines():
            self._write(f"{self._stamp()} THINK {line}".rstrip())

    def _on_action(self, event: Event) -> None:
        d = event.data
        self._write(f"{self._stamp()} ACT   {d.get('tool')}: {_clip(str(d.get('preview', '')), 300)}")

    def _on_observation(self, event: Event) -> None:
        if self.config.quiet:
            return
        d = event.data
        output = strip_ansi(str(d.get("output", ""))).strip()
        status = "blocked" if d.get("blocked") else ("ok" if d.get("ok") else "failed")
        self._write(f"{self._stamp()} OBS   {status} ({len(output)}B)")
        if not self.verbose and len(output.splitlines()) > 24:
            lines = output.splitlines()
            output = "\n".join([*lines[:14], f"  ⋮ (+{len(lines) - 17} lines)", *lines[-3:]])
        for line in output.splitlines():
            self._write(f"        {line}")

    def _on_finding(self, event: Event) -> None:
        finding = event.data.get("finding")
        title = getattr(finding, "title", str(finding))
        severity = str(getattr(finding, "severity", "info")).upper()
        self._write(f"{self._stamp()} FIND  [{severity}] {title}")

    def _on_flag(self, event: Event) -> None:
        flag = event.data.get("flag")
        value = getattr(flag, "value", str(flag))
        self._write("!" * 78)
        self._write(f"{self._stamp()} FLAG  {value}")
        self._write("!" * 78)

    def _on_blocked(self, event: Event) -> None:
        self._write(f"{self._stamp()} BLOCK {_clip(str(event.data.get('reason', '')), 300)}")

    def _on_warning(self, event: Event) -> None:
        self._write(f"{self._stamp()} WARN  {_clip(str(event.data.get('message', '')), 300)}")

    def _on_error(self, event: Event) -> None:
        self._write(f"{self._stamp()} ERROR {_clip(str(event.data.get('message', '')), 400)}")

    def _on_retrying(self, event: Event) -> None:
        d = event.data
        self._write(
            f"{self._stamp()} RETRY attempt {d.get('attempt')} in {float(d.get('delay', 0)):.1f}s "
            f"({_clip(str(d.get('error', '')), 100)})"
        )

    def _on_compaction(self, event: Event) -> None:
        d = event.data
        self._write(f"{self._stamp()} COMPACT {d.get('removed')} messages summarised")

    def _on_session_end(self, event: Event) -> None:
        d = event.data
        usage = d.get("usage") or {}
        self._write("-" * 78)
        self._write(f"{self._stamp()} END   status={d.get('status')} steps={d.get('steps')} "
                    f"duration={fmt_elapsed(d.get('duration', 0))}")
        if d.get("reason"):
            self._write(f"        reason: {_clip(str(d['reason']), 200)}")
        self._write(f"        tokens: {usage.get('input_tokens', 0)} in / "
                    f"{usage.get('output_tokens', 0)} out · cost ${float(d.get('cost_usd') or 0):.4f}")
        if d.get("flags"):
            self._write(f"        flags: {', '.join(d['flags'])}")
        self._write(f"        findings: {d.get('findings', 0)}")
        if d.get("report"):
            self._write(f"        report: {d['report']}")
        self._write("-" * 78)


# --------------------------------------------------------------------------- #
# JSON renderer
# --------------------------------------------------------------------------- #
class JsonRenderer:
    def __init__(self, config: Config, stream=None) -> None:
        self.stream = stream or sys.stdout
        self.config = config

    def handle(self, event: Event) -> None:
        payload = {"ts": event.ts, "event": event.type, **_jsonable(event.data)}
        print(json.dumps(payload, ensure_ascii=False, default=str), file=self.stream, flush=True)


def build_renderer(config: Config):
    if config.json_feed:
        return JsonRenderer(config)
    if config.plain or not RICH_AVAILABLE:
        return PlainRenderer(config)
    if not sys.stdout.isatty():
        # Piped or redirected output: keep it clean and greppable.
        return PlainRenderer(config)
    return RichRenderer(config)
