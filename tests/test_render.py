"""Renderers: the same event stream, three presentations."""

from __future__ import annotations

import io
import json

from redloop.config import Config
from redloop.events import Event, EventBus
from redloop.memory import Finding, Flag
from redloop.render import (
    JsonRenderer,
    PlainRenderer,
    RichRenderer,
    action_preview,
    fmt_elapsed,
)


def feed(renderer, events):
    for event in events:
        renderer.handle(event)


EVENTS = [
    Event("session_start", {
        "target": "10.0.0.5", "objective": "capture the flag", "scope": "10.0.0.5",
        "provider": "anthropic", "model": "claude-sonnet-4-5", "max_steps": 40,
        "max_minutes": 90, "run_dir": "/tmp/run", "max_cost_usd": 0,
    }),
    Event("step_start", {"step": 1, "max_steps": 40, "elapsed": 3, "tokens": 1200,
                         "cost_usd": 0.01, "findings": 0}),
    Event("thought", {"text": "SSH is open, so let me look at the web service first."}),
    Event("action", {"tool": "shell", "args": {"command": "nmap -sV 10.0.0.5"},
                     "preview": "nmap -sV 10.0.0.5", "spinner": True}),
    Event("observation", {"tool": "shell", "ok": True, "blocked": False,
                          "output": "80/tcp open http\n" * 40, "duration": 1.5}),
    Event("blocked", {"reason": "8.8.8.8 is out of scope"}),
    Event("warning", {"message": "repeated action suppressed"}),
    Event("finding", {"finding": Finding(title="Exposed backup", severity="high")}),
    Event("flag", {"flag": Flag(value="flag{test}", source="tool output")}),
    Event("session_end", {
        "status": "flag", "reason": "flag captured", "steps": 3, "duration": 42,
        "usage": {"input_tokens": 1000, "output_tokens": 200}, "cost_usd": 0.05,
        "flags": ["flag{test}"], "findings": 1, "report": "/tmp/run/report.md",
    }),
]


def test_plain_renderer_is_line_oriented_and_ansi_free():
    stream = io.StringIO()
    config = Config(plain=True)
    feed(PlainRenderer(config, stream=stream), EVENTS)
    text = stream.getvalue()

    assert "STEP 1/40" in text
    assert "THINK SSH is open" in text
    assert "ACT   shell: nmap -sV 10.0.0.5" in text
    assert "BLOCK 8.8.8.8 is out of scope" in text
    assert "FIND  [HIGH] Exposed backup" in text
    assert "FLAG  flag{test}" in text
    assert "END   status=flag" in text
    assert "\x1b[" not in text
    assert text.count("80/tcp open http") < 40  # long output is abbreviated


def test_plain_renderer_verbose_shows_more():
    stream = io.StringIO()
    feed(PlainRenderer(Config(plain=True, verbose=True), stream=stream), EVENTS)
    assert stream.getvalue().count("80/tcp open http") > 20


def test_plain_renderer_quiet_hides_observations():
    stream = io.StringIO()
    feed(PlainRenderer(Config(plain=True, quiet=True), stream=stream), EVENTS)
    text = stream.getvalue()
    assert "80/tcp open http" not in text
    assert "STEP 1" in text


def test_json_renderer_emits_one_object_per_event():
    stream = io.StringIO()
    feed(JsonRenderer(Config(), stream=stream), EVENTS)
    lines = [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]
    assert len(lines) == len(EVENTS)
    assert lines[0]["event"] == "session_start"
    assert lines[0]["target"] == "10.0.0.5"
    assert lines[-1]["event"] == "session_end"
    assert lines[7]["finding"]["severity"] == "high"  # dataclasses are serialised


def test_rich_renderer_draws_without_crashing():
    from rich.console import Console

    stream = io.StringIO()
    console = Console(file=stream, no_color=True, width=100, force_terminal=False)
    feed(RichRenderer(Config(), console=console), EVENTS)
    text = stream.getvalue()
    assert "redloop" in text
    assert "nmap -sV 10.0.0.5" in text
    assert "flag{test}" in text
    assert "run summary" in text


def test_rich_renderer_handles_unknown_events():
    from rich.console import Console

    console = Console(file=io.StringIO(), no_color=True, width=80)
    renderer = RichRenderer(Config(), console=console)
    renderer.handle(Event("not_a_real_event", {"x": 1}))
    renderer.handle(Event("session_end", {}))


def test_renderer_never_raises_on_weird_payloads():
    from rich.console import Console

    stream = io.StringIO()
    renderer = RichRenderer(Config(), console=Console(file=stream, no_color=True, width=80))
    renderer.handle(Event("action", {"tool": None, "args": None, "preview": None}))
    renderer.handle(Event("observation", {"output": None}))
    renderer.handle(Event("session_start", {}))
    renderer.handle(Event("session_end", {"usage": None}))


def test_broken_listener_does_not_break_the_bus():
    bus = EventBus()
    bus.subscribe(lambda event: 1 / 0)
    stream = io.StringIO()
    bus.subscribe(JsonRenderer(Config(), stream=stream).handle)
    bus.emit("step_start", step=1)
    assert bus.errors
    assert "step_start" in stream.getvalue()


def test_action_preview_for_each_tool():
    assert action_preview("shell", {"command": "id"}) == "id"
    assert "GET http://x/" in action_preview("http", {"url": "http://x/"})
    assert "POST" in action_preview("http", {"url": "http://x/", "method": "post"})
    assert action_preview("python", {"code": "print(1)\nprint(2)"}).startswith("python (2 lines)")
    assert action_preview("note_add", {"text": "creds"}) == "creds"
    assert "HIGH" in action_preview("record_finding", {"title": "x", "severity": "high"})
    assert action_preview("submit_flag", {"flag": "flag{x}"}) == "flag{x}"
    assert action_preview("unknown_tool", {"a": 1}) == '{"a": 1}'


def test_action_preview_clips_long_values():
    assert len(action_preview("shell", {"command": "x" * 500})) == 500
    assert len(action_preview("note_add", {"text": "y" * 500})) == 160


def test_fmt_elapsed():
    assert fmt_elapsed(0) == "00:00"
    assert fmt_elapsed(65) == "01:05"
    assert fmt_elapsed(3661) == "1:01:01"
