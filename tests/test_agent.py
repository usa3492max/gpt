"""The autonomous loop: parsing failures, guardrails, repeats, budgets, reporting."""

from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path

import pytest
from conftest import ScriptedClient, action

from redloop.agent import Agent
from redloop.config import Config
from redloop.events import EventBus, NullRenderer
from redloop.llm.base import Completion, LLMClient, Usage
from redloop.memory import Memory
from redloop.transcript import Transcript


def build(tmp_path: Path, replies, *, client=None, **overrides) -> tuple[Agent, NullRenderer]:
    config = Config(
        target="127.0.0.1",
        provider="mock",
        runs_dir=tmp_path,
        max_steps=overrides.pop("max_steps", 6),
        max_minutes=overrides.pop("max_minutes", 5.0),
        command_timeout=overrides.pop("command_timeout", 15),
        authorized=True,
    )
    for key, value in overrides.items():
        setattr(config, key, value)
    config.finalize()

    bus = EventBus()
    recorder = NullRenderer()
    bus.subscribe(recorder.handle)
    run_dir = tmp_path / "run"
    agent = Agent(
        config,
        bus,
        client=client or ScriptedClient(replies),
        memory=Memory(),
        run_dir=run_dir,
    )
    transcript = Transcript(run_dir, config)
    bus.subscribe(transcript.handle)
    agent.transcript = transcript  # closed by go()
    return agent, recorder


def go(agent: Agent):
    try:
        return asyncio.run(agent.run())
    finally:
        agent.transcript.close()


# --------------------------------------------------------------------------- #
# happy paths
# --------------------------------------------------------------------------- #
def test_runs_a_command_then_submits_a_flag(tmp_path):
    agent, events = build(tmp_path, [
        action("shell", command="echo recon-complete"),
        action("submit_flag", flag="flag{agent_works}", evidence="test"),
    ])
    result = go(agent)

    assert result.status == "flag"
    assert result.steps == 2
    assert result.flags[0].value == "flag{agent_works}"
    assert "flag" in events.types()
    assert "session_start" in events.types()
    assert "session_end" in events.types()
    observations = [e for e in events.of_type("observation")]
    assert "recon-complete" in observations[0].data["output"]


def test_flag_in_tool_output_stops_the_run(tmp_path):
    agent, events = build(tmp_path, [
        action("shell", command="echo 'here it is: flag{from_output}'"),
    ])
    result = go(agent)
    assert result.status == "flag"
    assert any(f.value == "flag{from_output}" for f in result.flags)
    assert events.of_type("flag")


def test_give_up_completes_the_run(tmp_path):
    agent, _ = build(tmp_path, [action("give_up", reason="nothing to do")])
    result = go(agent)
    assert result.status == "completed"
    assert "nothing to do" in result.reason


def test_report_and_artefacts_are_written(tmp_path):
    agent, _ = build(tmp_path, [
        action("record_finding", title="Weak SSH config", severity="medium", details="d"),
        action("submit_flag", flag="flag{reported}"),
    ])
    result = go(agent)
    run_dir = Path(result.run_dir)
    assert (run_dir / "report.md").exists()
    assert (run_dir / "results.json").exists()
    assert (run_dir / "memory.json").exists()
    assert (run_dir / "notes.md").exists()
    report = (run_dir / "report.md").read_text()
    assert "flag{reported}" in report
    assert "Weak SSH config" in report
    assert "MEDIUM" in report
    payload = json.loads((run_dir / "results.json").read_text())
    assert payload["run"]["status"] == "flag"
    assert payload["findings"][0]["title"] == "Weak SSH config"


# --------------------------------------------------------------------------- #
# recovery behaviour
# --------------------------------------------------------------------------- #
def test_unparseable_reply_is_recoverable(tmp_path):
    agent, events = build(tmp_path, [
        "I think the target is probably running something.",
        action("submit_flag", flag="flag{recovered}"),
    ])
    result = go(agent)
    assert result.status == "flag"
    assert result.steps == 2
    warnings = [e.data["message"] for e in events.of_type("warning")]
    assert any("action" in message.lower() for message in warnings)


def test_unknown_tool_is_rejected_and_nudged(tmp_path):
    agent, events = build(tmp_path, [
        '{"tool": "metasploit", "args": {"module": "x"}}',
        action("submit_flag", flag="flag{nudged}"),
    ])
    result = go(agent)
    assert result.status == "flag"
    assert any("unknown tool" in e.data["message"].lower() for e in events.of_type("warning"))
    # The nudge must list the real tools.
    last_user = agent.client.calls[1][-1].content
    assert "shell" in last_user


def test_missing_required_argument_is_reported_to_the_model(tmp_path):
    agent, events = build(tmp_path, [
        '{"tool": "shell", "args": {"timeout": 5}}',
        action("submit_flag", flag="flag{ok}"),
    ])
    result = go(agent)
    assert result.status == "flag"
    observations = events.of_type("observation")
    assert "missing required argument" in observations[0].data["output"]


def test_blocked_action_is_fed_back(tmp_path):
    agent, events = build(tmp_path, [
        action("shell", command="curl -s http://93.184.216.34/"),
        action("submit_flag", flag="flag{blocked_but_ok}"),
    ])
    result = go(agent)
    assert result.status == "flag"
    assert events.of_type("blocked")
    blocked = events.of_type("blocked")[0].data["reason"]
    assert "93.184.216.34" in blocked


def test_repeated_action_is_suppressed(tmp_path):
    same = action("shell", command="echo same-thing")
    agent, events = build(tmp_path, [same, same, same, same,
                                     action("submit_flag", flag="flag{escape}")])
    result = go(agent)
    assert result.status == "flag"
    repeats = [e for e in events.of_type("warning") if "repeated" in e.data["message"]]
    assert repeats
    executed = [e for e in events.of_type("action") if e.data["tool"] == "shell"]
    assert len(executed) == 2  # first two run, the rest are suppressed


def test_consecutive_failures_end_the_run(tmp_path):
    replies = [action("shell", command=f"exit {index}") for index in range(12)]
    agent, _ = build(tmp_path, replies, max_steps=20)
    result = go(agent)
    assert result.status == "exhausted"
    assert "unproductive" in result.reason


# --------------------------------------------------------------------------- #
# limits
# --------------------------------------------------------------------------- #
def test_step_budget_is_enforced(tmp_path):
    replies = [action("shell", command=f"echo step-{index}") for index in range(5)]
    agent, _ = build(tmp_path, replies, max_steps=3)
    result = go(agent)
    assert result.steps == 3
    assert result.status == "exhausted"
    assert "step budget" in result.reason


def test_time_budget_is_enforced(tmp_path):
    agent, _ = build(tmp_path, [action("shell", command="sleep 2")] * 5, max_minutes=0.01)
    result = go(agent)
    assert result.status in {"timeout", "exhausted"}
    assert result.steps <= 2


def test_cost_budget_is_enforced(tmp_path):
    agent, _ = build(tmp_path, [action("shell", command=f"echo {i}") for i in range(5)],
                     max_cost_usd=0.0000001, model="claude-sonnet-4-5")
    result = go(agent)
    assert result.status == "budget"


def test_dry_run_executes_nothing_and_stops(tmp_path):
    marker = tmp_path / "marker"
    agent, _ = build(tmp_path, [action("shell", command=f"touch {marker}")], dry_run=True)
    result = go(agent)
    assert result.steps == 1
    assert not marker.exists()
    assert "dry run" in result.reason


# --------------------------------------------------------------------------- #
# context management
# --------------------------------------------------------------------------- #
def test_context_is_compacted_when_it_grows(tmp_path):
    replies = [action("shell", command=f"echo {index} {'x' * 1500}") for index in range(10)]
    agent, events = build(tmp_path, replies, max_steps=10, context_window=6000)
    result = go(agent)
    assert result.status in {"exhausted", "completed"}
    assert events.of_type("compaction")
    # After compaction the model is told the history was summarised, and the
    # prompt it receives must be much smaller than the raw transcript.
    final_prompt = "\n".join(m.content for m in agent.client.calls[-1])
    assert "HISTORY COMPACTED" in final_prompt or "compacted" in final_prompt.lower()
    assert len(final_prompt) < 60_000


def test_state_block_carries_facts_and_notes(tmp_path):
    agent, _ = build(tmp_path, [
        action("note_add", text="admin password is hunter2"),
        action("shell", command="printf '22/tcp open ssh\\n'"),
        action("submit_flag", flag="flag{done}"),
    ])
    go(agent)
    final_prompt = "\n".join(m.content for m in agent.client.calls[-1])
    assert "hunter2" in final_prompt
    assert "22/tcp" in final_prompt
    assert "step 3" in final_prompt


# --------------------------------------------------------------------------- #
# model failures
# --------------------------------------------------------------------------- #
class ExplodingClient(LLMClient):
    name = "exploding"
    model = "boom"

    def __init__(self, error):
        self.error = error
        self.calls = 0

    async def complete(self, system, messages, *, max_tokens=0, temperature=0):
        self.calls += 1
        raise self.error

    async def aclose(self):
        return None


class CountingClient(LLMClient):
    name = "counting"
    model = "counter"

    def __init__(self):
        self.calls = 0

    async def complete(self, system, messages, *, max_tokens=0, temperature=0):
        self.calls += 1
        return Completion(text=action("give_up", reason="done"),
                          usage=Usage(input_tokens=1000, output_tokens=100))

    async def aclose(self):
        return None


def test_model_error_ends_the_run_with_a_report(tmp_path):
    from redloop.llm import AuthError

    agent, events = build(tmp_path, [], client=ExplodingClient(AuthError("bad key")))
    result = go(agent)
    assert result.status == "error"
    assert "bad key" in result.reason
    assert Path(result.run_dir, "report.md").exists()
    assert events.of_type("error")


def test_usage_and_cost_are_tracked(tmp_path):
    agent, _ = build(tmp_path, [], client=CountingClient(), model="claude-sonnet-4-5")
    result = go(agent)
    assert result.usage.input_tokens == 1000
    assert result.usage.output_tokens == 100
    assert result.cost_usd == pytest.approx(0.003 + 0.0015)


# --------------------------------------------------------------------------- #
# flags from custom patterns
# --------------------------------------------------------------------------- #
def test_custom_flag_regex_is_honoured(tmp_path):
    agent, _ = build(
        tmp_path,
        [action("shell", command="echo 'SECRET{treasure}'")],
        extra_flag_patterns=[r"SECRET\{[a-z]+\}"],
    )
    result = go(agent)
    assert result.status == "flag"
    assert result.flags[0].value == "SECRET{treasure}"


def test_multi_flag_keeps_running(tmp_path):
    agent, _ = build(
        tmp_path,
        [
            action("shell", command="echo 'flag{first}'"),
            action("shell", command="echo 'flag{second}'"),
            action("give_up", reason="both captured"),
        ],
        stop_on_flag=False,
    )
    result = go(agent)
    assert {f.value for f in result.flags} == {"flag{first}", "flag{second}"}
    assert result.status == "completed"


# --------------------------------------------------------------------------- #
# e2e with the real mock model against the local lab
# --------------------------------------------------------------------------- #
def test_end_to_end_mock_model_against_lab(tmp_path, lab_server):
    from redloop.llm import MockClient

    port = lab_server.rsplit(":", 1)[1]
    if int(port) > 10000:
        pytest.skip("mock port scanner covers 1-10000")
    # The mock model scans 127.0.0.1 and prefers conventional web ports. If the
    # machine already serves something on one of them the run would attack that
    # instead, so this test needs a quiet loopback.
    for busy in (80, 3000, 5000, 8000, 8080, 8443, 8888):
        with socket.socket() as probe:
            probe.settimeout(0.05)
            if probe.connect_ex(("127.0.0.1", busy)) == 0:
                pytest.skip(f"port {busy} is already serving on loopback")

    agent, events = build(
        tmp_path, [], client=MockClient(target="127.0.0.1"), max_steps=15
    )
    result = go(agent)
    assert result.status == "flag"
    assert result.flags[0].value == "flag{test_lab}"
    assert result.findings
    report = Path(result.run_dir, "report.md").read_text()
    assert "flag{test_lab}" in report
    assert "Actions taken" in report
    assert (Path(result.run_dir) / "feed.txt").exists()
    assert (Path(result.run_dir) / "transcript.jsonl").exists()
    feed = (Path(result.run_dir) / "feed.txt").read_text()
    assert "FLAG" in feed and "STEP 1" in feed
