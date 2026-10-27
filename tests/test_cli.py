"""End-to-end command-line behaviour."""

from __future__ import annotations

import json

from redloop.cli import main


def test_version(capsys):
    assert main(["--version"]) == 0
    assert "redloop" in capsys.readouterr().out


def test_list_tools(capsys):
    assert main(["--list-tools"]) == 0
    out = capsys.readouterr().out
    assert "shell(command*" in out
    assert "submit_flag" in out


def test_env_listing(capsys):
    assert main(["--env"]) == 0
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().out


def test_missing_target_is_a_usage_error(capsys):
    assert main(["-p", "mock"]) == 2
    assert "no target" in capsys.readouterr().err


def test_missing_api_key_is_reported(capsys, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert main(["-t", "10.0.0.5"]) == 2
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err


def test_unknown_provider_is_reported(capsys):
    assert main(["-t", "10.0.0.5", "-p", "does-not-exist"]) == 2
    assert "unknown provider" in capsys.readouterr().err


def test_public_target_requires_explicit_authorisation(capsys):
    assert main(["-t", "93.184.216.34", "-p", "mock"]) == 2
    err = capsys.readouterr().err
    assert "--i-am-authorized" in err
    assert "authorised" in err.lower()


def test_print_prompt_shows_the_system_prompt(capsys):
    assert main(["-t", "10.0.0.5", "-p", "mock", "--print-prompt"]) == 0
    out = capsys.readouterr().out
    assert "=== SYSTEM PROMPT ===" in out
    assert "autonomous offensive-security agent" in out
    assert "=== FIRST USER MESSAGE ===" in out
    assert "10.0.0.5" in out


def test_doctor_reports_the_environment(capsys):
    code = main(["-t", "127.0.0.1", "-p", "mock", "--doctor"])
    out = capsys.readouterr().out
    assert "redloop doctor" in out
    assert "Guardrails" in out
    assert code in (0, 1)


def test_dry_run_needs_no_target_traffic(tmp_path, capsys):
    code = main([
        "-t", "127.0.0.1", "-p", "mock", "--dry-run", "--plain",
        "--runs-dir", str(tmp_path), "--max-steps", "1",
    ])
    assert code == 0
    out = capsys.readouterr().out
    assert "dry-run" in out.lower()
    run_dirs = [p for p in tmp_path.iterdir() if p.is_dir()]
    assert run_dirs


def test_full_run_with_the_mock_model(tmp_path, capsys):
    code = main([
        "-t", "127.0.0.1", "-p", "mock", "--plain", "--max-steps", "3",
        "--runs-dir", str(tmp_path),
    ])
    out = capsys.readouterr().out
    assert "STEP 1/3" in out
    assert code in (0, 3)
    run_dir = next(p for p in tmp_path.iterdir() if p.is_dir())
    assert (run_dir / "report.md").exists()
    assert (run_dir / "results.json").exists()
    payload = json.loads((run_dir / "results.json").read_text())
    assert payload["run"]["target"] == "127.0.0.1"
    assert payload["run"]["provider"] == "mock"


def test_json_feed_is_machine_readable(tmp_path, capsys):
    code = main([
        "-t", "127.0.0.1", "-p", "mock", "--json-feed", "--max-steps", "2",
        "--runs-dir", str(tmp_path),
    ])
    captured = capsys.readouterr().out
    events = [json.loads(line) for line in captured.splitlines() if line.strip().startswith("{")]
    assert events
    assert events[0]["event"] == "session_start"
    assert any(event["event"] == "session_end" for event in events)
    assert code in (0, 3)


def test_resume_restores_the_scratchpad(tmp_path, capsys):
    run_dir = tmp_path / "resumed"
    run_dir.mkdir()
    (run_dir / "memory.json").write_text(json.dumps({
        "notes": [{"text": "earlier note", "title": "t", "step": 1, "ts": 0}],
        "findings": [], "flags": [], "facts": {}, "attempts": ["shell: nmap"],
    }))
    main([
        "-t", "127.0.0.1", "-p", "mock", "--plain", "--max-steps", "1",
        "--resume", str(run_dir),
    ])
    out = capsys.readouterr().out
    assert "STEP 1/1" in out
    assert (run_dir / "report.md").exists()


def test_interrupt_is_reported_cleanly(tmp_path, monkeypatch, capsys):
    # A model that blocks forever should be interruptible without a traceback.
    import asyncio

    from redloop import cli as cli_module

    class HangClient:
        name = "hang"
        model = "hang"

        async def complete(self, *args, **kwargs):
            await asyncio.sleep(30)

        async def aclose(self):
            return None

    monkeypatch.setattr(cli_module, "build_client", lambda config, **kwargs: HangClient())

    original_run = asyncio.run

    def fake_run(coro):
        async def limited():
            try:
                return await asyncio.wait_for(coro, timeout=0.2)
            except asyncio.TimeoutError:
                raise KeyboardInterrupt from None

        return original_run(limited())

    monkeypatch.setattr(asyncio, "run", fake_run)
    code = main(["-t", "127.0.0.1", "-p", "mock", "--plain", "--runs-dir", str(tmp_path)])
    captured = capsys.readouterr()
    assert "interrupted" in (captured.out + captured.err).lower()
    assert code == 130
