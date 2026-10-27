"""Tool behaviour: execution, limits, confinement and the HTTP client."""

from __future__ import annotations

import asyncio
from pathlib import Path

from redloop.config import Config
from redloop.memory import Memory
from redloop.safety import ScopeGuard
from redloop.tools import build_registry
from redloop.tools.base import ToolContext, truncate


def make_ctx(run_dir: Path, *, target="127.0.0.1", timeout=20, max_output=6000,
             dry_run=False, scope=()) -> ToolContext:
    config = Config(
        target=target,
        max_output_chars=max_output,
        command_timeout=timeout,
        dry_run=dry_run,
        runs_dir=run_dir,
    )
    return ToolContext(
        config=config,
        guard=ScopeGuard(target=target, scope=list(scope)),
        memory=Memory(),
        run_dir=run_dir,
        step=1,
    )


def run_tool(name: str, args: dict, ctx: ToolContext):
    return asyncio.run(build_registry()[name].execute(args, ctx))


# --------------------------------------------------------------------------- #
# shell
# --------------------------------------------------------------------------- #
def test_shell_runs_and_captures_stdout(run_dir):
    result = run_tool("shell", {"command": "echo hello-from-shell"}, make_ctx(run_dir))
    assert result.ok
    assert "hello-from-shell" in result.output
    assert result.exit_code == 0


def test_shell_captures_stderr_and_nonzero_exit(run_dir):
    result = run_tool("shell", {"command": "echo oops >&2; exit 3"}, make_ctx(run_dir))
    assert not result.ok
    assert result.exit_code == 3
    assert "oops" in result.output


def test_shell_timeout_kills_the_process(run_dir):
    result = run_tool("shell", {"command": "sleep 30", "timeout": 1}, make_ctx(run_dir))
    assert result.meta["timed_out"] is True
    assert result.duration < 10
    assert "timeout" in result.output.lower()


def test_shell_strips_ansi_colour(run_dir):
    result = run_tool(
        "shell", {"command": r"printf '\033[31mred\033[0m text'"}, make_ctx(run_dir)
    )
    assert "red text" in result.output
    assert "\x1b" not in result.output


def test_shell_output_is_truncated_and_persisted(run_dir):
    ctx = make_ctx(run_dir, max_output=200)
    result = run_tool("shell", {"command": "head -c 5000 /dev/zero | tr '\\0' 'a'"}, ctx)
    assert result.truncated
    assert len(result.output) < 1000
    assert "elided" in result.output
    saved = list((run_dir / "loot").glob("*.log"))
    assert saved and len(saved[0].read_text()) > 4000


def test_shell_blocks_destructive_commands(run_dir):
    result = run_tool("shell", {"command": "rm -rf /"}, make_ctx(run_dir))
    assert result.blocked
    assert not result.ok
    assert result.meta.get("guardrail")


def test_shell_blocks_out_of_scope_targets(run_dir):
    result = run_tool(
        "shell", {"command": "nmap -sV 93.184.216.34"}, make_ctx(run_dir, target="10.0.0.1")
    )
    assert result.blocked
    assert "93.184.216.34" in result.output


def test_shell_dry_run_does_not_execute(run_dir):
    marker = run_dir / "should-not-exist"
    result = run_tool(
        "shell", {"command": f"touch {marker}"}, make_ctx(run_dir, dry_run=True)
    )
    assert result.ok
    assert "dry-run" in result.output
    assert not marker.exists()


def test_shell_strips_a_leading_prompt(run_dir):
    result = run_tool("shell", {"command": "$ echo prompted"}, make_ctx(run_dir))
    assert "prompted" in result.output
    assert result.meta["command"] == "echo prompted"


def test_shell_handles_missing_binary(run_dir):
    result = run_tool("shell", {"command": "definitely-not-a-binary --help"}, make_ctx(run_dir))
    assert not result.ok
    assert result.exit_code == 127


# --------------------------------------------------------------------------- #
# python
# --------------------------------------------------------------------------- #
def test_python_runs_code(run_dir):
    result = run_tool("python", {"code": "print(6 * 7)"}, make_ctx(run_dir))
    assert result.ok
    assert "42" in result.output


def test_python_writes_a_script_into_the_work_dir(run_dir):
    result = run_tool("python", {"code": "print('x')"}, make_ctx(run_dir))
    assert result.ok
    scripts = list((run_dir / "work").glob("step001_snippet.py"))
    assert scripts and "print('x')" in scripts[0].read_text()


def test_python_blocks_out_of_scope_socket_code(run_dir):
    code = "import socket\ns=socket.socket()\ns.connect(('93.184.216.34', 80))\n"
    result = run_tool("python", {"code": code}, make_ctx(run_dir))
    assert result.blocked


def test_python_reports_tracebacks(run_dir):
    result = run_tool("python", {"code": "raise ValueError('boom')"}, make_ctx(run_dir))
    assert not result.ok
    assert "ValueError" in result.output


def test_python_strips_markdown_fences(run_dir):
    result = run_tool("python", {"code": "```python\nprint('fenced')\n```"}, make_ctx(run_dir))
    assert result.ok
    assert "fenced" in result.output


# --------------------------------------------------------------------------- #
# files
# --------------------------------------------------------------------------- #
def test_write_then_read(run_dir):
    ctx = make_ctx(run_dir)
    written = run_tool("write_file", {"path": "notes.txt", "content": "hello"}, ctx)
    assert written.ok
    read = run_tool("read_file", {"path": "notes.txt"}, ctx)
    assert read.ok
    assert "hello" in read.output


def test_write_outside_the_run_dir_is_refused(run_dir):
    result = run_tool("write_file", {"path": "/usr/local/bin/evil", "content": "x"},
                      make_ctx(run_dir))
    assert not result.ok
    assert "confined" in result.output
    assert not Path("/usr/local/bin/evil").exists()


def test_write_to_tmp_is_allowed(run_dir, tmp_path):
    target = Path("/tmp/redloop-test-write.txt")
    result = run_tool("write_file", {"path": str(target), "content": "x"}, make_ctx(run_dir))
    assert result.ok
    target.unlink(missing_ok=True)


def test_read_binary_file_shows_hex(run_dir):
    binary = run_dir / "blob.bin"
    binary.write_bytes(bytes(range(64)))
    result = run_tool("read_file", {"path": str(binary)}, make_ctx(run_dir))
    assert result.ok
    assert "binary" in result.output
    assert "hex" in result.output


def test_read_missing_file(run_dir):
    result = run_tool("read_file", {"path": "nope.txt"}, make_ctx(run_dir))
    assert not result.ok


def test_list_dir(run_dir):
    (run_dir / "work").mkdir(exist_ok=True)
    (run_dir / "work" / "a.txt").write_text("1")
    result = run_tool("list_dir", {"path": "."}, make_ctx(run_dir))
    assert result.ok
    assert "a.txt" in result.output


def test_read_directory_points_at_list_dir(run_dir):
    result = run_tool("read_file", {"path": "."}, make_ctx(run_dir))
    assert not result.ok
    assert "list_dir" in result.output


# --------------------------------------------------------------------------- #
# http
# --------------------------------------------------------------------------- #
def test_http_get(run_dir, lab_server):
    result = run_tool("http", {"url": lab_server + "/"}, make_ctx(run_dir))
    assert result.ok
    assert "200" in result.output
    assert "index" in result.output
    assert result.meta["status"] == 200


def test_http_post_follows_redirect_and_keeps_cookie(run_dir, lab_server):
    result = run_tool(
        "http",
        {"url": lab_server + "/login.php", "method": "POST",
         "data": "username=admin' OR 1=1-- -&password=x"},
        make_ctx(run_dir),
    )
    assert result.ok
    assert "flag{test_lab}" in result.output


def test_http_404_is_still_a_response(run_dir, lab_server):
    result = run_tool("http", {"url": lab_server + "/missing"}, make_ctx(run_dir))
    assert result.ok
    assert result.meta["status"] == 404


def test_http_binary_body_is_saved(run_dir, lab_server):
    result = run_tool("http", {"url": lab_server + "/binary"}, make_ctx(run_dir))
    assert result.ok
    assert "binary body" in result.output
    assert result.meta["saved"]


def test_http_blocks_out_of_scope_host(run_dir):
    result = run_tool("http", {"url": "http://93.184.216.34/"}, make_ctx(run_dir, target="10.0.0.1"))
    assert result.blocked


def test_http_adds_missing_scheme(run_dir, lab_server):
    bare = lab_server.replace("http://", "")
    result = run_tool("http", {"url": bare + "/"}, make_ctx(run_dir))
    assert result.ok


def test_http_connection_refused_is_reported(run_dir):
    result = run_tool("http", {"url": "http://127.0.0.1:1/"}, make_ctx(run_dir))
    assert not result.ok
    assert "failed" in result.output.lower()


# --------------------------------------------------------------------------- #
# registry / plumbing
# --------------------------------------------------------------------------- #
def test_registry_contains_expected_tools():
    registry = build_registry()
    for name in ("shell", "python", "http", "read_file", "write_file", "list_dir",
                 "note_add", "record_finding", "submit_flag", "give_up"):
        assert name in registry


def test_tool_signatures_and_help():
    registry = build_registry()
    assert registry["shell"].signature() == "shell(command*, timeout)"
    assert "nmap" in registry["shell"].help_text()


def test_missing_required_argument_is_rejected(run_dir):
    result = run_tool("shell", {}, make_ctx(run_dir))
    assert not result.ok
    assert "missing required argument" in result.output


def test_args_are_normalised(run_dir):
    result = run_tool("shell", {"Command": "echo ok"}, make_ctx(run_dir))
    assert result.ok
    assert "ok" in result.output


def test_note_and_finding_tools_persist(run_dir):
    ctx = make_ctx(run_dir)
    assert run_tool("note_add", {"text": "creds admin:hunter2", "title": "creds"}, ctx).ok
    assert run_tool("record_finding", {"title": "XSS", "severity": "high"}, ctx).ok
    assert ctx.memory.notes[0].text == "creds admin:hunter2"
    assert ctx.memory.findings[0].severity == "high"
    assert (run_dir / "memory.json").exists()


def test_submit_flag_returns_control_signal(run_dir):
    ctx = make_ctx(run_dir)
    result = run_tool("submit_flag", {"flag": "flag{abc}"}, ctx)
    assert result.meta["control"] == "flag"
    assert ctx.memory.flags[0].value == "flag{abc}"


def test_give_up_returns_control_signal(run_dir):
    result = run_tool("give_up", {"reason": "out of ideas"}, make_ctx(run_dir))
    assert result.meta["control"] == "give_up"


def test_truncate_keeps_head_and_tail():
    text = "A" * 5000 + "MIDDLE" + "B" * 5000
    out, truncated = truncate(text, 2000)
    assert truncated
    assert out.startswith("A")
    assert out.endswith("B")
    assert "elided" in out
    assert len(out) < 2400
