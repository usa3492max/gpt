"""The action parser has to survive everything a real model emits."""

from __future__ import annotations

import json

import pytest

from redloop.protocol import Action, format_action, parse_action

CASES = [
    # plain fenced json
    ('```json\n{"tool": "shell", "args": {"command": "ls"}}\n```', "shell", {"command": "ls"}),
    # bare json in prose
    ('I will scan.\n{"tool": "shell", "args": {"command": "nmap -sV 1.2.3.4"}}', "shell",
     {"command": "nmap -sV 1.2.3.4"}),
    # single quotes / python dict
    ("{'tool': 'shell', 'args': {'command': 'id'}}", "shell", {"command": "id"}),
    # trailing comma
    ('{"tool": "shell", "args": {"command": "id",},}', "shell", {"command": "id"}),
    # alias
    ('{"tool": "bash", "args": {"command": "whoami"}}', "shell", {"command": "whoami"}),
    # flat shorthand
    ('{"tool": "shell", "command": "uname -a"}', "shell", {"command": "uname -a"}),
    # nested function object
    ('{"tool": {"name": "shell", "args": {"command": "pwd"}}}', "shell", {"command": "pwd"}),
    # args as a JSON string
    ('{"tool": "shell", "args": "{\\"command\\": \\"date\\"}"}', "shell", {"command": "date"}),
    # case and spacing in the tool name
    ('{"tool": "  Shell  ", "args": {"command": "ls -la"}}', "shell", {"command": "ls -la"}),
    # xml-ish tag wrapper
    ("<action>{'tool': 'shell', 'args': {'command': 'env'}}</action>", "shell",
     {"command": "env"}),
    # markdown fence without a language
    ('```\n{"tool": "shell", "args": {"command": "ps aux"}}\n```', "shell",
     {"command": "ps aux"}),
    # http shorthand
    ('{"tool": "http", "url": "http://x/", "method": "POST", "data": "a=1"}', "http",
     {"url": "http://x/", "method": "POST", "data": "a=1"}),
    # python alias
    ('{"tool": "python3", "code": "print(1)"}', "python", {"code": "print(1)"}),
]

PARSED = [
    (raw, tool, args, parse_action(raw)) for raw, tool, args in CASES
]


@pytest.mark.parametrize("raw,tool,args,result", PARSED)
def test_parses_common_formats(raw, tool, args, result):
    assert result.ok, f"failed to parse: {raw!r} ({result.error})"
    assert result.action.tool == tool
    for key, value in args.items():
        assert result.action.args[key] == value


def test_thought_is_stripped_from_prose():
    reply = (
        "The scan shows SSH open, so the web app is probably the way in.\n\n"
        "```json\n{\"tool\": \"http\", \"args\": {\"url\": \"http://x/\"}}\n```"
    )
    result = parse_action(reply)
    assert result.ok
    assert result.thought.startswith("The scan shows SSH open")
    assert "```" not in result.thought


def test_explicit_thought_field_wins():
    reply = '{"thought": "testing sqli", "tool": "shell", "args": {"command": "sqlmap -u x"}}'
    result = parse_action(reply)
    assert result.ok
    assert result.action.thought == "testing sqli"


def test_last_action_wins_when_model_restates():
    reply = (
        '```json\n{"tool": "shell", "args": {"command": "one"}}\n```\n'
        "Actually, the better move is:\n"
        '```json\n{"tool": "shell", "args": {"command": "two"}}\n```\n'
    )
    result = parse_action(reply)
    assert result.ok
    assert result.action.args["command"] == "two"


def test_shell_fence_fallback():
    reply = "I'll just run the scan directly.\n\n```bash\nnmap -p- 10.0.0.5\n```\n"
    result = parse_action(reply)
    assert result.ok
    assert result.action.tool == "shell"
    assert result.action.args["command"] == "nmap -p- 10.0.0.5"


def test_shell_fence_with_prompt_prefix():
    reply = "```bash\n$ curl -s http://x/\n```"
    result = parse_action(reply)
    assert result.ok
    assert result.action.args["command"] == "curl -s http://x/"


def test_shell_fence_not_used_when_not_at_the_end():
    reply = "```bash\nls\n```\nThen I would check the output carefully.\n"
    assert not parse_action(reply).ok


def test_no_action_gives_helpful_hint():
    result = parse_action("I think the target is probably running Apache.")
    assert not result.ok
    assert "No executable action" in (result.error or "")
    assert '"tool"' in (result.error or "")


def test_empty_reply():
    result = parse_action("   ")
    assert not result.ok
    assert "empty" in (result.error or "")


def test_unknown_tool_is_preserved_not_dropped():
    result = parse_action('{"tool": "metasploit", "args": {"module": "x"}}')
    assert result.ok
    assert result.action.tool == "metasploit"


def test_finish_with_flag_becomes_submit():
    result = parse_action('{"tool": "finish", "args": {"flag": "flag{abc}"}}')
    assert result.ok
    assert result.action.tool == "submit_flag"
    assert result.action.args["flag"] == "flag{abc}"


def test_finish_without_flag_becomes_give_up():
    result = parse_action('{"tool": "done", "args": {"reason": "nothing left"}}')
    assert result.ok
    assert result.action.tool == "give_up"
    assert "nothing left" in result.action.args["reason"]


def test_submit_with_list_of_flags():
    result = parse_action('{"tool": "submit_flag", "args": {"flag": ["flag{a}", "flag{b}"]}}')
    assert result.ok
    assert result.action.args["flag"] == "flag{a}"


def test_action_without_tool_is_rejected():
    assert not parse_action('{"args": {"command": "ls"}}').ok


def test_json_with_ansi_colour_codes():
    result = parse_action('\x1b[32m{"tool": "shell", "args": {"command": "ls"}}\x1b[0m')
    assert result.ok
    assert result.action.args["command"] == "ls"


def test_multiline_command_is_preserved():
    reply = json.dumps({"tool": "shell", "args": {"command": "echo one\necho two"}})
    result = parse_action(reply)
    assert result.ok
    assert result.action.args["command"] == "echo one\necho two"


def test_format_action_roundtrip():
    original = Action("shell", {"command": "id"})
    parsed = parse_action(format_action(original))
    assert parsed.ok
    assert parsed.action.tool == "shell"
    assert parsed.action.args == {"command": "id"}
