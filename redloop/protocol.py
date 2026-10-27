"""The agent's action protocol.

Every model — Claude, GPT, a 7B model on Ollama — is asked to answer with short
prose reasoning followed by exactly one JSON action object::

    The port scan shows SSH and HTTP.  I'll fingerprint the web server first.

    ```json
    {"tool": "shell", "args": {"command": "whatweb http://10.0.0.5"}}
    ```

Real models are not that tidy.  They emit bare JSON, XML-ish tags, Python
dicts with single quotes, fenced YAML-ish blocks, or a shell command in a
```bash fence.  :func:`parse_action` accepts all of it and still leaves the
prose intact so the live feed can show the model thinking out loud.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from typing import Any

#: Names models use for a tool, mapped onto the real registry names.
TOOL_ALIASES: dict[str, str] = {
    "sh": "shell",
    "bash": "shell",
    "terminal": "shell",
    "exec": "shell",
    "execute": "shell",
    "command": "shell",
    "run": "shell",
    "run_command": "shell",
    "run_shell": "shell",
    "shell_command": "shell",
    "cmd": "shell",
    "py": "python",
    "python3": "python",
    "python_exec": "python",
    "code": "python",
    "http_request": "http",
    "http_get": "http",
    "request": "http",
    "curl": "http",
    "fetch": "http",
    "web_request": "http",
    "browse": "http",
    "read": "read_file",
    "cat": "read_file",
    "view_file": "read_file",
    "write": "write_file",
    "save_file": "write_file",
    "ls": "list_dir",
    "list": "list_dir",
    "list_files": "list_dir",
    "note": "note_add",
    "notes": "note_add",
    "remember": "note_add",
    "add_note": "note_add",
    "scratchpad": "note_add",
    "submit": "submit_flag",
    "flag": "submit_flag",
    "submit_flags": "submit_flag",
    "report_flag": "submit_flag",
    "finish": "submit_flag",
    "complete": "submit_flag",
    "done": "submit_flag",
    "giveup": "give_up",
    "abort": "give_up",
    "stop": "give_up",
}

#: Keys that describe the call rather than its arguments.
META_KEYS = {
    "tool",
    "action",
    "name",
    "tool_name",
    "toolname",
    "function",
    "call",
    "thought",
    "reasoning",
    "thinking",
    "plan",
    "why",
    "note",
    "notes",
    "description",
    "comment",
    "observation",
}

#: Per-tool shorthand keys.  ``{"tool":"shell","command":"ls"}`` becomes
#: ``{"tool":"shell","args":{"command":"ls"}}``.
SHORTHANDS: dict[str, dict[str, str]] = {
    "shell": {"command": "command", "cmd": "command", "script": "command", "shell": "command"},
    "python": {"code": "code", "script": "code", "source": "code", "python": "code"},
    "http": {
        "url": "url",
        "uri": "url",
        "method": "method",
        "data": "data",
        "body": "data",
        "json": "json",
        "headers": "headers",
    },
    "read_file": {"path": "path", "file": "path", "filename": "path"},
    "write_file": {"path": "path", "file": "path", "filename": "path", "content": "content", "data": "content"},
    "list_dir": {"path": "path", "dir": "path", "directory": "path"},
    "note_add": {"text": "text", "content": "text", "note": "text", "title": "title"},
    "submit_flag": {
        "flag": "flag",
        "answer": "flag",
        "value": "flag",
        "flags": "flag",
        "result": "flag",
        "proof": "flag",
        "evidence": "evidence",
    },
    "give_up": {"reason": "reason", "why": "reason", "summary": "reason", "message": "reason"},
}

FENCE_RE = re.compile(r"```[ \t]*([A-Za-z0-9_+-]*)[ \t]*\n?(.*?)```", re.DOTALL)
TAG_RE = re.compile(
    r"<(action|tool_call|tool_call_json|json|action_json)>(.*?)</\1>", re.DOTALL | re.IGNORECASE
)
SHELL_FENCE_LANGS = {"bash", "sh", "shell", "zsh", "console", "terminal", "cmd", "powershell", "ps1"}
JSON_FENCE_LANGS = {"json", "json5", "javascript", "js", "yaml", "yml", "tool", "action", "tool_call", ""}


@dataclass
class Action:
    tool: str
    args: dict[str, Any] = field(default_factory=dict)
    thought: str = ""
    raw: str = ""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Action(tool={self.tool!r}, args={self.args!r})"


@dataclass
class ParseResult:
    action: Action | None
    thought: str = ""
    error: str | None = None
    raw: str = ""

    @property
    def ok(self) -> bool:
        return self.action is not None


NO_ACTION_HINT = (
    "No executable action was found in your reply. Reply with 2-5 sentences of reasoning "
    "and then exactly one fenced JSON block, for example:\n"
    '```json\n{"tool": "shell", "args": {"command": "nmap -sV -Pn <target>"}}\n```\n'
    'A tool call must use one of the available tools and only its documented arguments.'
)


def parse_action(text: str, *, allow_shell_fence: bool = True) -> ParseResult:
    """Extract the last valid action object from a model reply."""
    if not text or not text.strip():
        return ParseResult(action=None, error="the model returned an empty reply")
    text = _strip_ansi(text)

    payloads: list[tuple[str, int, int]] = []  # (json_text, start, end)
    for match in FENCE_RE.finditer(text):
        lang = (match.group(1) or "").lower()
        body = match.group(2).strip()
        if lang in JSON_FENCE_LANGS and body.startswith(("{", "[")):
            payloads.append((body, match.start(), match.end()))
    for match in TAG_RE.finditer(text):
        body = match.group(2).strip()
        if body:
            payloads.append((body, match.start(), match.end()))
    # Bare JSON objects anywhere in the message.
    for obj in _iter_json_objects(text):
        payloads.append((obj, text.find(obj), text.find(obj) + len(obj)))

    # Last valid action wins: models sometimes restate an earlier plan.
    for raw_payload, start, end in reversed(payloads):
        parsed = _loads_loose(raw_payload)
        action = _action_from_object(parsed)
        if action is None:
            continue
        thought = action.thought or _prose_outside(text, start, end)
        return ParseResult(
            action=Action(
                tool=action.tool,
                args=action.args,
                thought=thought,
                raw=raw_payload,
            ),
            thought=thought,
            raw=text,
        )

    if allow_shell_fence:
        shell = _shell_fence_command(text)
        if shell:
            thought = _strip_fences(text).strip()
            return ParseResult(
                action=Action(
                    tool="shell",
                    args={"command": shell},
                    thought=thought,
                    raw=text,
                ),
                thought=thought,
                raw=text,
            )

    return ParseResult(action=None, thought=_strip_fences(text).strip(), error=NO_ACTION_HINT, raw=text)


# --------------------------------------------------------------------------- #
# Object -> Action
# --------------------------------------------------------------------------- #
def _action_from_object(obj: Any) -> Action | None:
    if not isinstance(obj, dict):
        return None

    thought = ""
    for key in ("thought", "reasoning", "thinking", "plan", "why"):
        value = obj.get(key)
        if isinstance(value, str) and value.strip():
            thought = value.strip()
            break

    tool_obj = None
    for key in ("tool", "action", "name", "tool_name", "toolname", "function", "call"):
        if key in obj:
            tool_obj = obj[key]
            break
    if tool_obj is None:
        return None

    # {"tool": {"name": "shell", "args": {...}}}
    if isinstance(tool_obj, dict):
        nested_args = tool_obj.get("args") or tool_obj.get("arguments") or tool_obj.get("input") or {}
        tool_obj = tool_obj.get("name") or tool_obj.get("tool")
        if not isinstance(tool_obj, str):
            return None
        if isinstance(nested_args, dict) and not any(
            k in obj for k in ("args", "arguments", "input", "parameters")
        ):
            obj = {**obj, "args": nested_args}

    if not isinstance(tool_obj, str) or not tool_obj.strip():
        return None

    tool = _normalise_tool(tool_obj)
    args = _extract_args(obj, tool)
    args = _apply_shorthands(tool, args, obj)
    args = _apply_aliases(tool, args)
    if tool in {"submit_flag", "give_up"}:
        tool, args = _normalise_terminal(tool, args, obj)
    if tool == "__drop__":
        return None
    return Action(tool=tool, args=args, thought=thought)


def _normalise_tool(name: str) -> str:
    cleaned = name.strip().strip("\"'`").lower()
    cleaned = re.sub(r"[\s\-]+", "_", cleaned)
    cleaned = re.sub(r"^(the_|use_|call_|tool_)", "", cleaned)
    # Strip a namespace such as "functions.shell".
    cleaned = cleaned.rsplit(".", 1)[-1]
    return TOOL_ALIASES.get(cleaned, cleaned)


def _extract_args(obj: dict[str, Any], tool: str) -> dict[str, Any]:
    for key in ("args", "arguments", "input", "parameters", "params", "kwargs", "options"):
        value = obj.get(key)
        if isinstance(value, dict):
            return dict(value)
        if isinstance(value, str) and value.strip():
            # Args supplied as a JSON string.
            parsed = _loads_loose(value)
            if isinstance(parsed, dict):
                return dict(parsed)
    # Flat shape: everything that is not metadata belongs to the tool.
    return {k: v for k, v in obj.items() if k.lower() not in META_KEYS}


def _apply_shorthands(tool: str, args: dict[str, Any], obj: dict[str, Any]) -> dict[str, Any]:
    out = dict(args)
    shorthand = SHORTHANDS.get(tool)
    if not shorthand:
        return out
    for src, dst in shorthand.items():
        if dst not in out and src in out and src != dst:
            out[dst] = out[src]
    # Also lift shorthand keys that live at the top level of the object.
    for src, dst in shorthand.items():
        if dst not in out and src in obj and not isinstance(obj[src], dict):
            out[dst] = obj[src]
    return out


def _apply_aliases(tool: str, args: dict[str, Any]) -> dict[str, Any]:
    if tool == "http":
        for src, dst in (("url", "url"), ("uri", "url"), ("body", "data"), ("content", "data")):
            if dst not in args and src in args:
                args[dst] = args[src]
    if tool == "note_add":
        for src in ("text", "note", "content", "message"):
            if src in args and not args.get("text"):
                args["text"] = args[src]
                break
    return args


def _normalise_terminal(tool: str, args: dict[str, Any], obj: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """A model saying "finish" may mean "here is the flag" or "I give up"."""
    if tool == "submit_flag":
        flag = args.get("flag")
        if isinstance(flag, list):
            flag = flag[0] if flag else None
        if not flag:
            # Look for anything flag-shaped in the raw object.
            for value in obj.values():
                if isinstance(value, str) and re.search(r"\{[^}]{1,200}\}", value):
                    flag = _first_flag_like(value)
                    if flag:
                        break
        if flag and isinstance(flag, str):
            return "submit_flag", {"flag": flag.strip(), "evidence": str(args.get("evidence", ""))}
        return "give_up", {"reason": str(args.get("reason") or obj.get("reason") or "model finished")}
    return tool, args


def _first_flag_like(text: str) -> str | None:
    match = re.search(r"[A-Za-z0-9_]{2,20}\{[^}\n]{1,200}\}", text)
    return match.group(0) if match else None


# --------------------------------------------------------------------------- #
# Payload scanning helpers
# --------------------------------------------------------------------------- #
def _loads_loose(payload: str) -> Any:
    payload = payload.strip()
    for candidate in (payload, _trim_to_object(payload)):
        if not candidate:
            continue
        try:
            return json.loads(candidate)
        except (json.JSONDecodeError, ValueError):
            pass
        try:
            # Python-dict style with single quotes, True/False, trailing commas.
            value = ast.literal_eval(candidate)
            if isinstance(value, (dict, list)):
                return value
        except (ValueError, SyntaxError, MemoryError, RecursionError):
            pass
        # Last resort: repair the two most common JSON sins.
        repaired = re.sub(r",\s*([}\]])", r"\1", candidate)
        repaired = repaired.replace("'", '"')
        try:
            return json.loads(repaired)
        except (json.JSONDecodeError, ValueError):
            continue
    return None


def _trim_to_object(text: str) -> str:
    start = text.find("{")
    if start == -1:
        return ""
    end = _match_brace(text, start)
    return text[start : end + 1] if end else ""


def _iter_json_objects(text: str):
    """Yield balanced-brace substrings, skipping those inside string literals."""
    i = 0
    n = len(text)
    while i < n:
        if text[i] == "{":
            end = _match_brace(text, i)
            if end is not None:
                yield text[i : end + 1]
                i = end + 1
                continue
        i += 1


def _match_brace(text: str, start: int) -> int | None:
    depth = 0
    quote = ""
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def _prose_outside(text: str, start: int, end: int) -> str:
    if start < 0:
        return _strip_fences(text).strip()
    return _strip_fences(text[:start] + "\n" + text[end:]).strip()


def _strip_fences(text: str) -> str:
    return FENCE_RE.sub(lambda m: "" if (m.group(1) or "").lower() in {"json", "tool", "action"} else m.group(0), text)


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)


def _shell_fence_command(text: str) -> str | None:
    """Fallback: a trailing ```bash block containing one command."""
    fences = [
        m for m in FENCE_RE.finditer(text) if (m.group(1) or "").lower() in SHELL_FENCE_LANGS
    ]
    if not fences:
        return None
    last = fences[-1]
    body = "\n".join(line for line in last.group(2).splitlines() if line.strip())
    if not body.strip() or len(body) > 4000:
        return None
    # Only trust it when it is the tail of the message (the model is issuing it).
    if text[last.end() :].strip():
        return None
    # Strip a leading shell prompt such as "$ nmap ..." or "# nmap ...".
    return re.sub(r"^\s*[$#>]\s*", "", body).strip()


# --------------------------------------------------------------------------- #
# Tool-call formatting (used when talking back to the model)
# --------------------------------------------------------------------------- #
def format_action(action: Action) -> str:
    return json.dumps({"tool": action.tool, "args": action.args}, ensure_ascii=False)
