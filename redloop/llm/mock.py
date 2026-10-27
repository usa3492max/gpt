"""A deterministic, rule-based stand-in for an LLM.

It exists so the whole agent — parsing, guardrails, tool execution, live feed,
report writing — can be exercised and demonstrated without an API key or a GPU.
It reacts to what it observes, so it behaves like a (very narrow) reasoning
model rather than replaying a fixed script.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .base import Completion, LLMClient, Message, Usage

FLAG_LIKE = re.compile(r"[A-Za-z0-9_]{2,20}\{[^}\n]{1,200}\}")
STATUS_LINE = re.compile(r"->\s*(\d{3})")


class MockClient(LLMClient):
    name = "mock"

    def __init__(self, target: str = "127.0.0.1", model: str = "mock-rulebased") -> None:
        self.target = target or "127.0.0.1"
        self.model = model
        self._calls = 0

    async def complete(
        self,
        system: str,
        messages: list[Message],
        *,
        max_tokens: int = 2048,
        temperature: float = 0.7,
    ) -> Completion:
        self._calls += 1
        history = _history(messages)
        last_output = _last_observation(messages)
        observed = "\n".join(m.content for m in messages if m.role == "user")
        usage = Usage(
            input_tokens=max(1, sum(len(m.content) for m in messages) // 4),
            output_tokens=120,
        )
        thought, action = self._decide(history, last_output, observed)
        text = f"{thought}\n\n```json\n{json.dumps(action)}\n```"
        return Completion(text=text, usage=usage, stop_reason="end_turn", model=self.model)

    # ------------------------------------------------------------------ logic
    def _decide(
        self, history: list[tuple[str, str]], last_output: str, observed: str
    ) -> tuple[str, dict[str, Any]]:
        ran_shell = [cmd for tool, cmd in history if tool == "shell"]
        ran_http = [url for tool, url in history if tool == "http"]
        ran_python = [code for tool, code in history if tool == "python"]
        noted = any(tool == "note_add" for tool, _ in history)
        found = any(tool == "record_finding" for tool, _ in history)
        ports = _open_ports(observed)
        web = _web_port(ports)
        base = f"http://{self.target}:{web}" if web else ""
        scanned = any("connect_ex" in code or "socket" in code for code in ran_python)

        flag = FLAG_LIKE.search(last_output)
        if flag:
            return (
                "The last response contains what looks like the flag. I'll submit it exactly as "
                "printed before doing anything else.",
                {"tool": "submit_flag", "args": {
                    "flag": flag.group(0),
                    "evidence": "found in the output of the previous action",
                }},
            )

        if not ran_shell and not scanned:
            return (
                "Starting with service discovery. A bounded version scan tells me what I am "
                "dealing with before I touch anything, and it is cheap to run.",
                {"tool": "shell", "args": {
                    "command": f"nmap -sV -Pn -T4 --top-ports 500 {self.target}",
                    "timeout": 240,
                }},
            )

        if not ports and ran_shell and not scanned:
            return (
                "nmap is not available in this container, so I'll fall back to a Python connect "
                "scan over the common port range. Same information, no dependency.",
                {"tool": "python", "args": {"code": _PORT_SCAN_SNIPPET.replace("__TARGET__", self.target)}},
            )

        if not ports:
            return (
                "Nothing responded anywhere in the scanned range, so the target is either down or "
                "firewalled from here. Repeating the scan will not change that; I'll stop and "
                "report the negative result.",
                {"tool": "give_up", "args": {
                    "reason": f"No TCP service responded on {self.target}; target appears filtered "
                              "or offline from this container.",
                }},
            )

        if web and not any(url.rstrip("/").endswith(f":{web}") for url in ran_http):
            return (
                f"Port {web} is open. I'll fetch the root page and read the headers and body for "
                "versions, links and hints before doing any guessing.",
                {"tool": "http", "args": {"url": f"{base}/"}},
            )

        if web and not noted:
            return (
                "Worth writing down what the stack looks like now, so it survives context "
                "compaction later.",
                {"tool": "note_add", "args": {
                    "title": "stack",
                    "text": f"Target {self.target} exposes HTTP on port {web}; version strings and "
                            "paths recorded as I find them.",
                }},
            )

        if web and not any("robots.txt" in url for url in ran_http):
            return (
                "robots.txt and other well-known files often leak the paths the developers did "
                "not want indexed. Cheap to check.",
                {"tool": "http", "args": {"url": f"{base}/robots.txt"}},
            )

        if web and not any("/admin" in url for url in ran_http):
            return (
                "There is no obvious login form on the index, so I'll probe the conventional "
                "admin path directly.",
                {"tool": "http", "args": {"url": f"{base}/admin/"}},
            )

        if web and not any("/backup" in url for url in ran_http):
            return (
                "A backup directory is advertised and it usually holds exactly the artefacts "
                "developers forget — config dumps, SQL exports, old source.",
                {"tool": "http", "args": {"url": f"{base}/backup/"}},
            )

        if web and not any("config.php.bak" in url for url in ran_http):
            return (
                "config.php.bak is served as plain text because the server does not map .bak to "
                "PHP, which means I can read the database credentials directly.",
                {"tool": "http", "args": {"url": f"{base}/backup/config.php.bak"}},
            )

        if web and not found:
            return (
                "Those credentials and the role-cookie comment are a real weakness, so I'll record "
                "the finding with the response as evidence before moving on.",
                {"tool": "record_finding", "args": {
                    "title": "Exposed configuration backup discloses database credentials",
                    "severity": "high",
                    "details": f"/backup/config.php.bak on port {web} is served as text and "
                               "contains the application's database password.",
                    "evidence": last_output[:800],
                    "remediation": "Remove backup files from the web root and block *.bak in the "
                                   "server configuration.",
                }},
            )

        if web and not any("/api/notes" in url for url in ran_http):
            return (
                "The API takes a user id straight from the query string. I'll request another "
                "user's notes to see whether authorisation is enforced.",
                {"tool": "http", "args": {"url": f"{base}/api/notes?user=2"}},
            )

        if web and not any("login.php" in url for url in ran_http):
            return (
                "The admin panel needs a role cookie. The login form is the only way in, so I'll "
                "test it with a classic SQL injection bypass before considering brute force.",
                {"tool": "http", "args": {
                    "url": f"{base}/login.php",
                    "method": "POST",
                    "data": "username=admin%27+OR+1%3D1+--+-&password=x",
                }},
            )

        if web and "role=admin" in last_output and not any(
            "Cookie" in url for url in ran_http
        ) and not any("/admin" in url for url in ran_http[-1:]):
            return (
                "The login bypass returned a role=admin cookie with a redirect. I'll replay the "
                "admin page with that cookie to reach the authenticated content.",
                {"tool": "http", "args": {
                    "url": f"{base}/admin/",
                    "headers": {"Cookie": "role=admin"},
                }},
            )

        return (
            "I have exhausted the cheap hypotheses for this target and I am not making progress. "
            "Rather than spin on the same ideas, I'll stop and report what I have so a human can "
            "pick it up.",
            {"tool": "give_up", "args": {
                "reason": "No further low-cost hypotheses after enumeration; see findings and notes.",
            }},
        )


def _history(messages: list[Message]) -> list[tuple[str, str]]:
    """(tool, primary argument) for every action already taken."""
    out: list[tuple[str, str]] = []
    for message in messages:
        if message.role != "assistant":
            continue
        for match in re.finditer(r"```json\s*(\{.*?\})\s*```", message.content, re.DOTALL):
            try:
                obj = json.loads(match.group(1))
            except ValueError:
                continue
            tool = str(obj.get("tool", ""))
            args = obj.get("args", {}) or {}
            primary = str(
                args.get("command")
                or args.get("url")
                or args.get("code")
                or args.get("path")
                or args.get("text")
                or args.get("flag")
                or args.get("reason")
                or ""
            )
            out.append((tool, primary))
    return out


def _last_observation(messages: list[Message]) -> str:
    """Only real tool output counts — never the engagement brief or the format hint."""
    for message in reversed(messages):
        if message.role != "user":
            continue
        text = message.content
        start = text.find("=== OBSERVATION")
        if start == -1:
            continue
        end = text.find("=== END OBSERVATION", start)
        return text[start:end] if end != -1 else text[start:]
    return ""


def _open_ports(text: str) -> dict[str, str]:
    ports: dict[str, str] = {}
    for match in re.finditer(r"(\d{1,5})/tcp\s+open\s+(\S*)", text):
        ports[match.group(1)] = match.group(2)
    return ports


NON_WEB_PORTS = {
    "21", "22", "23", "25", "53", "110", "111", "135", "139", "143", "389", "445", "465",
    "587", "636", "993", "995", "1433", "1521", "2049", "3306", "3389", "5432", "5900",
    "5985", "5986", "6379", "8081x", "9200x", "11211", "27017",
}


def _web_port(ports: dict[str, str]) -> str:
    for port in ("80", "8080", "8000", "8888", "3000", "5000", "443", "8443"):
        if port in ports:
            return port
    for port, service in ports.items():
        if "http" in service.lower():
            return port
    # Unknown service on an unusual port: HTTP is the most likely thing to try.
    for port in ports:
        if port not in NON_WEB_PORTS:
            return port
    return ""


def _same_target(url: str, target: str) -> bool:
    return target in url


_PORT_SCAN_SNIPPET = '''\
import socket
from concurrent.futures import ThreadPoolExecutor

TARGET = "__TARGET__"


def probe(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.25)
    try:
        return port if sock.connect_ex((TARGET, port)) == 0 else None
    except OSError:
        return None
    finally:
        sock.close()


with ThreadPoolExecutor(max_workers=256) as pool:
    open_ports = sorted(p for p in pool.map(probe, range(1, 10001)) if p)

for port in open_ports:
    print(f"{port}/tcp open unknown")
if not open_ports:
    print("no open TCP ports found in 1-10000")
'''
