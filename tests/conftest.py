"""Shared fixtures: a scripted model, a temporary run directory and a local lab."""

from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import pytest

from redloop.config import Config
from redloop.events import EventBus, NullRenderer
from redloop.llm.base import Completion, LLMClient, Message, Usage


class ScriptedClient(LLMClient):
    """A model that replays prepared replies (or calls a function to decide)."""

    name = "scripted"
    model = "scripted-1"

    def __init__(self, replies: list[Any]) -> None:
        self.replies = list(replies)
        self.calls: list[list[Message]] = []

    async def complete(self, system, messages, *, max_tokens=2048, temperature=0.7):
        self.calls.append([Message(m.role, m.content) for m in messages])
        if not self.replies:
            reply = '{"tool": "give_up", "args": {"reason": "script exhausted"}}'
        else:
            reply = self.replies.pop(0)
        if callable(reply):
            reply = reply(messages)
        return Completion(text=reply, usage=Usage(input_tokens=100, output_tokens=20))


def action(tool: str, **args) -> str:
    import json

    return "Thinking about it.\n\n```json\n" + json.dumps({"tool": tool, "args": args}) + "\n```"


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    path = tmp_path / "run"
    path.mkdir()
    return path


@pytest.fixture
def config(tmp_path: Path) -> Config:
    cfg = Config(
        target="127.0.0.1",
        provider="mock",
        runs_dir=tmp_path / "runs",
        max_steps=8,
        max_minutes=5,
        command_timeout=20,
        authorized=True,
    )
    return cfg.finalize()


@pytest.fixture
def bus() -> tuple[EventBus, NullRenderer]:
    bus = EventBus()
    recorder = NullRenderer()
    bus.subscribe(recorder.handle)
    return bus, recorder


def free_port(start: int = 8100, end: int = 8999) -> int:
    for port in range(start, end):
        with socket.socket() as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no free port")


class _LabHandler(BaseHTTPRequestHandler):
    flag = "flag{test_lab}"
    hits: list[str] = []

    def log_message(self, *args):  # silence
        pass

    def do_GET(self):
        _LabHandler.hits.append(self.path)
        if self.path == "/":
            body = b"<html><body>index <a href='/login.php'>login</a></body></html>"
            self._send(200, body, "text/html")
        elif self.path == "/admin/":
            if "role=admin" in (self.headers.get("Cookie") or ""):
                self._send(200, f"<p>Flag: {self.flag}</p>".encode(), "text/html")
            else:
                self._send(403, b"forbidden", "text/html")
        elif self.path == "/robots.txt":
            self._send(200, b"Disallow: /admin/\n", "text/plain")
        elif self.path == "/binary":
            self._send(200, bytes(range(256)) * 4, "application/octet-stream")
        else:
            self._send(404, b"nope", "text/plain")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(min(length, 4096)).decode("utf-8", "replace")
        body = unquote(raw).lower()
        if "' or" in body or "or 1=1" in body or "or+1" in raw.lower():
            self._send(302, b"ok", "text/html",
                       {"Location": "/admin/", "Set-Cookie": "role=admin; Path=/"})
        else:
            self._send(401, b"bad credentials", "text/plain")

    def _send(self, code, body: bytes, content_type: str, headers: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def lab_server():
    port = free_port()
    _LabHandler.hits = []
    httpd = ThreadingHTTPServer(("127.0.0.1", port), _LabHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)
