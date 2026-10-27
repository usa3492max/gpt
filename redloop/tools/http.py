"""The ``http`` tool: a first-class HTTP client for web challenges."""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from .base import Tool, ToolContext, ToolResult, strip_ansi, truncate

MAX_BODY_CHARS = 40_000

INTERESTING_HEADERS = (
    "server",
    "x-powered-by",
    "content-type",
    "location",
    "set-cookie",
    "content-length",
    "x-frame-options",
    "content-security-policy",
    "www-authenticate",
    "x-flag",
    "x-debug",
    "x-backend-server",
    "via",
    "allow",
)


class HttpTool(Tool):
    name = "http"
    summary = (
        "Make an HTTP(S) request and see status, headers and body. Handles redirects and "
        "self-signed certificates. Prefer this over curl for web work: it is cleaner and "
        "lets you set methods, bodies and headers."
    )
    args = {
        "url": "absolute URL, including scheme (http://target/login.php)",
        "method": "HTTP method, default GET (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH)",
        "headers": 'optional object, e.g. {"Cookie": "session=abc"}',
        "data": "optional raw request body string (form-encoded data works)",
        "json": "optional object sent as a JSON body",
        "timeout": "optional seconds, default 30",
        "follow_redirects": "optional bool, default true",
    }
    required = ("url",)

    async def run(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        started = time.monotonic()
        url = str(args.get("url", "")).strip().strip("<>\"'")
        if not url:
            return ToolResult(False, "missing url")
        if not url.lower().startswith(("http://", "https://")):
            url = "http://" + url

        parsed = urlparse(url)
        host = parsed.hostname or ""
        decision = ctx.guard.authorize(host)
        if not decision.allowed:
            return ToolResult(False, f"BLOCKED: {decision.reason}", blocked=True)

        method = str(args.get("method") or "GET").upper().strip()
        headers = _coerce_headers(args.get("headers"))
        data = args.get("data")
        json_body = args.get("json")
        if json_body is None:
            json_body = args.get("body") if isinstance(args.get("body"), (dict, list)) else None
        if data is not None and not isinstance(data, (str, bytes)):
            data = json.dumps(data)
        follow = _as_bool(args.get("follow_redirects"), True)
        timeout = _as_float(args.get("timeout"), 30.0)

        if ctx.dry_run:
            return ToolResult(True, f"[dry-run] would send {method} {url}", meta={"dry_run": True})

        history: list[str] = []
        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=timeout,
                follow_redirects=follow,
                headers={"User-Agent": "redloop/0.1 (+authorised assessment)"},
            ) as client:
                response = await client.request(
                    method, url, headers=headers, content=data, json=json_body
                )
                for redirect in response.history:
                    history.append(f"{redirect.status_code} {redirect.url}")
        except httpx.TimeoutException:
            return ToolResult(
                False,
                f"{method} {url} timed out after {timeout:.0f}s. Is the service up, and is the "
                "port actually reachable from this container?",
                duration=time.monotonic() - started,
            )
        except httpx.HTTPError as exc:
            return ToolResult(
                False,
                f"{method} {url} failed: {type(exc).__name__}: {exc}\n"
                "Check the scheme, host, port and that the service is listening.",
                duration=time.monotonic() - started,
            )

        body_text, saved = _render_body(response, ctx)
        body_text, truncated = truncate(body_text, MAX_BODY_CHARS)
        lines = [f"{method} {url} -> {response.status_code} {response.reason_phrase} "
                 f"({len(response.content)} bytes, {response.elapsed.total_seconds():.2f}s)"]
        if history:
            lines.append("redirects: " + " -> ".join(history))
        lines.append("")
        for key in INTERESTING_HEADERS:
            if key in response.headers:
                lines.append(f"{key}: {response.headers[key]}")
        cookie_header = response.headers.get("set-cookie")
        if cookie_header:
            lines.append(f"set-cookie: {cookie_header}")
        lines.append("")
        lines.append("----- BODY -----")
        lines.append(body_text if body_text.strip() else "[empty body]")
        if saved:
            lines.append(f"[full body saved to {saved}]")
        return ToolResult(
            ok=True,
            output="\n".join(lines),
            meta={
                "status": response.status_code,
                "url": str(response.url),
                "headers": dict(response.headers),
                "bytes": len(response.content),
                "content_type": response.headers.get("content-type", ""),
                "saved": str(saved) if saved else "",
            },
            truncated=truncated,
            duration=time.monotonic() - started,
        )


def _render_body(response: httpx.Response, ctx: ToolContext) -> tuple[str, Any]:
    content_type = response.headers.get("content-type", "").lower()
    raw = response.content
    if any(kind in content_type for kind in ("text", "json", "xml", "html", "javascript")):
        try:
            text = raw.decode(response.encoding or "utf-8", errors="replace")
        except (LookupError, TypeError):
            text = raw.decode("utf-8", errors="replace")
        return strip_ansi(text), None
    saved = None
    if raw:
        try:
            saved = ctx.loot_dir / f"step{ctx.step:03d}_body.bin"
            saved.write_bytes(raw[: 5 * 1024 * 1024])
        except OSError:
            saved = None
    preview = raw[:512].hex(" ")
    return f"[binary body, {len(raw)} bytes]\nhex preview: {preview}", saved


def _coerce_headers(raw: Any) -> dict[str, str]:
    if raw is None:
        return {}
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                raw = parsed
            else:
                raw = dict(
                    line.split(":", 1) for line in raw.splitlines() if ":" in line
                )
        except (json.JSONDecodeError, ValueError):
            raw = dict(line.split(":", 1) for line in raw.splitlines() if ":" in line)
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items()}


def _as_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _as_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
