#!/usr/bin/env python3
"""A deliberately vulnerable web application, for exercising redloop.

It is a toy, but it has the shape of a real CTF web challenge:

  /                     index page with a hint in an HTML comment
  /robots.txt           advertises /admin/ and /backup/
  /login.php            SQL injection in the username field
  /admin/               requires the role=admin cookie issued by the bypass
  /backup/              directory listing, exposes config.php.bak
  /backup/config.php.bak  database credentials
  /api/notes?user=N     IDOR: any user id returns that user's notes
  /flag.txt             403 unless you are admin

Never expose this to an untrusted network. It is intentionally broken.
"""

from __future__ import annotations

import html
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG = os.environ.get("FLAG", "flag{r3dl00p_l4b_sql1_byp4ss}")
DB_PASSWORD = "Sup3rS3cretDBPass!"
BIND = os.environ.get("LAB_BIND", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8080"))
QUIET = os.environ.get("LAB_QUIET", "") == "1"

NOTES = {
    "1": "admin's note: staging deploy key rotates on Fridays.",
    "2": "alice's note: my password is Tr0ub4dor&3 (please rotate it).",
}

INDEX = """<!doctype html>
<html><head><title>Acme Intranet</title></head>
<body>
<h1>Acme Intranet</h1>
<p>Internal portal. <a href="/login.php">Staff login</a></p>
<p><a href="/api/notes?user=1">My notes</a></p>
<!-- TODO(dev): remove /backup/ before go-live, it still has the old config dump -->
<!-- build: apache 2.4.49, php 7.4 -->
</body></html>
"""

LOGIN = """<!doctype html>
<html><body>
<h1>Staff login</h1>
<form method="post" action="/login.php">
  <label>Username <input name="username"></label>
  <label>Password <input name="password" type="password"></label>
  <button type="submit">Log in</button>
</form>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.49"
    sys_version = "(Unix)"
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------------ utils
    def log_message(self, fmt: str, *args) -> None:
        if not QUIET:
            sys.stderr.write("[lab] %s %s\n" % (self.address_string(), fmt % args))

    def _send(self, code: int, body: str, content_type: str = "text/html; charset=utf-8",
              headers: dict[str, str] | None = None) -> None:
        payload = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Powered-By", "PHP/7.4.3")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _is_admin(self) -> bool:
        cookie = self.headers.get("Cookie", "")
        return "role=admin" in cookie.replace(" ", "")

    # ----------------------------------------------------------------- routing
    def do_GET(self) -> None:
        path = urllib.parse.urlparse(self.path)
        route = path.path.rstrip("/") or "/"
        query = urllib.parse.parse_qs(path.query)

        if route == "/":
            return self._send(200, INDEX)
        if route == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n",
                              "text/plain")
        if route == "/login.php":
            return self._send(200, LOGIN)
        if route == "/admin":
            if self._is_admin():
                return self._send(
                    200,
                    "<html><body><h1>Admin panel</h1>"
                    f"<p>Welcome back, administrator.</p><p>Flag: <code>{FLAG}</code></p>"
                    "</body></html>",
                )
            return self._send(403, "<html><body><h1>403 Forbidden</h1></body></html>")
        if route == "/backup":
            listing = "".join(
                f'<li><a href="/backup/{html.escape(name)}">{html.escape(name)}</a></li>'
                for name in ("config.php.bak", "db.sql.gz", "notes.txt")
            )
            return self._send(200, f"<html><body><h1>Index of /backup</h1><ul>{listing}</ul></body></html>")
        if route == "/backup/config.php.bak":
            return self._send(
                200,
                "<?php\n"
                "// TODO: remove this backup before production\n"
                "define('DB_HOST', 'localhost');\n"
                "define('DB_USER', 'acme_app');\n"
                f"define('DB_PASS', '{DB_PASSWORD}');\n"
                "define('DB_NAME', 'acme');\n"
                "// admin panel is at /admin/ and checks the role cookie\n",
                "text/plain",
            )
        if route == "/api/notes":
            user = (query.get("user") or ["1"])[0]
            note = NOTES.get(user)
            if not note:
                return self._send(404, '{"error":"not found"}', "application/json")
            return self._send(
                200,
                '{"user_id": "%s", "note": "%s"}' % (user, note),
                "application/json",
            )
        if route == "/flag.txt":
            if self._is_admin():
                return self._send(200, FLAG, "text/plain")
            return self._send(403, "403 Forbidden: administrators only")
        return self._send(404, "<html><body><h1>404 Not Found</h1></body></html>")

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:
        path = urllib.parse.urlparse(self.path).path.rstrip("/")
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(min(length, 65536)).decode("utf-8", "replace")
        form = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
        if path != "/login.php":
            return self._send(404, "not found", "text/plain")

        username = form.get("username", "")
        password = form.get("password", "")
        # The "database query": deliberately injectable.
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        lowered = username.lower().replace(" ", "")
        injected = any(
            token in lowered
            for token in ("'or", "or'1'='1", "'or1=1", "or1=1--", "'or1=1#", "admin'--", "'or1=1")
        ) or "' or " in username.lower()
        legit = username == "admin" and password == DB_PASSWORD

        if injected or legit:
            return self._send(
                302,
                "<html><body>Redirecting to <a href='/admin/'>/admin/</a></body></html>",
                headers={"Location": "/admin/", "Set-Cookie": "role=admin; Path=/"},
            )
        self.log_message("login query: %s", query)
        return self._send(401, "<html><body><h1>Invalid credentials</h1>"
                               f"<p>Query: {html.escape(query)}</p></body></html>")


def serve(bind: str = BIND, port: int = PORT) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((bind, port), Handler)
    print(f"[lab] Acme Intranet listening on http://{bind}:{port}  (flag: {FLAG})", flush=True)
    return httpd


def main() -> int:
    httpd = serve()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[lab] shutting down")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
