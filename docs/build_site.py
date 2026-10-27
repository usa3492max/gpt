#!/usr/bin/env python3
"""Build the static documentation site in ``docs/`` for GitHub Pages.

The site is generated from the same markdown that ships with the repository, so
the published pages cannot drift from the source.  Run it after editing
``README.md``, ``docs/architecture.md`` or ``docs/CHANGELOG.md``:

    make site          # or: python docs/build_site.py

Output (all inside ``docs/``, served from the branch root's ``/docs`` folder):

    index.html        landing page
    docs.html         README
    architecture.html docs/architecture.md
    changelog.html    release notes
    assets/style.css  one stylesheet, no CDN, no web fonts
    .nojekyll         stop GitHub from reprocessing the output
"""

from __future__ import annotations

import html
import re
import shutil
import sys
from pathlib import Path

try:
    import markdown
except ImportError:  # pragma: no cover
    sys.exit("build_site.py needs the markdown package: pip install -e '.[docs]'")

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
SITE_URL = "https://usa3492max.github.io/gpt/"
REPO_URL = "https://github.com/usa3492max/gpt"
RELEASE_URL = f"{REPO_URL}/releases/tag/v0.1.0"
VERSION = "0.1.0"

#: page key -> (source markdown, output file, <title>, description)
PAGES = {
    "docs": (
        ROOT / "README.md",
        "docs.html",
        "Documentation",
        "Install, configure and run Panther gpt — providers, flags, guardrails and troubleshooting.",
    ),
    "architecture": (
        DOCS / "architecture.md",
        "architecture.html",
        "Architecture",
        "How the loop, action protocol, guardrails, memory and compaction fit together.",
    ),
    "changelog": (
        DOCS / "CHANGELOG.md",
        "changelog.html",
        "Changelog",
        f"Release notes for Panther gpt v{VERSION}.",
    ),
}

NAV = [
    ("index.html", "Overview"),
    ("docs.html", "Docs"),
    ("architecture.html", "Architecture"),
    ("changelog.html", "Changelog"),
]

#: The terminal preview on the landing page.  It is abridged from a real run against
#: the bundled lab (see docs/CHANGELOG.md); the box drawing is generated so the
#: borders always line up at the chosen width.
BOX_WIDTH = 76


def _box(title: str, lines: list[str], width: int = BOX_WIDTH) -> str:
    """Draw a rounded panel the way the rich renderer does."""
    head = f"\u256d\u2500 {title} "
    top = head + "\u2500" * max(0, width - len(head) - 1) + "\u256e"
    body = [
        "\u2502 " + line.ljust(width - 4) + " \u2502" for line in lines
    ]
    bottom = "\u2570" + "\u2500" * (width - 2) + "\u256f"
    return "\n".join([top, *body, bottom])


def _feed_preview() -> str:
    return "\n".join(
        [
            " STEP 9/40  04:12  \u00b7  18.3k tok  \u00b7  $0.041  \u00b7  1 finding",
            _box(
                "thinking",
                [
                    "robots.txt advertises /admin/ and /backup/, and the index has a",
                    "TODO comment about an old config dump. The backup directory is the",
                    "cheapest thing to check and it usually holds exactly what",
                    "developers forget.",
                ],
            ),
            "   \u25b6 http  GET http://lab-web:8080/backup/config.php.bak",
            _box(
                "output \u00b7 0.0s",
                [
                    "GET .../backup/config.php.bak -> 200 OK (239 bytes)",
                    "x-powered-by: PHP/7.4.3",
                    "----- BODY -----",
                    "define('DB_USER', 'acme_app');",
                    "define('DB_PASS', 'Sup3rS3cretDBPass!');",
                ],
            ),
            _box(
                "finding",
                ["HIGH  Exposed configuration backup discloses database credentials"],
            ),
            _box(
                "thinking",
                [
                    "Those credentials and the role-cookie hint are a real weakness, so I",
                    "will record the finding, then test the login form for injection",
                    "before considering any brute force.",
                ],
            ),
            "   \u25b6 http  POST http://lab-web:8080/login.php",
            "   body=username=admin%27+OR+1%3D1+--+-&password=x",
            _box(
                "output \u00b7 0.1s",
                [
                    "POST .../login.php -> 200 OK (136 bytes)",
                    "set-cookie: role=admin; Path=/",
                    "----- BODY -----",
                    "<h1>Admin panel</h1> Welcome back, administrator.",
                    "Flag: <code>flag{r3dl00p_l4b_sql1_byp4ss}</code>",
                ],
            ),
        ]
    )


FEED = _feed_preview()

INSTALL = "make build && cp .env.example .env && make run TARGET=10.10.11.42"

FEATURES = [
    (
        "One action per turn",
        "The model reasons, emits one JSON tool call, and the runtime returns the real "
        "observation. Nothing is fabricated and every step is reviewable.",
    ),
    (
        "Any model, one protocol",
        "Claude, or anything OpenAI-compatible: Ollama, LM Studio, vLLM, OpenRouter, Groq. "
        "A tolerant parser absorbs the sloppy JSON weaker models produce.",
    ),
    (
        "Survives its own context",
        "A scratchpad plus automatic fact extraction keeps a 60-step run coherent. "
        "Compaction is deterministic and spends no API calls.",
    ),
    (
        "Live feed you can read",
        "Thinking panels, a per-action spinner and a flag banner in the terminal — plus "
        "plain text for logs and a JSON stream for your own tooling.",
    ),
    (
        "Guardrails that fire",
        "Scope is enforced on every host, URL and Python snippet; destructive commands are "
        "blocked. Refusals go back to the model so it adapts instead of retrying.",
    ),
    (
        "A report, not a log",
        "Every run leaves report.md, results.json, the full transcript, the replayable feed "
        "and raw loot in one directory.",
    ),
]

MODELS = [
    ("Anthropic", "`-p anthropic`", "claude-sonnet-4-5", "Recommended. Prompt caching on long runs."),
    ("OpenAI", "`-p openai`", "gpt-4.1", "Any chat-completions model."),
    ("Ollama", "`-p ollama`", "qwen2.5-coder:14b", "Local, no API cost."),
    ("LM Studio", "`-p lmstudio`", "local-model", "Desktop local server."),
    ("OpenRouter", "`-p openrouter`", "anthropic/claude-sonnet-4.5", "Many models, one key."),
    ("Groq", "`-p groq`", "llama-3.3-70b-versatile", "Fast hosted inference."),
    ("Anything else", "`-p custom --base-url`", "your model", "Any /v1/chat/completions endpoint."),
    ("Offline demo", "`-p mock`", "mock-rulebased", "No key, no GPU. Exercises the loop."),
]

CATEGORIES = [
    ("Web", "Headers and source first, then robots/backup/.git; gobuster and ffuf for paths and "
            "parameters; SQLi, LFI, SSTI, XXE, SSRF, JWT alg:none, IDOR, upload filters."),
    ("Pwn", "file, checksec, strings, readelf, objdump, r2/gdb; pwntools against the remote; "
            "ret2win, format strings, ret2libc, then read /flag.txt."),
    ("Crypto", "Identifies the scheme, then attacks the weakness — small e, shared modulus, "
               "Wiener, XOR/repeating key, predictable RNG — with sympy and z3."),
    ("Forensics", "file, exiftool, strings, binwalk -e, foremost, pngcheck, zsteg, tshark for "
                  "pcaps, john and hashcat for hashes."),
    ("Reversing", "objdump, radare2, gdb; derives the key or accepted input from the check logic."),
    ("Privesc / AD", "sudo -l, SUID/SGID, capabilities, cron, writable services, credential "
                     "reuse, smbclient, enum4linux, ldapsearch."),
]


# --------------------------------------------------------------------------- #
# markdown
# --------------------------------------------------------------------------- #
def render_markdown(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    body = markdown.markdown(
        text,
        extensions=["fenced_code", "tables", "toc", "sane_lists", "attr_list"],
        extension_configs={"toc": {"permalink": False, "toc_depth": "2-3"}},
    )
    return _rewrite_links(body)


def _rewrite_links(body: str) -> str:
    """Point repository-relative links at the generated pages."""
    replacements = {
        # Repository files that are not published as pages live on GitHub.
        'href="LICENSE"': f'href="{REPO_URL}/blob/main/LICENSE"',
        'href="docs/architecture.md"': 'href="architecture.html"',
        'href="README.md"': 'href="docs.html"',
        'href="./README.md"': 'href="docs.html"',
        'href="docs/CHANGELOG.md"': 'href="changelog.html"',
        'href="CHANGELOG.md"': 'href="changelog.html"',
        'href="docs/architecture.md#': 'href="architecture.html#',
        f'href="{REPO_URL}/blob/main/docs/architecture.md"': 'href="architecture.html"',
    }
    for old, new in replacements.items():
        body = body.replace(old, new)
    # Links to repo files that do not exist as pages go to GitHub.
    body = re.sub(
        r'href="((?:labs|tests|redloop|docker)/[^"]*)"',
        lambda m: f'href="{REPO_URL}/blob/main/{m.group(1)}"',
        body,
    )
    body = body.replace(f'href="{REPO_URL}/blob/main/docs/', 'href="')
    # External links open in a new tab.
    body = re.sub(
        r'<a href="(https?://[^"]+)"',
        lambda m: (
            m.group(0)
            if "usa3492max.github.io" in m.group(1)
            else f'<a href="{m.group(1)}" target="_blank" rel="noopener"'
        ),
        body,
    )
    return body


def toc_from(body: str) -> str:
    """A compact table of contents from the page's h2 headings."""
    items = []
    for match in re.finditer(r'<h2 id="([^"]+)">(.*?)</h2>', body, re.DOTALL):
        anchor, label = match.group(1), re.sub(r"<[^>]+>", "", match.group(2))
        items.append(f'<li><a href="#{anchor}">{html.escape(label.strip())}</a></li>')
    if not items:
        return ""
    return (
        '<nav class="toc" aria-label="On this page"><p class="toc-title">On this page</p><ul>'
        + "".join(items)
        + "</ul></nav>"
    )


# --------------------------------------------------------------------------- #
# templates
# --------------------------------------------------------------------------- #
def page(
    *,
    title: str,
    description: str,
    body: str,
    active: str = "",
    wide: bool = False,
    footer_note: str = "",
) -> str:
    nav_html = "".join(
        f'<a class="{"active" if href == active else ""}" href="{href}">{label}</a>'
        for href, label in NAV
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} · Panther gpt</title>
<meta name="description" content="{html.escape(description)}">
<meta name="color-scheme" content="dark">
<meta property="og:type" content="website">
<meta property="og:title" content="{html.escape(title)} · Panther gpt">
<meta property="og:description" content="{html.escape(description)}">
<meta property="og:url" content="{SITE_URL}">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%230c0d12'/%3E%3Ctext x='16' y='23' font-family='monospace' font-size='18' fill='%23ff4d5e' text-anchor='middle'%3E%3E%3C/text%3E%3C/svg%3E">
<link rel="stylesheet" href="assets/style.css">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="topbar">
  <div class="topbar-inner">
    <a class="brand" href="index.html"><span class="mark">&gt;</span> Panther <span class="thin">gpt</span></a>
    <nav class="sitenav" aria-label="Site">{nav_html}
      <a href="{REPO_URL}" target="_blank" rel="noopener">GitHub<span class="ext">↗</span></a>
    </nav>
  </div>
</header>
<main id="main" class="{'wide' if wide else 'narrow'}">
{body}
</main>
<footer class="footer">
  <p>{footer_note or "Panther gpt — autonomous offensive-security agent."}</p>
  <p class="muted">
    v{VERSION} · MIT licensed ·
    <a href="{REPO_URL}" target="_blank" rel="noopener">source</a> ·
    <a href="{RELEASE_URL}" target="_blank" rel="noopener">release</a> ·
    <a href="changelog.html">changelog</a>
  </p>
  <p class="disclaimer">
    For authorised security testing only: systems you own, or systems you have explicit written
    permission to test. Unauthorised access to computer systems is a criminal offence in most
    jurisdictions. You are responsible for what you point it at.
  </p>
</footer>
</body>
</html>
"""


def doc_page(source: Path, output: str, title: str, description: str, active: str) -> str:
    body_md = render_markdown(source)
    toc = toc_from(body_md)
    content = f"""
<article class="prose">
{toc}
{body_md}
</article>
"""
    return page(
        title=title,
        description=description,
        body=content,
        active=active,
        wide=True,
        footer_note="Generated from the repository's own markdown — it cannot drift from the source.",
    )


def landing() -> str:
    feature_cards = "".join(
        f'<div class="card"><h3>{html.escape(name)}</h3><p>{html.escape(text)}</p></div>'
        for name, text in FEATURES
    )
    model_rows = "".join(
        f"<tr><td>{html.escape(name)}</td><td><code>{html.escape(flag)}</code></td>"
        f"<td><code>{html.escape(default)}</code></td><td>{html.escape(note)}</td></tr>"
        for name, flag, default, note in MODELS
    )
    category_rows = "".join(
        f"<tr><td><strong>{html.escape(name)}</strong></td><td>{html.escape(text)}</td></tr>"
        for name, text in CATEGORIES
    )
    body = f"""
<section class="hero">
  <p class="eyebrow"><span class="dot"></span> v{VERSION} · released as “Panther gpt”</p>
  <h1>An autonomous pentest agent that<br><span class="accent">thinks out loud.</span></h1>
  <p class="lede">
    Give it a target. It enumerates, forms hypotheses, exploits and reports — choosing its own
    next step with a large language model, and streaming its reasoning to your terminal while it
    works. Built for CTF challenges and authorised engagements.
  </p>
  <div class="cta">
    <a class="btn primary" href="docs.html">Read the docs</a>
    <a class="btn" href="{REPO_URL}" target="_blank" rel="noopener">View source</a>
    <a class="btn" href="changelog.html">Release notes</a>
  </div>
  <div class="install">
    <span class="prompt">$</span><code>{html.escape(INSTALL)}</code>
    <span class="install-note">one command installs the Kali toolchain and the agent</span>
  </div>
</section>

<section class="terminal-wrap">
  <div class="terminal" role="img" aria-label="Captured terminal output from a real run">
    <div class="terminal-bar"><span class="light r"></span><span class="light y"></span><span class="light g"></span><span class="terminal-title">redloop — live feed</span></div>
    <pre>{html.escape(FEED)}</pre>
  </div>
  <p class="caption">
    Abridged from a real run against the bundled practice lab: it found an exposed config backup,
    pulled the database password out of it, recorded the finding, then turned a login-form SQL
    injection into the flag — eleven steps, no guidance.
  </p>
</section>

<section class="band">
  <h2>Built for unattended runs, not demos</h2>
  <div class="grid">{feature_cards}</div>
</section>

<section class="band">
  <h2>How it works</h2>
  <ol class="steps">
    <li><strong>Brief</strong> — target, scope, objective and any hints you give it.</li>
    <li><strong>Reason</strong> — the model reads the last observation and picks one hypothesis.</li>
    <li><strong>Act</strong> — exactly one tool call, checked against scope and a blast-radius blocklist.</li>
    <li><strong>Observe</strong> — real output comes back, facts and flags are scraped into the scratchpad.</li>
    <li><strong>Adapt</strong> — repeats are suppressed, unproductive streaks trigger a change of tactic.</li>
  </ol>
  <p class="muted">
    The state block is rebuilt for every call, so the model always sees current facts rather than a
    stale copy of its own history — which is what keeps a sixty-step run coherent.
    <a href="architecture.html">Read the architecture →</a>
  </p>
</section>

<section class="band">
  <h2>Bring your own model</h2>
  <div class="table-scroll">
    <table class="models">
      <thead><tr><th>Provider</th><th>Flag</th><th>Default model</th><th>Notes</th></tr></thead>
      <tbody>{model_rows}</tbody>
    </table>
  </div>
  <p class="muted">
    Local models reach the container through <code>host.docker.internal</code>, which the Makefile
    and compose file already wire up.
  </p>
</section>

<section class="band">
  <h2>CTF categories it has tradecraft for</h2>
  <div class="table-scroll">
    <table class="categories">
      <thead><tr><th>Category</th><th>Approach</th></tr></thead>
      <tbody>{category_rows}</tbody>
    </table>
  </div>
</section>

<section class="band safety">
  <h2>Guardrails, stated plainly</h2>
  <ul class="checks">
    <li><strong>Authorisation gate.</strong> A non-loopback target requires <code>--i-am-authorized</code>.</li>
    <li><strong>Scope enforcement.</strong> Every hop, URL and Python snippet is checked. Private
        ranges are allowed because CTF boxes pivot; arbitrary public hosts are refused with the
        exact <code>--scope</code> you would need.</li>
    <li><strong>Blast radius.</strong> <code>mkfs</code>, <code>dd of=/dev/sd*</code>,
        <code>rm -rf /</code>, fork bombs and shutdown are blocked outright.</li>
    <li><strong>Hard limits.</strong> Per-command timeouts, a 2 MB output cap, step, time and cost
        budgets, and a stop after eight unproductive actions.</li>
    <li><strong>Full audit trail.</strong> Every action, refusal and observation is written to the
        run directory.</li>
  </ul>
  <p class="muted">
    This is not a sandbox for untrusted code — the container is the boundary — and it is not a
    substitute for a human tester's judgement. Findings are the agent's observations; verify them
    before disclosure.
  </p>
</section>

<section class="band final">
  <h2>Try it in five minutes</h2>
  <pre class="snippet"><span class="c"># 1. build the image (Kali toolchain + agent)</span>
make build

<span class="c"># 2. add a key — or use Ollama, or skip it with -p mock</span>
cp .env.example .env
$EDITOR .env

<span class="c"># 3. run against something you are allowed to test</span>
make run TARGET=10.10.11.42

<span class="c"># no target yet? watch it solve the bundled lab</span>
make demo</pre>
  <div class="cta">
    <a class="btn primary" href="docs.html">Get started</a>
    <a class="btn" href="{RELEASE_URL}" target="_blank" rel="noopener">Download v{VERSION}</a>
  </div>
</section>
"""
    return page(
        title="Autonomous pentest agent",
        description=(
            "Panther gpt — an LLM-driven autonomous penetration-testing agent. Enumerates, "
            "exploits and reports on its own, with a live terminal feed, scope guardrails and "
            "support for Claude or local models."
        ),
        body=body,
        active="index.html",
        wide=True,
        footer_note="Panther gpt · redloop — autonomous offensive-security agent.",
    )


# --------------------------------------------------------------------------- #
# build
# --------------------------------------------------------------------------- #
def build() -> list[Path]:
    written: list[Path] = []
    (DOCS / "assets").mkdir(parents=True, exist_ok=True)

    written.append(_write(DOCS / "index.html", landing()))
    for key, (source, output, title, description) in PAGES.items():
        if not source.exists():
            print(f"  skip {source} (missing)")
            continue
        written.append(
            _write(
                DOCS / output,
                doc_page(source, output, title, description, active=output),
            )
        )

    css_src = DOCS / "assets" / "style.css"
    if not css_src.exists():
        print(f"  warning: {css_src} is missing; the site will be unstyled")
    written.append(_write(DOCS / ".nojekyll", ""))
    written.append(_write(DOCS / "404.html", _not_found()))
    return written


def _not_found() -> str:
    body = """
<section class="hero">
  <p class="eyebrow"><span class="dot"></span> 404</p>
  <h1>That path does not exist.</h1>
  <p class="lede">The page you asked for is not here. Try the overview, the documentation or the
  release notes.</p>
  <div class="cta">
    <a class="btn primary" href="index.html">Overview</a>
    <a class="btn" href="docs.html">Documentation</a>
    <a class="btn" href="changelog.html">Changelog</a>
  </div>
</section>
"""
    return page(
        title="Not found",
        description="Page not found.",
        body=body,
        footer_note="Panther gpt — autonomous offensive-security agent.",
    )


def _write(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    size = len(content)
    print(f"  wrote {path.relative_to(ROOT)} ({size:,}B)")
    return path


def main() -> int:
    print("building the site in docs/")
    if not (DOCS / "assets" / "style.css").exists():
        print("  note: expected docs/assets/style.css to exist")
    written = build()
    shutil.rmtree(DOCS / "__pycache__", ignore_errors=True)
    print(f"done: {len(written)} files")
    print(f"  local preview: python -m http.server --directory docs 8000")
    print(f"  published at : {SITE_URL}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
