# Changelog

All notable changes to Panther gpt (package and CLI name: `redloop`).

## v0.1.0 — "Panther gpt"

*Released 2026-10-27*

First public release: a complete, self-contained automated penetration-testing agent.

```bash
make build && cp .env.example .env     # add ANTHROPIC_API_KEY
make run TARGET=10.10.11.42
```

### Highlights

- **One action per turn.** The model reasons, emits one JSON tool call, the runtime executes it
  and returns the real observation plus a refreshed state block. No fabricated output, ever.
- **Any model.** Anthropic Claude, or anything OpenAI-compatible — Ollama, LM Studio, vLLM,
  OpenRouter, Groq. Also `--provider mock`, an offline rule-based model for demos and CI.
- **Survives its own context window.** A durable scratchpad plus automatic fact extraction
  (ports/versions, URLs, credentials, hashes, HTML comments) feeds every prompt, so long runs
  don't collapse into amnesiac loops. Compaction is deterministic and costs no API calls.
- **Live feed.** Rich terminal view with thinking panels, per-action spinner, findings and a
  flag banner; `--plain` for logs/CI; `--json-feed` for piping into your own tooling.
- **Reports, not logs.** Every run writes `report.md`, `results.json`, `transcript.jsonl`,
  `feed.txt`, `memory.json` and captures full output in `loot/`.
- **CTF-ready toolchain.** Kali image with nmap, gobuster/ffuf, sqlmap, hydra, netcat, binwalk,
  exiftool, gdb/radare2, wordlists and Python libs (pwntools, z3, sympy, pycryptodome). The
  system prompt carries per-category tradecraft: web, pwn, crypto, forensics, reversing, privesc.

### Guardrails

- Authorisation gate — non-loopback targets require `--i-am-authorized`.
- Scope enforcement on every IP, URL, host flag, positional host **and** Python snippet, with
  private ranges allowed (CTF pivots) and public off-scope hosts refused with the exact `--scope`
  needed. Refusals go back to the model so it adapts.
- Blast-radius blocklist: `mkfs`, `dd of=/dev/sd*`, `rm -rf /`, fork bombs, shutdown.
- Hard limits: per-command timeouts, 2 MB output cap, step/time/cost budgets, repeat suppression,
  and a stop after 8 unproductive actions.

### Adding

- Ten tools: `shell`, `python`, `http`, `read_file`, `write_file`, `list_dir`, `note_add`,
  `record_finding`, `submit_flag`, `give_up`.
- Provider clients for the Anthropic Messages API (with prompt caching) and any
  OpenAI-compatible `/v1/chat/completions` endpoint, plus a retry wrapper with backoff and an
  error taxonomy the loop can react to.
- A deliberately vulnerable practice lab (`labs/web`) and `make demo` to watch the whole loop
  work without an API key.

### Verification

- 226 tests pass (protocol parsing across 29 real model output formats, guardrails, every tool,
  both provider wire protocols via mocked HTTP, the agent loop, rendering, CLI).
- End-to-end: the agent autonomously solves the bundled lab — port discovery → SQL injection
  bypass → flag — through the real tool and report pipeline.
- `ruff` clean; wheel verified in a clean virtualenv.

### Known gaps

- The Docker image build was not executed in the development sandbox (no daemon available), so
  `make build` is the first thing to try on your machine.
- Only the web category has been empirically validated. Pwn/crypto/forensics support is real
  (tools in the image, tradecraft in the prompt) but unproven until pointed at a challenge.
- Prebuilt wheels are not attached to the GitHub release because binary uploads are blocked in
  the environment the release was cut from; `python -m build` reproduces the identical wheel.

---

## Roadmap

- Web dashboard for watching runs in a browser (local only, token-gated).
- Pivot support: consider discovered internal hosts as first-class scope.
- Metasploit and impacket integration behind an opt-in flag.
- Recorded run replay from `transcript.jsonl`.
