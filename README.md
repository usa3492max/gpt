# redloop

**An autonomous penetration-testing agent.** Point it at a target; it enumerates, forms
hypotheses, exploits, and reports — deciding its own next step with a large language model and
streaming its reasoning to your terminal as it goes.

```bash
make build
cp .env.example .env          # add your ANTHROPIC_API_KEY (or use Ollama)
make run TARGET=10.10.11.42
```

That is the whole setup. Everything else — Kali toolchain, wordlists, Python libraries — lives
in the container.

```
╭───────────────────────────────────────────────────╮
│  redloop  ·  autonomous offensive-security agent  │
╰───────────────────────────────────────────────────╯
target    10.10.11.42
objective capture the flag
model     anthropic · claude-sonnet-4-5
limits    40 steps · 90 min
run dir   runs/20261027-141503_10.10.11.42

 STEP 7/40  04:12  ·  18.3k tok  ·  $0.041  ·  1 finding
╭─ thinking ─────────────────────────────────────────────────────────────────╮
│ The 302 to /admin/ only happens with a role cookie, and the response body │
│ echoes my payload — that is textbook SQL injection in the login query.    │
│ Instead of brute forcing credentials, I'll confirm it with a UNION and     │
│ pull the users table directly.                                            │
╰────────────────────────────────────────────────────────────────────────────╯
  ▶ http  POST http://10.10.11.42/login.php  body=username=admin' UNION SELECT 1,2,3-- -
╭─ output · 0.4s ────────────────────────────────────────────────────────────╮
│ POST .../login.php -> 200 OK (1462 bytes)                                  │
│ set-cookie: role=admin; Path=/                                             │
│ ───── BODY ─────                                                           │
│ <h1>Admin panel</h1> Welcome back, administrator.  id=1 login=admin ...    │
╰────────────────────────────────────────────────────────────────────────────╯
```

---

## Contents

- [Why it is different](#why-it-is-different)
- [Quick start](#quick-start)
- [Choosing a model](#choosing-a-model)
- [Command-line reference](#command-line-reference)
- [Watching it work](#watching-it-work)
- [What comes out of a run](#what-comes-out-of-a-run)
- [How it works](#how-it-works)
- [CTF playbook](#ctf-playbook)
- [Scope and safety](#scope-and-safety)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Legal](#legal)

---

## Why it is different

Most "AI pentest" projects are a thin loop around `nmap` that asks a model for a command and
hops it will work. redloop is built for long autonomous runs against real targets:

| | |
|---|---|
| **One action per turn, real observations** | The model never sees fabricated tool output. Every step is executed, captured and fed back verbatim (truncated at the edges, full copy on disk). |
| **Works with any model** | Claude, GPT, or a local 7B model through Ollama. The protocol is plain JSON in a fenced block, and the parser tolerates the sloppy variants real models produce. |
| **Survives its own context window** | A durable scratchpad plus automatic fact extraction (ports, URLs, versions, credentials, hashes) means a 60-step run does not degrade into an amnesiac loop. History is compacted deterministically, not by hoping the model remembers. |
| **Guardrails that actually fire** | Scope enforcement on every host, IP and URL — including inside Python snippets — and a blocklist for commands that would destroy the container. Refusals are explained to the model so it adapts instead of retrying. |
| **Anti-loop mechanics** | Repeated actions are suppressed, unproductive streaks trigger a strategy nudge, and the run stops rather than burning your budget. |
| **A report, not a log** | Every run writes `report.md`, `results.json`, the full transcript, the raw loot and a replay of the feed. |
| **Live, watchable, pipeable** | Colour terminal feed with a spinner per action; `--plain` for logs; `--json-feed` for tooling. |

---

## Quick start

### Requirements

- Docker (Engine 20.10+ or Docker Desktop) with the daemon running
- An API key for Claude, **or** Ollama for local models, **or** nothing at all to try the
  bundled demo target

### 1. Build

```bash
git clone <this repo> && cd redloop
make build
```

First build pulls the Kali base image and installs the toolchain — expect 5–10 minutes.
For a much smaller image (nmap, curl, nc, gobuster, python only):

```bash
make build TOOLSET=slim
```

### 2. Configure

```bash
cp .env.example .env
$EDITOR .env        # set ANTHROPIC_API_KEY=sk-ant-...
```

### 3. Run

```bash
make run TARGET=10.10.11.42
```

`make run` prints an authorisation notice and passes `--i-am-authorized` for you. To run the
container directly:

```bash
docker run --rm -it --env-file .env -v "$PWD/runs:/app/runs" \
  --add-host host.docker.internal:host-gateway \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  redloop:latest --target 10.10.11.42 --i-am-authorized
```

### 4. No target? Try the demo

There is a deliberately vulnerable web app in `labs/web`. It has an SQL injection in the login
form, an exposed config backup, an IDOR and a role-cookie bypass.

```bash
make demo          # builds the lab, then lets the agent solve it with the offline demo model
```

The demo uses `--provider mock`, a small rule-based model that needs no API key or GPU. It
exists to prove the plumbing and to let you watch the interface; it is not an LLM. Swap in a
real model with `make run TARGET=lab-web PROVIDER=ollama MODEL=qwen2.5-coder:14b`.

---

## Choosing a model

### Claude (recommended)

Best reasoning-per-step, which matters because every step costs a real action. Set in `.env`:

```bash
REDLOOP_PROVIDER=anthropic
REDLOOP_MODEL=claude-sonnet-4-5
ANTHROPIC_API_KEY=sk-ant-...
```

Override per run: `make run TARGET=... ARGS="--model claude-opus-4-1 --max-tokens 4096"`.

Claude runs use prompt caching on the system prompt, which cuts the input cost of long runs
substantially (the cache hit shows up in the run summary as `cached` tokens).

### Local models through Ollama

```bash
# on the host
ollama serve
ollama pull qwen2.5-coder:14b      # or llama3.1:8b, mistral-nemo, deepseek-coder-v2

make run TARGET=10.10.11.42 PROVIDER=ollama MODEL=qwen2.5-coder:14b
```

Inside Docker, `localhost` is the container, so the agent maps `OLLAMA_HOST` to
`host.docker.internal` automatically (`docker-compose.yml` and `make run` already add the host
gateway). If you run the container by hand, include `--add-host host.docker.internal:host-gateway`.

Fully containerised models:

```bash
docker compose --profile local up -d ollama     # publishes 11434 on the host
make ollama-pull MODEL=qwen2.5-coder:14b
make run TARGET=127.0.0.1 PROVIDER=ollama MODEL=qwen2.5-coder:14b
```

The published port means the agent still reaches Ollama through
`host.docker.internal:11434`, so no extra configuration is needed.

Local model notes:

- 7B–14B models solve web and recon challenges reasonably; they get lost on multi-stage
  binaries. Give them more steps and a smaller `--max-output-chars` (3000) to keep the context
  clean.
- Set `REDLOOP_CONTEXT_WINDOW` to the real window (8192 or 32768). The agent compacts when it
  approaches 55% of that, and a wrong value is the usual cause of "context exceeded" errors.
- Larger is not always better: a coder-tuned model that follows the JSON protocol beats a
  70B general model that replies in prose.

### Everything else

Any endpoint that speaks `POST /v1/chat/completions` works:

| Provider | Flag | Default endpoint |
|---|---|---|
| Anthropic | `-p anthropic` | `https://api.anthropic.com` |
| OpenAI | `-p openai` | `https://api.openai.com/v1` |
| Ollama | `-p ollama` | `http://localhost:11434/v1` |
| LM Studio | `-p lmstudio` | `http://localhost:1234/v1` |
| OpenRouter | `-p openrouter` | `https://openrouter.ai/api/v1` |
| Groq | `-p groq` | `https://api.groq.com/openai/v1` |
| Anything else | `-p custom --base-url https://host/v1` | you supply it |
| Offline demo | `-p mock` | none |

Credentials come from `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `OPENROUTER_API_KEY`,
`GROQ_API_KEY`, or `--api-key`. Check your setup before a real run:

```bash
make doctor        # toolchain, scope, endpoint reachability, and a real model round-trip
```

---

## Command-line reference

```
redloop --target <ip|host|cidr|url> [options]
```

### Engagement

| Flag | Meaning |
|---|---|
| `-t, --target` | Target IP, hostname, CIDR or URL (a URL is reduced to its host) |
| `-o, --objective` | What success looks like. Default: capture any flag / assess the target |
| `-s, --scope` | Additional authorised hosts, CIDRs or `*.wildcards` |
| `--seed-notes` | Context to hand the agent up front (credentials, hints, intended path) |
| `--flag-regex` | Extra regex for recognising flags (repeatable) |
| `--multi-flag` | Keep going after the first flag (challenges with several) |
| `--i-am-authorized` | Confirm authorisation (required for non-loopback targets) |

### Model

| Flag | Meaning |
|---|---|
| `-p, --provider` | Provider preset (see table above) |
| `-m, --model` | Model name |
| `--api-key` | Credential, instead of the environment |
| `--base-url` | Override the endpoint |
| `--temperature` | Sampling temperature (default 0.7) |
| `--max-tokens` | Max reply tokens per step (default 2048) |
| `--context-window` | Model context size; drives compaction |

### Limits

| Flag | Default | Meaning |
|---|---|---|
| `--max-steps` | 40 | Number of actions |
| `--max-minutes` | 90 | Wall-clock budget |
| `--max-cost` | none | Stop at this estimated API spend (USD) |
| `--command-timeout` | 300 | Seconds before a single command is killed |
| `--max-output-chars` | 6000 | How much of each output reaches the model |

### Guardrails

| Flag | Default | Meaning |
|---|---|---|
| `--scope-check / --no-scope-check` | on | Refuse actions against hosts outside scope |
| `--allow-private-networks / --no-...` | on | Allow RFC1918 ranges (CTF pivots) |
| `--i-am-authorized` | off | Authorisation acknowledgement |

### Output

| Flag | Meaning |
|---|---|
| `--runs-dir` | Where run directories go (default `./runs`) |
| `--run-dir` | Write this run to a specific directory |
| `--resume DIR` | Continue an earlier run, restoring its scratchpad |
| `--plain` | Line-oriented, no colour (for `docker logs`, CI, grep) |
| `--json-feed` | One JSON object per event on stdout |
| `-v, --verbose` | Print full tool output |
| `-q, --quiet` | Only steps, actions and final results |
| `--no-color` | Disable colour but keep the layout |

### Other

`--dry-run` (ask the model for one action, execute nothing), `--print-prompt` (dump the exact
system prompt and brief), `--doctor [--check-model]`, `--list-tools`, `--env`, `--version`.

Exit codes: `0` flag captured or completed · `1` error · `2` usage/configuration ·
`3` a limit was reached (steps, time or cost) · `130` interrupted.

### Examples

```bash
# a CTF box, more steps, a shell as the objective
make run TARGET=10.10.11.42 ARGS="--max-steps 80 --objective 'get a shell and read /root/flag.txt'"

# web engagement with an API host in scope too
make run TARGET=app.example.com ARGS="-s api.example.com other.example.com --max-cost 3"

# a challenge that hides the flag somewhere specific
make run TARGET=10.10.11.42 ARGS="--seed-notes 'creds: admin:Summer2024  login /admin'"

# a binary exploitation challenge: point the model at the files
make run TARGET=10.10.11.42 ARGS="--objective 'download /challenge, exploit it on port 31337'"

# watch the plan without touching anything
make run TARGET=10.10.11.42 ARGS="--dry-run"

# pipe the feed into your own tooling
make run TARGET=10.10.11.42 ARGS="--json-feed" | jq -r 'select(.event=="action") | .preview'

# continue yesterday's run
redloop --resume runs/20261026-183012_10.10.11.42 --i-am-authorized
```

---

## Watching it work

The feed is the point: you see the model's reasoning, the exact action, and the output it
reacted to.

- **Rich mode** (default on a TTY): panels for thinking, a spinner while a long tool runs,
  findings highlighted as they are recorded, a banner the moment a flag appears.
- **`--plain`**: timestamped lines, no ANSI — what lands in `feed.txt` and `docker logs`.
- **`--json-feed`**: every event as JSON, for `jq`, dashboards or your own UI. Events are
  `session_start`, `step_start`, `thought`, `action`, `observation`, `finding`, `flag`,
  `blocked`, `warning`, `error`, `retrying`, `compaction`, `session_end`.
- **`--quiet`** for a summary-only run; **`--verbose`** to read every line of output.

Press `Ctrl-C` at any time: the agent stops, writes the report and exits `130`.

---

## What comes out of a run

```
runs/20261027-141503_10.10.11.42/
├── report.md          # the deliverable: summary, findings, evidence, actions, reproduction
├── results.json       # the same, machine readable
├── transcript.jsonl   # every event, timestamped
├── feed.txt           # exactly what the terminal showed
├── memory.json        # scratchpad state (used by --resume)
├── notes.md           # notes and findings in markdown
├── work/              # scripts the agent wrote and executed
└── loot/              # full command output, HTTP bodies, captured files
```

The report opens with an executive summary and a findings table, then per-finding details with
the captured evidence, the attack surface it mapped, a numbered log of every action, and the
command line to reproduce the run.

---

## How it works

```
        ┌────────────────────────────────────────────────────────────┐
        │  brief + state (facts, notes, findings, recent actions)     │
        └───────────────────────────┬────────────────────────────────┘
                                    ▼
                    ┌──────────────────────────────┐
                    │  model (Claude/Ollama/...)   │
                    │   prose + one JSON action    │
                    └───────────────┬──────────────┘
                                    ▼
                    ┌──────────────────────────────┐
      refusal ◄─────┤  guardrails: scope, blast    │
                    │  radius, repeat detection    │
                    └───────────────┬──────────────┘
                                    ▼
        ┌───────────────────────────────────────────────────────────┐
        │ tools: shell · python · http · files · notes · findings   │
        └───────────────┬───────────────────────────────┬───────────┘
                        ▼                               ▼
              ┌──────────────────┐            ┌──────────────────┐
              │ observation      │            │ events: feed,     │
              │ (+fact scraping) │            │ transcript, report│
              └──────────────────┘            └──────────────────┘
```

The loop asks for exactly one action per turn, executes it, and returns the observation with a
fresh state block. That single-action discipline is what makes the transcript reviewable and
the guardrails enforceable.

**Tools** (10, documented to the model in the system prompt):

| Tool | Purpose |
|---|---|
| `shell` | Any command in the container — nmap, curl, gobuster, sqlmap, hydra, nc, openssl |
| `python` | Run a snippet: socket exploits, crypto, parsing, pwntools |
| `http` | HTTP client with methods, headers, bodies, redirects, cookie handling |
| `read_file` / `write_file` / `list_dir` | Challenge files, exploit scripts, loot |
| `note_add` | Durable scratchpad that survives compaction |
| `record_finding` | Structured finding with severity, evidence, remediation |
| `submit_flag` / `give_up` | Declare success, or stop cleanly |

**Context management.** Facts are scraped from every observation (ports and versions, URLs,
HTML comments, emails, hashes, credentials). When the estimated prompt exceeds ~55% of the
model's window, the middle of the conversation is replaced with a deterministic summary built
from that scratchpad — no extra model call, no information loss that matters.

**Anti-loop mechanics.** Identical actions are suppressed after two attempts with an explanation
of what changed since; three unproductive steps add an explicit "change tactic" instruction to
the state block; eight end the run as `exhausted` rather than spending your budget.

More detail, including the exact prompt structure, lives in [docs/architecture.md](docs/architecture.md).

---

## CTF playbook

The system prompt carries category-specific tradecraft; the image carries the tools. What that
means in practice:

| Category | What the agent reaches for |
|---|---|
| **Web** | Header/JS/source review first, then robots/sitemap/backup/`.git`; gobuster/ffuf for paths and parameters; SQLi (manual, then sqlmap), LFI, SSTI, XXE, SSRF, command injection, JWT `alg:none`, IDOR, upload filters, default creds |
| **Pwn** | `file`, `checksec`, `strings`, `readelf`, `objdump`, `r2`/`gdb`; pwntools for remote interaction; ret2win, format strings, ret2libc, shellcode; reads `/flag.txt` once it has execution |
| **Crypto** | Identifies the scheme first (openssl, python), then attacks the weakness — small `e`, shared modulus, Wiener, XOR/repeating key, predictable RNG, classical ciphers, hash length extension — with sympy/z3 for the algebra |
| **Forensics / stego** | `file`, `exiftool`, `strings`, `binwalk -e`, `foremost`, `pngcheck`, `zsteg`/`steghide`, `tshark` for pcaps, john/hashcat for hashes |
| **Reversing** | `objdump -d`, radare2, gdb, python/Java/.NET decompilation; derives the key or the accepted input from the check logic |
| **Priv-esc / AD** | `sudo -l`, SUID/SGID, capabilities, cron, writable services, kernel versions, credential reuse, smbclient/enum4linux/ldapsearch |

Give it the objective and the files, not the method:

```bash
make run TARGET=10.10.11.42 ARGS="--objective 'the download endpoint serves a binary; exploit it remotely and read /flag.txt'"
```

If a challenge needs a file you have locally, mount it into the container and mention the path
in `--seed-notes`.

---

## Scope and safety

This tool sends real exploits at real machines. Built-in guardrails:

1. **Authorisation gate.** A non-loopback target requires `--i-am-authorized` (or
   `REDLOOP_AUTHORIZED=1`). Without it the run refuses to start.
2. **Scope enforcement.** Every command, URL and Python snippet is scanned for destinations.
   The target and `--scope` entries are in bounds; private ranges are allowed by default (CTF
   boxes pivot into internal networks, and the agent's own tooling is on loopback); arbitrary
   public hosts are refused. A refusal is fed back to the model with instructions to adapt.
3. **Blast-radius protection.** `mkfs`, `dd of=/dev/sda`, `rm -rf /`, fork bombs, shutting down
   the host and similar commands are blocked outright — they are never needed to solve a
   challenge and are usually a model hallucination.
4. **Bounded execution.** Every command has a timeout, output is capped at 2 MB per action
   (with the head and tail shown), and the whole run is bounded by steps, wall clock and
   optionally cost.
5. **Complete audit trail.** Every action, refusal and observation is written to the run
   directory.

What it is **not**: a safe sandbox for untrusted code (the container is the boundary — the agent
runs as root because real tooling needs it), a substitute for a human tester's judgement, or a
licence to scan the internet. Do not add `--privileged`, and do not mount your home directory
into it while pointing it at a hostile target.

Limitations worth knowing:

- Findings are the agent's observations. Verify before you disclose or remediate.
- The agent will not invent a path it cannot see: a challenge that needs a specific tool not in
  the image needs `make shell` and a package install, or an image rebuild.
- Long, noisy scans (`-p-` on a filtered host) eat steps. Bounded scans with `--min-rate` are
  usually better, and the prompt says so.
- Very small local models produce malformed actions; the parser recovers, but a 3B model is
  going to be slow and shallow. Start at 14B for autonomous work.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `ANTHROPIC_API_KEY is not set` | Put it in `.env` (copy `.env.example`), export it, or pass `--api-key` |
| `401 ... invalid x-api-key` | Wrong or revoked key; check `make doctor` |
| `! Docker is not installed` | Install Docker, or run locally: `make venv && source .venv/bin/activate` |
| `model call failed: HTTP 404` | Wrong `--base-url` (usually needs `/v1`) or the model is not pulled |
| Ollama unreachable inside Docker | Add `--add-host host.docker.internal:host-gateway`, and make sure Ollama listens on `0.0.0.0` (`OLLAMA_HOST=0.0.0.0 ollama serve`) |
| `context length exceeded` | Set `--context-window` to the model's real window, or lower `--max-output-chars` |
| Every scan says "filtered" | Missing capabilities: add `--cap-add NET_RAW --cap-add NET_ADMIN` |
| Agent loops on the same idea | Increase `--max-steps`, give `--seed-notes` with a hint, or use a stronger model |
| `NET_ADMIN is not granted` on start | Same as above; nmap falls back to connect scans without it |
| Colours look wrong in CI | `--plain` or `--json-feed` |

`make doctor` checks all of this in one shot, including a real round-trip to the model.

---

## Development

```bash
make venv                 # local virtualenv with dev dependencies
source .venv/bin/activate
redloop --help
make test                 # 226 tests, no network required
make lint                 # ruff
```

Layout:

```
redloop/
├── cli.py            argument parsing, wiring, exit codes
├── agent.py          the loop, limits, compaction, reporting hooks
├── protocol.py       tolerant action parser (JSON/XML/dicts/shell fences)
├── prompts.py        system prompt, brief, state block, nudges
├── context.py        token accounting and deterministic compaction
├── memory.py         scratchpad, fact extraction, flag detection
├── safety.py         scope guard and blast-radius blocklist
├── render.py         rich / plain / JSON renderers
├── report.py         report.md and results.json
├── transcript.py     transcript.jsonl and feed.txt
├── doctor.py         environment checks
├── llm/              anthropic, openai-compatible, retry, mock
└── tools/            shell, python, http, files, notes, findings, control
labs/web/             deliberately vulnerable practice target
tests/                226 tests covering the parser, guardrails, tools, loop and CLI
```

Adding a tool: subclass `Tool` in `redloop/tools/`, declare `name`, `summary`, `args` and
`required`, implement `async def run(args, ctx)`, then register it in
`redloop/tools/__init__.py`. The prompt, CLI help and parser aliases pick it up automatically.

---

## Legal

redloop is for authorised security testing only — systems you own, or systems you have explicit
written permission to test. Unauthorised access to computer systems is a criminal offence in
most jurisdictions. You are responsible for what you point it at. The authors accept no
liability for misuse or damage.

MIT licensed. See [LICENSE](LICENSE).
