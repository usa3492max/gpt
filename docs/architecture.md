# Architecture

This document explains how redloop is put together, why the pieces are separated the way they
are, and what to change when you extend it.

## Design constraints

1. **The model is unreliable.** Any protocol that assumes well-formed output will fail on the
   first local model you try. Parsing must be forgiving, and the loop must recover from a bad
   turn without losing the run.
2. **The context window is finite.** A 40-step run produces far more text than any model can
   hold. State has to live outside the conversation.
3. **Autonomy means unattended failure.** A run may last an hour with nobody watching, so
   limits, loop detection and guardrails must be structural rather than best-effort.
4. **One action per turn.** Multiple actions per turn make the transcript unreadable, break
   guardrail accounting and frustrate plan-level reasoning.

## Module map

| Module | Responsibility | Depends on |
|---|---|---|
| `cli.py` | Parse args, build config, wire bus/renderer/transcript/client/agent, exit codes | everything |
| `config.py` | Dataclass config, provider presets, env overlay, validation, pricing | — |
| `events.py` | Synchronous fan-out bus and the `Event` type | — |
| `agent.py` | The loop: limits, model call, parse, execute, learn, compact, finalise | protocol, prompts, tools, safety, memory, report |
| `protocol.py` | `parse_action`: model reply → `Action` | — |
| `prompts.py` | System prompt, brief, state block, observation/nudge formatting | tools (help text) |
| `context.py` | Token estimation, alternation repair, deterministic compaction | prompts |
| `memory.py` | Notes/findings/flags, fact extraction, digests, persistence | — |
| `safety.py` | `ScopeGuard`: host extraction/authorisation, destructive-command blocklist | config |
| `tools/` | Ten tools plus the sandboxed process runner | safety, memory |
| `llm/` | Provider clients, retry wrapper, offline mock | — |
| `render.py` | Rich / plain / JSON views of the event stream | events, tools |
| `report.py`, `transcript.py` | Durable artefacts | memory, config |
| `doctor.py` | Pre-flight checks | config, llm |

The dependency rule is: **the agent never prints and the renderer never executes.** Everything
crosses the boundary as an event, which is why the same run can be drawn richly, logged plainly,
streamed as JSON, or driven headlessly in tests.

## The loop, precisely

```
for step in 1..max_steps:
    stop if: stop requested | flag captured (and stop_on_flag) |
             time budget spent | cost budget spent | 8 unproductive actions
    state     = state_block(facts, findings, notes, stuck counter, clock)
    messages  = compact(messages, budget = token_budget - len(state))
    request   = alternating(messages + [state])
    reply     = client.complete(system_prompt, request)      # retries, backoff
    parsed    = parse_action(reply)
    if not parsed:      append nudge; continue
    if unknown tool:    append tool list; continue
    if seen twice:      append "you already did this"; continue
    result    = tool.execute(args)                            # guardrails inside
    scrape facts and flags from result.output
    append observation to messages
    if tool signalled flag/give_up: break
```

Three properties matter here.

**The system prompt is static.** No step counter, no clock, no target-specific text. Everything
volatile rides on the final user message. This is what makes provider-side prompt caching work:
the cached prefix is identical on every turn of a run.

**History is append-only between compactions.** Only observations and replies are stored.
Fresh state is generated per call and *not* stored, so the transcript stays small and the model
always sees current facts rather than a stale copy.

**Refusals are inputs.** A blocked action returns a `ToolResult` with a readable reason, which
becomes the observation. The model is expected to change plan; the repeat detector makes
retrying pointless anyway.

## The action protocol

The model is asked for prose followed by exactly one fenced JSON block:

````
The login form echoes my quote, so it is probably injectable.

```json
{"tool": "shell", "args": {"command": "sqlmap -u http://10.0.0.5/login.php --data 'u=1' --batch"}}
```
````

`parse_action` accepts, in order of preference and taking the *last* valid one:

1. Fenced blocks tagged `json`, `yaml`, `tool`, `action`, or untagged.
2. `<action>…</action>`, `<tool_call>…</tool_call>`, `<json>…</json>` tags.
3. Bare JSON objects anywhere in the text (balanced-brace scan that respects string literals).
4. Python dict literals (`ast.literal_eval`), then a repair pass for trailing commas and
   single quotes.
5. A trailing fenced `bash` block as `{"tool": "shell"}` — only if it ends the message.

Argument handling is equally forgiving: `args` / `arguments` / `input` / `parameters` (object or
JSON string), flat shorthand (`{"tool":"shell","command":"ls"}`), nested function objects
(`{"tool":{"name":"shell","args":{…}}}`), tool aliases (`bash`, `sh`, `curl`, `finish`,
`done`…), namespaced names (`functions.shell`) and case/spacing noise.

Two terminal behaviours are normalised: `finish`/`done` with a flag becomes `submit_flag`, and
without one becomes `give_up`. Models treat "I'm done" and "here is the answer" interchangeably
and the protocol should not lose the flag because of it.

Every failure mode produces a specific nudge listing the real tool names and the expected
format — the parser's error text is part of the prompt.

## Guardrails

`ScopeGuard` has two independent jobs.

**Authorisation.** Build a candidate set of destinations from a command line:

- dotted-quad literals (with optional CIDR) anywhere;
- URLs (any scheme);
- `user@host` forms;
- `host:port` forms;
- values of destination flags (`--url`, `--host`, `--target`, `-u`, `-h` for nikto/whatweb);
- positional arguments, but only for a narrow list of tools where a bare positional really is
  a host (nmap, masscan, nc, ssh, smbclient, …). Flags known to take non-host values
  (`hydra -l admin`, `-P pass.txt`) are skipped so usernames and wordlists are not mistaken for
  targets.

Each candidate is then authorised: explicit target or `--scope` entry (including CIDR and
`*.wildcard`), loopback, private range, or infrastructure host (the model API, package mirrors)
pass. Anything else public is refused with the exact `--scope` invocation that would allow it.
Hostnames are resolved (2s budget, cached) and re-checked by address.

Python snippets get the same treatment on IPs and URLs, because a snippet can open its own
sockets. This is a heuristic, not a sandbox; the container is the sandbox.

**Blast radius.** A blocklist of catastrophic patterns (`mkfs`, `dd of=/dev/sd*`, `rm -rf /`,
system-directory wipes, fork bombs, shutdown/reboot, deleting the agent's own install). None of
these are ever needed to solve a challenge; they are almost always a hallucination or a prompt
injection succeeding.

Risky-but-legitimate patterns (reverse shells, hydra, sqlmap, `curl | sh`) are recorded so a
human reviewing the feed can see them; they are allowed because they are the job.

## Memory and compaction

`Memory` holds notes, findings, flags, attempts, and a `FactStore`. The fact extractor runs on
every observation and picks out:

- open ports with service and version strings (including nmap's column layout);
- URLs, hostnames, emails, hashes;
- credentials in `user: pass` and `user = admin password = x` shapes;
- HTML comments (where CTF hints live);
- software versions, which are the input to CVE reasoning.

The digest of that store — not the transcript — is the agent's long-term memory. It is injected
into every state block, so a model that has forgotten everything still knows what has been
found, and it is the source of the report's "attack surface" section.

Compaction triggers at 55% of `context_window` (configurable). It keeps the brief, replaces the
middle with a deterministic summary (flags, facts, findings, notes, recent actions), keeps the
last few exchanges, then repairs role alternation. If the result still does not fit, the tail
shrinks; as a last resort only the brief and summary remain. A model call is never spent on
summarising, so compaction cannot fail or cost money.

## Rendering

`EventBus` is synchronous and swallows listener exceptions (they are recorded in `bus.errors`),
so a broken renderer cannot break a run. Renderers:

- `RichRenderer` — panels, rules, a spinner started on `action` and stopped on the next event,
  hidden when not a TTY or when `--quiet`.
- `PlainRenderer` — timestamped lines; also used to write `feed.txt`.
- `JsonRenderer` — one object per event for `jq` and dashboards.

Because `Transcript` subscribes a `PlainRenderer` writing to a file, the on-disk feed is
guaranteed to be exactly what a terminal would have shown.

## Providers

`LLMClient` is a two-method interface (`complete`, `aclose`). `AnthropicClient` speaks
`/v1/messages` with `cache_control` on the system prompt and converts native `tool_use` blocks
into the JSON protocol. `OpenAIClient` speaks `/v1/chat/completions` and covers OpenAI, Ollama,
LM Studio, vLLM, OpenRouter and Groq; it handles reasoning models (`max_completion_tokens`, no
temperature), SSE responses from local servers that stream anyway, and `tool_calls`.

HTTP status codes are mapped onto a small taxonomy — auth, rate limit (with `Retry-After`),
context overflow, server error, bad request — which the retry wrapper understands and the agent
reacts to. Context overflow is not fatal: the agent compacts harder and retries.

`MockClient` is a rule-based reader of its own observations. It exists so the whole system can be
demonstrated and tested without a model, and it exercises the same code paths as a real one: it
adapts when `nmap` is missing, follows links it finds, and submits flags it sees.

## Failure handling

| Failure | Response |
|---|---|
| Malformed reply | Nudge with format + tool list, continue (no step lost) |
| Unknown tool | Return available tools, continue |
| Tool raises | Caught, reported as a failed observation; the run continues |
| Command timeout | Process group killed, output returned with a note |
| Output flood | Capture capped at 2 MB, head+tail shown, full copy in `loot/` |
| Model auth error | Stop with `status=error`, report still written |
| Model rate limit / 5xx | Exponential backoff with jitter, up to 5 attempts |
| Context overflow | Compact with a smaller budget, retry once |
| Ctrl-C | Cancel, finalise, write report, exit 130 |
| Repeated action | Suppressed with an explanation |
| Unproductive streak (8) | Stop as `exhausted` to protect the budget |

## Testing strategy

226 tests, no network required:

- `test_protocol.py` — 29 formats real models emit (fences, tags, dicts, aliases, shorthands).
- `test_safety.py` — scope decisions including wildcards, CIDRs, DNS names, flag-value
  false positives; destructive blocklist; host extraction from realistic command lines.
- `test_tools.py` — execution, timeouts, truncation, file confinement, HTTP against a local
  server, dry-run.
- `test_llm.py` — both providers via `httpx.MockTransport`, error mapping, retry semantics,
  SSE, the mock model.
- `test_agent.py` — recovery from bad replies, guardrail blocks, repeat suppression, all four
  budget types, compaction, reporting, and an end-to-end run against a local lab.
- `test_cli.py` — argument handling, the authorisation gate, exit codes, JSON feed, resume,
  interrupt handling.

Adding a provider means implementing two methods and registering a preset; adding a tool means
one class plus one registry line.

## Extending

**New tool.** Subclass `Tool`, set `name`, `summary`, `args`, `required`, implement
`async def run(self, args, ctx) -> ToolResult`. Register in `redloop/tools/__init__.py`. The
system prompt, `--list-tools`, and the parser's aliases update automatically.

**New provider.** Implement `LLMClient.complete`, map HTTP errors onto the taxonomy in
`llm/base.py`, add a `ProviderPreset` to `config.PRESETS`, and choose a branch in
`llm.build_client`.

**New renderer.** Subscribe a callable taking `Event` to the bus. That is all.

**Different objective.** `--objective` is free text injected into the brief; the loop does not
assume a flag. For assessments, leave it empty and the agent works towards a credible report
with findings.
