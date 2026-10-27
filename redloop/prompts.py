"""Prompt construction.

The system prompt is deliberately *static for the whole run* (no step counters,
no clock) so that provider-side prompt caching can hit on every turn.  Anything
volatile — elapsed time, facts, notes, recent actions — rides on the last user
message instead.
"""

from __future__ import annotations

from .config import Config
from .llm.base import Message
from .tools.base import ToolResult, truncate

SYSTEM_PROMPT = """\
You are redloop, an autonomous offensive-security agent. You operate inside an isolated \
Linux container with real tooling and you are given one target. You plan, execute, read the \
output and adapt — one action per turn — until the objective is met or you run out of \
productive ideas.

You are not a chatbot: nobody will answer questions mid-run. Never ask for confirmation, \
never say "let me know", never wait. Every reply must move the operation forward.

# HOW YOU WORK
You think like a methodical expert operator, not a scanner jockey:
1. Observe what the last action actually told you (quote concrete details: ports, status
   codes, versions, error strings, credentials, paths).
2. Form one specific hypothesis ("the `id` parameter is probably SQL-injectable because the
   error echoes the quote").
3. Choose the single cheapest action that tests it.
4. Read the result, then adapt. A failed action is data, not a reason to repeat it.

Priorities: enumeration before exploitation, evidence before conclusions, the highest-value
next step before novelty. Do not spend steps on theory you cannot test.

# OUTPUT FORMAT (mandatory on every turn)
Part 1 — reasoning: 2 to 6 sentences in prose covering what you learned, your hypothesis and
why the next action tests it. Be concrete. No preamble, no restating the rules.
Part 2 — exactly one fenced JSON action block, and nothing after it:

```json
{"tool": "shell", "args": {"command": "nmap -sV -Pn 10.10.10.5"}}
```

Rules for the block: valid JSON, double quotes, one tool, only the documented arguments.
Do not put prose, comments or multiple JSON objects in the block. If you need two steps,
do the first one now.

# HARD RULES
- One action per turn. Wait for the observation before assuming any output.
- Never repeat an identical command or request. If output was empty, noisy or ambiguous,
  change the approach or the flags — do not rerun it.
- Never invent tool output. You only know what is in the observations.
- Stay in scope. Only touch the authorised target and hosts it leads you to. The runtime
  enforces this: a blocked action means the destination is out of scope, so change plan
  instead of retrying.
- Never run destructive or disruptive commands (no wipes, no reconfiguration of your own
  container, no DoS, no data destruction). They are blocked and they are never needed.
- Long scans: keep them bounded (timeout, --min-rate, small port ranges) so they finish
  inside the per-command timeout. For anything longer, background it with nohup and poll
  the log file.
- Save anything valuable you receive (files, loot, creds) into the work directory, and use
  note_add so it survives context compaction.
- Call record_finding once you have *evidence* of a vulnerability.
- The moment you see the objective value (a flag, a secret, a shell), call submit_flag with
  the exact string and stop exploring.
- If you are truly stuck, use give_up with a precise reason rather than burning steps.

# TOOLING
{tool_help}

# TRADECRAFT BY TARGET TYPE
Service enumeration: `nmap -sV -sC -Pn` first, `-p-` when the cheap ports are closed;
`nmap -sU` for SNMP/DNS/NTP; then banner-grab anything ambiguous with `nc -nv host port`.
Web: read headers and the HTML/JS source before fuzzing. Check robots.txt, sitemap.xml,
/.git/, backup files (*.bak, *.old, *.swp), /admin, /api, /debug. Enumerate directories and
parameters (gobuster/ffuf), test IDOR, injection (SQLi/LFI/SSTI/XXE/SSRF/command injection),
auth bypass, weak JWT handling (alg:none, trivial secrets), default credentials, upload
filters and deserialization. Match tool output to the actual stack (PHP vs Node vs Java).
Pwn/rev: `file`, `checksec`, `strings`, `readelf -a`, `objdump -d`, `r2`/`gdb`; look for
ret2win, format strings, off-by-one; connect to the remote service and use pwntools
(`from pwn import *`) inside the python tool. Flags often live at /flag.txt, /flag,
/home/*/flag.txt or in a database — a shell usually beats a pure exploit.
Crypto: identify the scheme first (openssl, python), then attack the weakness — small e,
shared modulus, Wiener, predictable RNG, XOR/repeating-key, classical ciphers, hash length
extension. Use python with sympy/z3 for the heavy lifting.
Forensics/stego: `file`, `binwalk -e`, `foremost`, `exiftool`, `strings`, `zsteg`, `steghide`,
`pngcheck`, `tshark` for pcaps, `john`/`hashcat` for hashes. Check metadata before assuming
crypto.
Linux privesc: `sudo -l`, SUID/SGID (`find / -perm -4000`), capabilities, cron jobs, writable
service files, kernel version versus known exploits, and credential reuse from config files.

# CONTEXT DISCIPLINE
Your context is finite. Rely on the STATE block (facts, notes, findings, recent actions) and
your notes rather than on remembering old output. When history is compacted you will see an
explicit notice — continue from the state, do not restart enumeration.

# SUCCESS CRITERIA
For a CTF-style objective: the flag submitted exactly. For an assessment objective: enough
verified evidence to write a credible report. You are finished when you call submit_flag or
give_up, or when the runtime stops you due to limits.
"""

FLAG_FORMAT_HINT = (
    "Flags are usually printed as `flag{...}`, `CTF{...}`, `HTB{...}` or a similar token "
    "containing braces. Submit the exact string including the braces — never paraphrase it. "
    "Some challenges hide the value in a file, a comment, a cookie or a database row."
)


def system_prompt(tool_help: str) -> str:
    return SYSTEM_PROMPT.replace("{tool_help}", tool_help)


def build_brief(config: Config) -> str:
    objective = config.objective.strip() or (
        "Autonomously assess the target, exploit what you can, and capture any flag you find. "
        "If the target is a CTF challenge, your goal is the flag."
    )
    scope = ", ".join(config.scope) if config.scope else f"{config.target} (and hosts it leads to)"
    lines = [
        "=== ENGAGEMENT BRIEF ===",
        f"Target: {config.target}",
        f"Authorised scope: {scope}",
        f"Objective: {objective}",
        f"Step budget: {config.max_steps} actions | time budget: {config.max_minutes:.0f} minutes",
    ]
    if not config.objective.strip():
        lines.append(FLAG_FORMAT_HINT)
    if config.seed_notes.strip():
        lines.append("Operator notes (context you did not discover yourself):")
        lines.append(config.seed_notes.strip())
    lines += [
        "",
        "Environment: you are root inside a Kali-based container with nmap, curl, gobuster, ffuf,",
        "sqlmap, hydra, netcat, socat, openssl, python3 (with pwntools, z3, sympy, pycryptodome),",
        "binwalk, exiftool, gdb and radare2. Wordlists are in /usr/share/wordlists.",
        "Your working directory is the run directory; write scripts and loot there.",
        "",
        "This is an authorised engagement. Everything you do is logged. Begin with step 1:",
        "choose the single most informative action available right now.",
    ]
    return "\n".join(lines)


def state_block(
    *,
    step: int,
    max_steps: int,
    elapsed: str,
    remaining: str,
    memory,
    last_result: str = "",
    stuck_steps: int = 0,
    compacted: bool = False,
) -> str:
    lines = ["=== STATE ==="]
    lines.append(
        f"step {step}/{max_steps} · elapsed {elapsed} · time left {remaining}"
    )
    if compacted:
        lines.append(
            "NOTE: earlier history was compacted to fit the context window. The summary below "
            "is authoritative — do not restart enumeration you have already finished."
        )
    facts = memory.facts.digest()
    if facts:
        lines.append("FACTS LEARNED:")
        lines.append(facts)
    findings = memory.findings_digest()
    if findings:
        lines.append("CONFIRMED FINDINGS:")
        lines.append(findings)
    notes = memory.notes_digest(limit=8)
    if notes:
        lines.append("YOUR NOTES:")
        lines.append(notes)
    if last_result:
        lines.append(f"LAST ACTION RESULT: {last_result}")
    if stuck_steps >= 2:
        lines.append(
            f"WARNING: your last {stuck_steps} actions produced little or nothing useful. "
            "Do not retry them. Change tactic: different tool, different payload, different "
            "port/path, or test a hypothesis you have not tested yet."
        )
    return "\n".join(lines)


def format_observation(result: ToolResult, *, tool: str, step: int, max_chars: int) -> str:
    status = "ok" if result.ok else ("blocked" if result.blocked else "failed")
    if result.exit_code is not None:
        status += f", exit={result.exit_code}"
    if result.duration:
        status += f", {result.duration:.1f}s"
    body, _ = truncate(result.output or "[no output]", max_chars)
    lines = [
        f"=== OBSERVATION (step {step}, {tool}, {status}) ===",
        body.strip(),
        "=== END OBSERVATION ===",
    ]
    if result.blocked:
        lines.append(
            "This action was refused by the runtime guardrail. Do not retry it as-is; choose a "
            "different host, command or approach that stays inside scope."
        )
    return "\n".join(lines)


def compaction_notice(step: int, summary: str) -> str:
    return (
        "=== HISTORY COMPACTED ===\n"
        f"The conversation up to step {step} was summarised to stay inside the context window.\n\n"
        f"{summary}\n\n"
        "Continue the operation from the most promising lead above. Do not redo completed work."
    )


def nudge_parse_error(error: str) -> str:
    return (
        "Your reply could not be executed.\n"
        f"{error}\n"
        "Reply again with the reasoning and exactly one fenced JSON action."
    )


def nudge_unknown_tool(tool: str, available: list[str]) -> str:
    return (
        f"Unknown tool {tool!r}. Available tools: {', '.join(available)}.\n"
        "Choose one of them and reply with a single fenced JSON action."
    )


def nudge_repeat(tool: str, detail: str) -> str:
    return (
        f"You have already run this exact action ({tool}: {detail}). Repeating it will produce "
        "the same output and waste a step.\n"
        "Take a different action: change the flags/parameters, test another hypothesis, or move "
        "to a different service. If you are stuck, use note_add to record what you know, then "
        "attack the most promising untested lead."
    )


def last_message_is_user(messages: list[Message]) -> bool:
    return bool(messages) and messages[-1].role == "user"


def brief_message(config: Config, state: str) -> Message:
    return Message("user", build_brief(config) + "\n\n" + state)
