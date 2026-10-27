"""Scratchpad memory: notes, findings, flags and auto-extracted facts.

A long autonomous run generates far more output than fits in a context window.
Rather than relying on the model to remember, the agent maintains a durable
scratchpad plus a small set of facts scraped from tool output (open ports,
discovered URLs, credentials, hashes).  Every prompt carries the digest, so a
model that has forgotten everything still knows what has been found.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

SEVERITIES = ("critical", "high", "medium", "low", "info")


# --------------------------------------------------------------------------- #
# Flag detection
# --------------------------------------------------------------------------- #
PLACEHOLDER_INNER = {
    "",
    "...",
    "…",
    "flag",
    "flags",
    "your_flag",
    "placeholder",
    "example",
    "redacted",
    "xxx",
    "xxx...",
    "here",
    "the_flag",
}


LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a"})


def is_placeholder_flag(value: str) -> bool:
    """Reject the format hints models love to echo (``flag{...}``, ``flag{y0ur_flag}``)."""
    if "{" not in value or not value.endswith("}"):
        return False
    inner = value[value.index("{") + 1 : -1].strip().strip(".").replace(" ", "").lower()
    if set(inner) <= {".", "*", "-", "_"}:
        return True
    if inner in PLACEHOLDER_INNER:
        return True
    normalised = inner.translate(LEET).replace("-", "_")
    if normalised in PLACEHOLDER_INNER:
        return True
    return normalised in {
        "yourflag",
        "your_flag_here",
        "insert_flag",
        "insertflag",
        "insert_flag_here",
        "flag_here",
        "flaghere",
        "theflag",
        "the_flag",
        "myflag",
        "my_flag",
        "redacted_flag",
        "some_flag_value",
    }


def detect_flags(text: str, patterns: list[str]) -> list[str]:
    """Return flag-shaped strings found in ``text``, in order, de-duplicated."""
    if not text:
        return []
    found: list[str] = []
    for pattern in patterns:
        try:
            for match in re.finditer(pattern, text):
                value = match.group(0).strip().strip(".,;:'\"`")
                if not value or value in found or len(value) > 400:
                    continue
                if is_placeholder_flag(value):
                    continue
                found.append(value)
        except re.error:
            continue
    return found


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #
@dataclass
class Note:
    text: str
    title: str = ""
    step: int = 0
    ts: float = field(default_factory=time.time)


@dataclass
class Finding:
    title: str
    severity: str = "info"
    details: str = ""
    evidence: str = ""
    remediation: str = ""
    step: int = 0
    ts: float = field(default_factory=time.time)

    def severity_rank(self) -> int:
        try:
            return SEVERITIES.index(self.severity.lower())
        except ValueError:
            return len(SEVERITIES)


@dataclass
class Flag:
    value: str
    source: str = ""
    step: int = 0
    ts: float = field(default_factory=time.time)


# --------------------------------------------------------------------------- #
# Automatic fact extraction
# --------------------------------------------------------------------------- #
PORT_RE = re.compile(
    r"(?m)^[ \t]*(\d{1,5})/(tcp|udp)[ \t]+open\b[ \t]*([^ \t\n]*)[ \t]*(.*)$"
)
URL_RE = re.compile(r"https?://[^\s<>\"')]+")
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
HASH_RE = re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b")
CRED_RE = re.compile(
    r"(?i)\b(?:user(?:name)?|login|admin|root)\s*[:=]\s*(\S{2,40})\s+"
    r"(?:pass(?:word)?|pwd)\s*[:=]\s*(\S{2,60})"
)
HTML_COMMENT_RE = re.compile(r"<!--(.{3,400}?)-->", re.DOTALL)
VERSION_HINT_RE = re.compile(
    r"(?i)\b(apache|nginx|openssh|vsftpd|proftpd|samba|wordpress|joomla|drupal|tomcat|jenkins"
    r"|gitlab|php|mysql|mariadb|postgres(?:ql)?|redis|mongodb|iis|lighttpd|openresty)"
    r"[/ ]+(?:httpd[ ]+|server[ ]+|version[ ]+)?v?([\d][\w.\-]{1,15})"
)


class FactStore:
    """Deduplicated facts scraped from tool output."""

    def __init__(self, limit: int = 120) -> None:
        self.limit = limit
        self.ports: dict[str, str] = {}
        self.urls: list[str] = []
        self.ips: list[str] = []
        self.emails: list[str] = []
        self.hashes: list[str] = []
        self.credentials: list[str] = []
        self.comments: list[str] = []
        self.software: dict[str, str] = {}

    def ingest(self, text: str) -> list[str]:
        """Update the store from output; return a list of newly learned facts."""
        if not text:
            return []
        new: list[str] = []

        for match in PORT_RE.finditer(text):
            port, proto, service, extra = match.groups()
            key = f"{port}/{proto}"
            value = " ".join(part for part in (service, (extra or "").strip()) if part).strip()
            if key not in self.ports:
                self.ports[key] = value[:80]
                new.append(f"port {key} open {value}".strip())
            elif value and len(value) > len(self.ports[key]):
                self.ports[key] = value[:80]

        for match in URL_RE.finditer(text):
            url = match.group(0).rstrip(".,;)")
            if url not in self.urls and len(self.urls) < self.limit:
                self.urls.append(url)
                new.append(f"url {url}")

        for match in IP_RE.finditer(text):
            ip = match.group(0)
            if ip not in self.ips and len(self.ips) < self.limit and not ip.startswith("0."):
                self.ips.append(ip)

        for match in EMAIL_RE.finditer(text):
            email = match.group(0)
            if email not in self.emails and len(self.emails) < 20:
                self.emails.append(email)
                new.append(f"email {email}")

        for match in HASH_RE.finditer(text):
            value = match.group(0)
            if value not in self.hashes and len(self.hashes) < 20:
                self.hashes.append(value)
                new.append(f"hash {value}")

        for match in CRED_RE.finditer(text):
            cred = f"{match.group(1)}:{match.group(2)}"
            if cred not in self.credentials and len(self.credentials) < 20:
                self.credentials.append(cred)
                new.append(f"credential {cred}")

        for match in HTML_COMMENT_RE.finditer(text):
            comment = " ".join(match.group(1).split())[:200]
            if comment and comment not in self.comments and len(self.comments) < 15:
                self.comments.append(comment)
                new.append(f"html comment: {comment}")

        for match in VERSION_HINT_RE.finditer(text):
            name, version = match.group(1).lower(), match.group(2)
            if name not in self.software:
                self.software[name] = version
                new.append(f"software {name} {version}")

        return new

    def digest(self, *, max_lines: int = 26) -> str:
        lines: list[str] = []
        if self.ports:
            ports = ", ".join(f"{k} {v}".strip() for k, v in sorted(self.ports.items()))
            lines.append(f"open ports: {ports}")
        if self.software:
            software = ", ".join(f"{k} {v}" for k, v in self.software.items())
            lines.append(f"software: {software}")
        if self.urls:
            lines.append("urls: " + ", ".join(self.urls[-10:]))
        if self.credentials:
            lines.append("credentials: " + ", ".join(self.credentials[-8:]))
        if self.emails:
            lines.append("emails: " + ", ".join(self.emails[-8:]))
        if self.hashes:
            lines.append("hashes: " + ", ".join(self.hashes[-6:]))
        if self.comments:
            lines.append("html comments: " + " | ".join(self.comments[-4:]))
        if self.ips:
            lines.append("hosts seen: " + ", ".join(self.ips[-10:]))
        return "\n".join(lines[:max_lines])

    def to_dict(self) -> dict:
        return {
            "ports": self.ports,
            "software": self.software,
            "urls": self.urls,
            "ips": self.ips,
            "emails": self.emails,
            "hashes": self.hashes,
            "credentials": self.credentials,
            "comments": self.comments,
        }


# --------------------------------------------------------------------------- #
# Memory
# --------------------------------------------------------------------------- #
class Memory:
    def __init__(self) -> None:
        self.notes: list[Note] = []
        self.findings: list[Finding] = []
        self.flags: list[Flag] = []
        self.facts = FactStore()
        self.attempts: list[str] = []

    # ------------------------------------------------------------- mutators
    def add_note(self, text: str, title: str = "", step: int = 0) -> Note:
        note = Note(text=text.strip(), title=title.strip(), step=step)
        self.notes.append(note)
        return note

    def add_finding(
        self,
        title: str,
        severity: str = "info",
        details: str = "",
        evidence: str = "",
        remediation: str = "",
        step: int = 0,
    ) -> Finding:
        severity = severity.lower().strip()
        if severity not in SEVERITIES:
            severity = "info"
        finding = Finding(
            title=title.strip() or "Unnamed finding",
            severity=severity,
            details=details.strip(),
            evidence=evidence.strip(),
            remediation=remediation.strip(),
            step=step,
        )
        self.findings.append(finding)
        return finding

    def add_flag(self, value: str, source: str = "", step: int = 0) -> Flag | None:
        value = value.strip()
        if not value or any(f.value == value for f in self.flags):
            return None
        flag = Flag(value=value, source=source, step=step)
        self.flags.append(flag)
        return flag

    def record_attempt(self, text: str, limit: int = 200) -> None:
        self.attempts.append(text.strip())
        if len(self.attempts) > limit:
            del self.attempts[: len(self.attempts) - limit]

    def ingest_facts(self, text: str) -> list[str]:
        return self.facts.ingest(text)

    # -------------------------------------------------------------- digests
    def notes_digest(self, limit: int = 12, chars: int = 300) -> str:
        if not self.notes:
            return ""
        recent = self.notes[-limit:]
        out = []
        for note in recent:
            body = note.text.replace("\n", " ")
            if len(body) > chars:
                body = body[:chars] + "…"
            label = f"[{note.title}] " if note.title else ""
            out.append(f"- (step {note.step}) {label}{body}")
        return "\n".join(out)

    def findings_digest(self, limit: int = 12) -> str:
        if not self.findings:
            return ""
        out = []
        for finding in self.findings[:limit]:
            out.append(f"- [{finding.severity}] {finding.title}")
        if len(self.findings) > limit:
            out.append(f"- … and {len(self.findings) - limit} more")
        return "\n".join(out)

    def attempts_digest(self, limit: int = 40, chars: int = 110) -> str:
        if not self.attempts:
            return ""
        out = []
        for attempt in self.attempts[-limit:]:
            line = " ".join(attempt.split())
            if len(line) > chars:
                line = line[:chars] + "…"
            out.append(f"- {line}")
        if len(self.attempts) > limit:
            out.insert(0, f"({len(self.attempts) - limit} earlier attempts omitted)")
        return "\n".join(out)

    def summary(self) -> str:
        """A compact, deterministic recap used when the context is compacted."""
        blocks = []
        if self.flags:
            blocks.append("FLAGS FOUND:\n" + "\n".join(f"- {f.value}" for f in self.flags))
        facts = self.facts.digest()
        if facts:
            blocks.append("FACTS:\n" + facts)
        findings = self.findings_digest()
        if findings:
            blocks.append("FINDINGS:\n" + findings)
        notes = self.notes_digest(limit=10)
        if notes:
            blocks.append("NOTES:\n" + notes)
        attempts = self.attempts_digest(limit=60)
        if attempts:
            blocks.append("ACTIONS ALREADY TAKEN (newest last):\n" + attempts)
        return "\n\n".join(blocks) if blocks else "(nothing recorded yet)"

    def has_flag(self) -> bool:
        return bool(self.flags)

    # ------------------------------------------------------------ persistence
    def to_dict(self) -> dict:
        return {
            "notes": [asdict(n) for n in self.notes],
            "findings": [asdict(f) for f in self.findings],
            "flags": [asdict(f) for f in self.flags],
            "facts": self.facts.to_dict(),
            "attempts": self.attempts,
        }

    def save(self, run_dir: Path) -> None:
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / "memory.json").write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        (run_dir / "notes.md").write_text(self.render_markdown(), encoding="utf-8")

    @classmethod
    def load(cls, run_dir: Path) -> Memory | None:
        """Rehydrate a scratchpad from a previous run directory (used by --resume)."""
        path = Path(run_dir) / "memory.json"
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        memory = cls()
        for item in data.get("notes", []):
            memory.notes.append(
                Note(
                    text=str(item.get("text", "")),
                    title=str(item.get("title", "")),
                    step=int(item.get("step", 0) or 0),
                    ts=float(item.get("ts", time.time()) or time.time()),
                )
            )
        for item in data.get("findings", []):
            memory.findings.append(
                Finding(
                    title=str(item.get("title", "Unnamed finding")),
                    severity=str(item.get("severity", "info")),
                    details=str(item.get("details", "")),
                    evidence=str(item.get("evidence", "")),
                    remediation=str(item.get("remediation", "")),
                    step=int(item.get("step", 0) or 0),
                )
            )
        for item in data.get("flags", []):
            memory.flags.append(
                Flag(
                    value=str(item.get("value", "")),
                    source=str(item.get("source", "")),
                    step=int(item.get("step", 0) or 0),
                )
            )
        facts = data.get("facts", {}) or {}
        for key in ("urls", "ips", "emails", "hashes", "credentials", "comments"):
            setattr(memory.facts, key, list(facts.get(key, [])))
        memory.facts.ports = dict(facts.get("ports", {}))
        memory.facts.software = dict(facts.get("software", {}))
        memory.attempts = [str(a) for a in data.get("attempts", [])]
        return memory

    def render_markdown(self) -> str:
        lines = ["# Scratchpad", ""]
        if self.flags:
            lines += ["## Flags", ""]
            lines += [f"- `{f.value}` — {f.source or 'observed'} (step {f.step})" for f in self.flags]
            lines.append("")
        if self.findings:
            lines += ["## Findings", ""]
            for finding in self.findings:
                lines.append(f"### [{finding.severity.upper()}] {finding.title}")
                if finding.details:
                    lines.append(finding.details)
                if finding.evidence:
                    lines += ["```", finding.evidence.strip()[:2000], "```"]
                if finding.remediation:
                    lines.append(f"*Remediation:* {finding.remediation}")
                lines.append("")
        facts = self.facts.digest()
        if facts:
            lines += ["## Facts", "", "```", facts, "```", ""]
        if self.notes:
            lines += ["## Notes", ""]
            lines += [f"- {n.text}" for n in self.notes]
        return "\n".join(lines) + "\n"
