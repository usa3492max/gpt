"""Memory: flag detection, fact extraction and scratchpad persistence."""

from __future__ import annotations

from redloop.config import DEFAULT_FLAG_PATTERNS
from redloop.memory import FactStore, Memory, detect_flags, is_placeholder_flag

NMAP = """Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for target (10.10.11.42)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Acme Intranet
8080/tcp open  http-proxy
Service Info: OS: Linux
"""


# --------------------------------------------------------------------------- #
# flags
# --------------------------------------------------------------------------- #
def test_detects_default_flag_formats():
    text = "nothing CTF{web_bypass} then HTB{pwn3d} and finally flag{real_one}"
    found = detect_flags(text, DEFAULT_FLAG_PATTERNS)
    assert "flag{real_one}" in found
    assert "CTF{web_bypass}" in found
    assert "HTB{pwn3d}" in found


def test_placeholder_flags_are_ignored():
    for text in ("flag{...}", "flag{}", "CTF{example}", "flag{y0ur_flag}"):
        assert detect_flags(text, DEFAULT_FLAG_PATTERNS) == [], text


def test_placeholder_helper():
    assert is_placeholder_flag("flag{...}")
    assert not is_placeholder_flag("flag{abc123}")


def test_custom_pattern_supported():
    found = detect_flags("the secret is SECRET{abc}", [r"SECRET\{[a-z]+\}"])
    assert found == ["SECRET{abc}"]


def test_duplicates_removed():
    text = "flag{a} flag{a} flag{b}"
    assert detect_flags(text, DEFAULT_FLAG_PATTERNS) == ["flag{a}", "flag{b}"]


def test_bad_regex_does_not_raise():
    assert detect_flags("flag{a}", ["(", r"flag\{[^}]+\}"]) == ["flag{a}"]


# --------------------------------------------------------------------------- #
# facts
# --------------------------------------------------------------------------- #
def test_extracts_ports_services_and_versions():
    facts = FactStore()
    facts.ingest(NMAP)
    assert "22/tcp" in facts.ports
    assert "ssh" in facts.ports["22/tcp"]
    assert facts.ports["80/tcp"].startswith("http")
    assert facts.software["apache"] == "2.4.41"
    assert "openssh" in facts.software


def test_extracts_urls_emails_hashes_credentials():
    facts = FactStore()
    facts.ingest(
        "found http://10.10.11.42/admin/ and mailto:admin@acme.test\n"
        "hash: 5f4dcc3b5aa765d61d8327deb882cf99\n"
        "username: admin password: Sup3rSecret\n"
    )
    assert any("10.10.11.42" in url for url in facts.urls)
    assert "admin@acme.test" in facts.emails
    assert "5f4dcc3b5aa765d61d8327deb882cf99" in facts.hashes
    assert any("admin" in cred for cred in facts.credentials)


def test_extracts_html_comments():
    facts = FactStore()
    facts.ingest("<html><!-- TODO: remove /backup/ before go-live --></html>")
    assert any("/backup/" in comment for comment in facts.comments)


def test_digest_is_human_readable():
    facts = FactStore()
    facts.ingest(NMAP)
    digest = facts.digest()
    assert "open ports" in digest
    assert "22/tcp" in digest
    assert "software" in digest


def test_ingest_reports_new_facts_only():
    facts = FactStore()
    first = facts.ingest(NMAP)
    second = facts.ingest(NMAP)
    assert any(fact.startswith("port ") for fact in first)
    assert second == []


# --------------------------------------------------------------------------- #
# memory
# --------------------------------------------------------------------------- #
def test_notes_and_findings_digests():
    memory = Memory()
    memory.add_note("found creds admin:hunter2", title="creds", step=3)
    memory.add_finding("Reflected XSS", severity="medium", step=4)
    assert "hunter2" in memory.notes_digest()
    assert "[medium] Reflected XSS" in memory.findings_digest()


def test_findings_severity_is_normalised():
    memory = Memory()
    assert memory.add_finding("x", severity="CRITICAL").severity == "critical"
    assert memory.add_finding("y", severity="nonsense").severity == "info"


def test_flags_are_deduplicated():
    memory = Memory()
    assert memory.add_flag("flag{a}", step=1) is not None
    assert memory.add_flag("flag{a}", step=2) is None
    assert len(memory.flags) == 1


def test_attempts_are_capped():
    memory = Memory()
    for index in range(250):
        memory.record_attempt(f"cmd {index}", limit=200)
    assert len(memory.attempts) == 200
    assert memory.attempts[-1] == "cmd 249"


def test_save_and_reload_roundtrip(tmp_path):
    memory = Memory()
    memory.add_note("note text", title="t", step=2)
    memory.add_finding("SQLi", severity="high", details="d", evidence="e", step=5)
    memory.add_flag("flag{roundtrip}", source="test", step=6)
    memory.ingest_facts(NMAP)
    memory.record_attempt("shell: nmap")
    memory.save(tmp_path)

    restored = Memory.load(tmp_path)
    assert restored is not None
    assert restored.notes[0].text == "note text"
    assert restored.findings[0].title == "SQLi"
    assert restored.flags[0].value == "flag{roundtrip}"
    assert "22/tcp" in restored.facts.ports
    assert restored.attempts == ["shell: nmap"]


def test_load_missing_returns_none(tmp_path):
    assert Memory.load(tmp_path / "nope") is None


def test_summary_includes_the_important_parts():
    memory = Memory()
    memory.add_note("admin creds work", step=3)
    memory.add_flag("flag{summary}", step=9)
    memory.ingest_facts(NMAP)
    memory.record_attempt("shell: nmap -sV 10.10.11.42")
    summary = memory.summary()
    assert "FLAGS FOUND" in summary
    assert "flag{summary}" in summary
    assert "FACTS" in summary
    assert "ACTIONS ALREADY TAKEN" in summary


def test_markdown_rendering(tmp_path):
    memory = Memory()
    memory.add_finding("Exposed backup", severity="high", details="d", remediation="r")
    memory.add_flag("flag{md}")
    text = memory.render_markdown()
    assert "# Scratchpad" in text
    assert "HIGH" in text
    assert "flag{md}" in text
