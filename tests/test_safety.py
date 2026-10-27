"""Guardrails: scope enforcement and blast-radius protection."""

from __future__ import annotations

import pytest

from redloop.safety import ScopeGuard


def guard(**kwargs) -> ScopeGuard:
    kwargs.setdefault("target", "10.10.11.42")
    return ScopeGuard(**kwargs)


# --------------------------------------------------------------------------- #
# scope
# --------------------------------------------------------------------------- #
def test_target_is_always_authorised():
    assert guard().authorize("10.10.11.42").allowed


def test_other_public_address_is_refused_with_guidance():
    decision = guard().authorize("8.8.8.8")
    assert not decision.allowed
    assert "--scope 8.8.8.8" in decision.reason


def test_explicit_scope_entry_authorises_public_host():
    g = guard(scope=["8.8.8.8", "api.example.net"])
    assert g.authorize("8.8.8.8").allowed
    assert g.authorize("api.example.net").allowed


def test_cidr_scope():
    g = guard(scope=["203.0.113.0/24"])
    assert g.authorize("203.0.113.17").allowed
    assert not g.authorize("203.0.114.17").allowed


def test_private_ranges_allowed_by_default():
    assert guard().authorize("10.99.0.5").allowed
    assert guard().authorize("192.168.56.7").allowed
    assert guard().authorize("172.16.5.5").allowed


def test_private_ranges_can_be_disabled():
    g = guard(allow_private=False)
    assert not g.authorize("10.99.0.5").allowed
    assert g.authorize("10.10.11.42").allowed  # still the explicit target


def test_loopback_allowed():
    assert guard().authorize("127.0.0.1").allowed
    assert guard().authorize("127.0.0.53").allowed


def test_infrastructure_hosts_are_not_blocked():
    # The agent must be able to reach its own model API and package mirrors.
    assert guard().authorize("api.anthropic.com").allowed
    assert guard().authorize("pypi.org").allowed


def test_wildcard_scope(monkeypatch):
    monkeypatch.setattr(ScopeGuard, "_resolve", lambda self, host: ["93.184.216.34"])
    g = guard(scope=["*.example.com"])
    assert g.authorize("app.example.com").allowed
    assert g.authorize("deep.app.example.com").allowed
    assert not g.authorize("example.org").allowed


def test_unresolvable_hostname_is_refused(monkeypatch):
    monkeypatch.setattr(ScopeGuard, "_resolve", lambda self, host: [])
    decision = guard().authorize("totally-unknown-host.invalid")
    assert not decision.allowed


def test_docker_service_name_resolving_to_private_is_allowed(monkeypatch):
    monkeypatch.setattr(ScopeGuard, "_resolve", lambda self, host: ["172.18.0.4"])
    assert guard().authorize("lab-web").allowed


def test_scope_can_be_switched_off():
    assert guard(enabled=False).authorize("8.8.8.8").allowed


# --------------------------------------------------------------------------- #
# destructive commands
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /",
        "rm -rf /*",
        "sudo rm -fr /etc",
        "mkfs.ext4 /dev/sda1",
        "dd if=/dev/zero of=/dev/sda bs=1M",
        "shutdown -h now",
        "reboot",
        ":(){ :|:& };:",
        "chmod -R 777 /",
        "wipefs -a /dev/nvme0n1",
    ],
)
def test_destructive_commands_are_blocked(command):
    decision = guard().check_command(command)
    assert not decision.allowed
    assert "destructive" in decision.reason.lower()


@pytest.mark.parametrize(
    "command",
    [
        "rm -rf ./loot/tmp",
        "ls -la /tmp",
        "nmap -sV -Pn 10.10.11.42",
        "cat /etc/passwd",
        "grep -r password . | head",
    ],
)
def test_ordinary_commands_are_allowed(command):
    assert guard().check_command(command).allowed


def test_out_of_scope_target_in_nmap_is_blocked():
    decision = guard().check_command("nmap -sV 8.8.8.8")
    assert not decision.allowed
    assert "8.8.8.8" in decision.reason


def test_out_of_scope_url_is_blocked():
    assert not guard().check_command("curl -s https://example.com/").allowed


def test_in_scope_url_is_allowed():
    assert guard().check_command("curl -s http://10.10.11.42:8080/login").allowed


# --------------------------------------------------------------------------- #
# host extraction
# --------------------------------------------------------------------------- #
def test_extract_hosts_from_typical_commands():
    g = guard()
    assert "10.10.11.42" in g.extract_hosts("nmap -sV -p- 10.10.11.42")
    assert "10.10.11.42" in g.extract_hosts("curl -s http://10.10.11.42:8080/x?y=1")
    assert "10.10.11.42" in g.extract_hosts("ssh admin@10.10.11.42")
    assert "10.10.11.42" in g.extract_hosts("nc -nv 10.10.11.42 4444")
    assert "10.10.11.42" in g.extract_hosts("sqlmap -u http://10.10.11.42/item?id=1 --batch")
    assert "10.10.11.42" in g.extract_hosts("gobuster dir -u http://10.10.11.42/ -w list.txt")


def test_dns_query_names_are_not_treated_as_destinations():
    # The zone name is not where the traffic goes; the @server is.
    assert guard().check_command("dig axfr @10.10.11.42 htb.local").allowed
    assert guard().check_command("dig axfr htb.local").allowed


def test_hydra_flags_are_not_treated_as_hosts():
    assert guard().check_command("hydra -l admin -P pass.txt ssh://10.10.11.42").allowed


def test_filenames_are_not_mistaken_for_hosts():
    hosts = guard().extract_hosts("nmap -oN scan.txt 10.10.11.42 > out.log")
    assert hosts == ["10.10.11.42"]


def test_bind_addresses_are_not_destinations():
    assert guard().extract_hosts("nc -lvnp 4444 -s 0.0.0.0") == []


def test_range_scope_blocks_adjacent_public_ip():
    g = guard(scope=["203.0.113.0/24"])
    assert g.check_command("nmap 203.0.113.5").allowed
    assert not g.check_command("nmap 203.0.114.5").allowed


# --------------------------------------------------------------------------- #
# python snippets
# --------------------------------------------------------------------------- #
def test_python_snippet_reaching_out_of_scope_is_blocked():
    code = 'import socket\ns=socket.socket()\ns.connect(("8.8.8.8", 53))\n'
    assert not guard().check_code(code).allowed


def test_python_snippet_against_the_target_is_allowed():
    code = 'import socket\ns=socket.socket()\ns.connect(("10.10.11.42", 80))\n'
    assert guard().check_code(code).allowed


def test_python_snippet_cannot_shadow_destructive_patterns():
    assert not guard().check_code("import os\nos.system('mkfs.ext4 /dev/sda')\n").allowed


def test_risky_commands_are_flagged_for_confirmation():
    decision = guard().check_command("hydra -l admin -P pass.txt ssh://10.10.11.42")
    assert decision.allowed
    assert decision.risky


def test_scope_description_is_informative():
    text = guard().describe()
    assert "10.10.11.42" in text
    assert "private" in text
