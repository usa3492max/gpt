"""Guardrails: scope enforcement and destructive-command protection.

Two independent things are enforced here.

1. **Scope.**  The engagement target is always authorised.  Private (RFC1918 /
   ULA / link-local) addresses and loopback are allowed by default, because CTF
   boxes pivot into internal networks and because the agent's own tooling lives
   on localhost.  Arbitrary *public* hosts are refused unless they were passed
   with ``--scope``.  That keeps a mistyped command or a hallucinated host from
   turning into an attack on a stranger's server.

2. **Blast radius.**  Commands that would destroy the container or its host
   (``mkfs``, ``dd of=/dev/sda``, ``rm -rf /``, fork bombs, ...) are blocked
   outright.  They are never needed to solve a challenge.

Everything the guard refuses is fed back to the model as an observation, so it
can adapt instead of silently retrying.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field

from .config import INFRASTRUCTURE_HOSTS

#: Tools whose arguments are network destinations.
NETWORK_COMMANDS = {
    "nmap",
    "masscan",
    "rustscan",
    "zmap",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "telnet",
    "ssh",
    "scp",
    "sftp",
    "ftp",
    "curl",
    "wget",
    "httpie",
    "http",
    "https",
    "sqlmap",
    "nikto",
    "whatweb",
    "gobuster",
    "ffuf",
    "feroxbuster",
    "dirb",
    "dirsearch",
    "wfuzz",
    "hydra",
    "medusa",
    "crackmapexec",
    "nxc",
    "smbclient",
    "smbmap",
    "enum4linux",
    "enum4linux-ng",
    "rpcclient",
    "snmpwalk",
    "ldapsearch",
    "dig",
    "nslookup",
    "host",
    "whois",
    "ping",
    "traceroute",
    "arp-scan",
    "nbtscan",
    "wpscan",
    "joomscan",
    "droopescan",
    "nuclei",
    "dnsrecon",
    "amass",
    "subfinder",
    "httpx",
    "ssh-audit",
    "ike-scan",
    "onesixtyone",
    "redis-cli",
    "mongo",
    "mysql",
    "psql",
    "impacket-smbclient",
    "responder",
    "mitmproxy",
}

DESTRUCTIVE_PATTERNS: list[tuple[str, str]] = [
    (r"\bmkfs(\.\w+)?\b", "formatting a filesystem"),
    (r"\bwipefs\b", "wiping a filesystem signature"),
    (r"\bdd\b[^\n]*\bof=/dev/(sd|nvme|hd|vd|mmcblk)", "raw write to a block device"),
    (r">\s*/dev/(sd|nvme|hd|vd|mmcblk)", "raw write to a block device"),
    (r"\b(shutdown|reboot|halt|poweroff)\b(?!.*--)", "shutting down the machine"),
    (r"\binit\s+[06]\b", "shutting down the machine"),
    (r":\s*\(\s*\)\s*\{.*\};\s*:", "fork bomb"),
    (r"\brm\s+(-[a-zA-Z]*\s+)*-?[a-zA-Z]*[rf][a-zA-Z]*\s+(-[a-zA-Z]+\s+)*(/|/\*|/~|~)\s*($|[;&|])",
     "recursive delete of the filesystem root"),
    (r"\brm\s+(-[a-zA-Z]*\s+)*-?[a-zA-Z]*[rf][a-zA-Z]*\s+(/etc|/bin|/sbin|/usr|/boot|/dev|/proc|/sys|/var/lib)(/|\s|$)",
     "recursive delete of a system directory"),
    (r"\bchmod\s+-R\s+[0-7]{3,4}\s+/(\s|$)", "changing permissions on the whole filesystem"),
    (r"\bchown\s+-R\s+\S+\s+/(\s|$)", "changing ownership of the whole filesystem"),
    (r"\b(apt|apt-get|dpkg)\s+.*\b(remove|purge)\b.*\bpython3?\b", "removing the agent's own runtime"),
    (r"\buserdel\s+-r?\s*root\b|\bpasswd\s+root\b", "locking out the container's user"),
    (r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(/app|/opt/redloop)\b", "deleting the agent installation"),
]

RISKY_PATTERNS: list[tuple[str, str]] = [
    (r"\b(curl|wget)\b[^\n|]*\|\s*(bash|sh|zsh)\b", "piping a remote script into a shell"),
    (r"\b(nc|ncat|socat)\b[^\n]*-[a-zA-Z]*e\b", "binding a shell to a socket"),
    (r"/bin/(ba)?sh\s+-i\b", "interactive reverse shell"),
    (r"\bhydra\b|\bmedusa\b", "credential brute forcing"),
    (r"\bsqlmap\b", "automated SQL injection"),
    (r"\bmsfconsole\b|\bmsfvenom\b", "Metasploit"),
    (r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s", "recursive delete"),
]

#: Flags whose value is unambiguously a destination.
HOST_FLAGS = (
    "--host",
    "--hostname",
    "--target",
    "--targets",
    "--url",
    "-u",
    "--domain",
    "--server",
)

#: Flags whose *next* token is a value, not a positional host.  Without this,
#: ``hydra -l admin -P pass.txt ssh://host`` would treat "admin" as a target.
FLAGS_WITH_VALUES = {
    "-l", "-L", "-P", "-p", "-U", "-w", "-t", "-o", "-oN", "-oX", "-oG", "-oA", "-oS",
    "-D", "-e", "-i", "-r", "-n", "-c", "-s", "-m", "-x", "-g", "-b", "-d", "-f", "-k",
    "-q", "-z", "-C", "-W", "-G", "-A", "-M", "-O", "-Q", "-R", "-S", "-T", "-V", "-Z",
    "--script", "--script-args", "--exclude", "--excludefile", "--output", "--wordlist",
    "--username", "--password", "--users", "--passwords", "--data", "--cookie", "--header",
    "--threads", "--rate", "--delay", "--timeout", "--proxy", "--user-agent", "--depth",
    "--status-codes", "--extensions", "--script-args-file", "--format", "--database",
}

#: Tools where a bare positional argument is a host.  Deliberately narrow: for
#: hydra/medusa/sqlmap and friends, hosts arrive via URLs or flags.  Resolver
#: tools (dig, nslookup, whois) are excluded because their positional argument
#: is a query name, not a destination.
POSITIONAL_HOST_TOOLS = {
    "nmap", "masscan", "rustscan", "zmap", "ping", "traceroute", "arp-scan", "nbtscan",
    "nc", "ncat", "netcat", "telnet", "ftp", "ssh", "scp", "sftp", "httpx", "nikto",
    "whatweb", "smbclient", "enum4linux",
    "enum4linux-ng", "snmpwalk", "ike-scan", "onesixtyone", "rpcclient", "smbmap",
}

IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])")
URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://([^\s/:'\"<>]+)")
HOSTPORT_RE = re.compile(r"(?<![\w.-])([a-zA-Z0-9][a-zA-Z0-9.-]{2,253}):(\d{1,5})(?![\w-])")
AT_HOST_RE = re.compile(r"[\w.-]+@([a-zA-Z0-9][a-zA-Z0-9.-]*)")

#: Tokens that look like hostnames but are really files, flags or placeholders.
FILE_SUFFIXES = {
    ".txt", ".log", ".md", ".json", ".xml", ".html", ".htm", ".php", ".py", ".sh", ".conf",
    ".bak", ".sql", ".db", ".csv", ".yaml", ".yml", ".ini", ".pem", ".key", ".crt", ".zip",
    ".tar", ".gz", ".jpg", ".png", ".gif", ".pdf", ".out", ".pcap", ".cap", ".bin", ".elf",
    ".pyc", ".so", ".o", ".c", ".h", ".rs", ".go", ".js", ".css", ".svg", ".lock", ".toml",
}


@dataclass
class Decision:
    allowed: bool
    reason: str = ""
    hosts: list[str] = field(default_factory=list)
    risky: str = ""

    def __bool__(self) -> bool:  # pragma: no cover - sugar
        return self.allowed


class ScopeGuard:
    """Decides whether a host or a command is inside the engagement."""

    def __init__(
        self,
        target: str = "",
        scope: Iterable[str] = (),
        *,
        enabled: bool = True,
        allow_private: bool = True,
        allow_loopback: bool = True,
        allow_infrastructure: bool = True,
        infra_hosts: Iterable[str] = INFRASTRUCTURE_HOSTS,
    ) -> None:
        self.target = (target or "").strip()
        self.entries = [self.target, *[s for s in scope if s]]
        self.enabled = enabled
        self.allow_private = allow_private
        self.allow_loopback = allow_loopback
        self.allow_infrastructure = allow_infrastructure
        self.infra_hosts = {h.lower() for h in infra_hosts}
        self._resolved: dict[str, list[str]] = {}

    # ------------------------------------------------------------------ scope
    def describe(self) -> str:
        if not self.enabled:
            return "scope checking disabled (--no-scope-check)"
        parts = [f"target={self.target or '<none>'}"]
        extras = [e for e in self.entries[1:]]
        if extras:
            parts.append("extra scope=" + ",".join(extras))
        if self.allow_private:
            parts.append("private networks allowed")
        return "; ".join(parts)

    def authorize(self, host: str) -> Decision:
        """Is ``host`` an address we are allowed to touch?"""
        host = (host or "").strip().strip("[]").lower().rstrip(".")
        if not host:
            return Decision(False, "empty host")
        if not self.enabled:
            return Decision(True, "scope checking disabled", [host])

        if self._is_infrastructure(host):
            return Decision(True, "infrastructure host", [host])
        if self._matches_entries(host):
            return Decision(True, f"{host} is in scope", [host])

        ip = self._as_ip(host)
        if ip is not None:
            if ip.is_loopback and self.allow_loopback:
                return Decision(True, "loopback", [host])
            if _is_private(ip) and self.allow_private:
                return Decision(True, "private address range", [host])
            return Decision(
                False,
                f"{host} is a public address that is not in scope. Add it with --scope {host} "
                "if you are authorised to test it.",
                [host],
            )

        # A hostname: resolve and re-check the addresses it points at.
        addresses = self._resolve(host)
        if addresses:
            for addr in addresses:
                decision = self.authorize(addr)
                if decision.allowed:
                    return Decision(True, f"{host} -> {addr}: {decision.reason}", [host])
            return Decision(
                False,
                f"{host} resolves to {', '.join(addresses)}, which is outside the authorised scope. "
                f"Add the target with --scope {host} if that is intended.",
                [host],
            )
        if self.allow_infrastructure and "." in host and not _looks_private_name(host):
            return Decision(
                False,
                f"{host} is not in scope and could not be resolved to a private address.",
                [host],
            )
        return Decision(False, f"{host} is not in scope", [host])

    def _matches_entries(self, host: str) -> bool:
        for entry in self.entries:
            entry = entry.strip().lower().rstrip(".")
            if not entry:
                continue
            if entry == host:
                return True
            if entry.startswith("*.") and (host.endswith(entry[1:]) or host == entry[2:]):
                return True
            try:
                network = ipaddress.ip_network(entry, strict=False)
            except ValueError:
                continue
            ip = self._as_ip(host)
            if ip is not None and ip in network:
                return True
            for addr in self._resolve(host):
                try:
                    if ipaddress.ip_address(addr) in network:
                        return True
                except ValueError:
                    continue
        return False

    def _is_infrastructure(self, host: str) -> bool:
        return self.allow_infrastructure and host in self.infra_hosts

    @staticmethod
    def _as_ip(host: str):
        try:
            return ipaddress.ip_address(host.split("/")[0])
        except ValueError:
            return None

    def _resolve(self, host: str) -> list[str]:
        if host in self._resolved:
            return self._resolved[host]
        result: list[str] = []

        def worker() -> None:
            try:
                infos = socket.getaddrinfo(host, None)
            except (socket.gaierror, UnicodeError, OSError):
                return
            for info in infos:
                addr = info[4][0]
                if addr not in result:
                    result.append(addr)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        thread.join(timeout=2.0)
        self._resolved[host] = result
        return result

    # --------------------------------------------------------------- commands
    def check_command(self, command: str, *, tool: str = "shell") -> Decision:
        """Validate a shell command before it reaches a subprocess."""
        command = (command or "").strip()
        if not command:
            return Decision(False, "empty command")

        for pattern, why in DESTRUCTIVE_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return Decision(
                    False,
                    f"Refused: this command would be destructive ({why}). "
                    "Target only the engagement host; never wipe or reconfigure the agent container.",
                    risky="destructive",
                )

        risky = ""
        for pattern, why in RISKY_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                risky = why
                break

        hosts = self.extract_hosts(command, tool=tool)
        if self.enabled:
            for host in hosts:
                decision = self.authorize(host)
                if not decision.allowed:
                    return Decision(False, decision.reason, hosts=hosts, risky=risky)
        return Decision(True, "", hosts=hosts, risky=risky)

    def check_code(self, code: str) -> Decision:
        """Validate a Python snippet.

        Arbitrary code can open its own sockets, so the same scope rules apply.
        Only unambiguous destinations (dotted-quad IPs and URLs) are enforced —
        guessing at hostnames inside source code would produce false positives.
        """
        code = code or ""
        for pattern, why in DESTRUCTIVE_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                return Decision(False, f"Refused: this snippet would be destructive ({why}).")
        if not self.enabled:
            return Decision(True, "")
        hosts: list[str] = []
        for match in IPV4_RE.finditer(code):
            hosts.append(match.group(0))
        for match in URL_RE.finditer(code):
            hosts.append(match.group(1))
        for host in hosts:
            if host.startswith("0."):
                continue
            decision = self.authorize(host)
            if not decision.allowed:
                return Decision(False, decision.reason, hosts=hosts)
        return Decision(True, "", hosts=hosts)

    def extract_hosts(self, command: str, *, tool: str = "shell") -> list[str]:
        """Best-effort list of network destinations inside a command line."""
        hosts: list[str] = []

        def add(value: str) -> None:
            value = value.strip().strip("\"'`,;()[]")
            value = value.split("://")[-1]
            value = value.split("/")[0].split("@")[-1]
            if ":" in value and not value.startswith("["):
                value = value.split(":")[0]
            if not value or value in hosts:
                return
            if value.startswith("-") or value.lower() == "0.0.0.0":
                return  # a flag or a bind address, not a destination
            if value.lower() in {"localhost", "::", "*"}:
                hosts.append(value)
                return
            # Bare name (docker service, hostname). Only count it if it resolves —
            # otherwise header names and usernames get flagged as destinations.
            if "." not in value and ScopeGuard._as_ip(value) is None and not self._resolve(value):
                return
            hosts.append(value)

        for match in IPV4_RE.finditer(command):
            add(match.group(0))
        for match in URL_RE.finditer(command):
            add(match.group(1))
        for match in AT_HOST_RE.finditer(command):
            add(match.group(1))
        for match in HOSTPORT_RE.finditer(command):
            add(match.group(1))

        words = command.split()
        first = _first_executable(words)

        # Hosts passed via an explicit flag: --url http://host, --host 10.0.0.5, ...
        for index, word in enumerate(words[:-1]):
            if word in HOST_FLAGS:
                value = words[index + 1]
                if "://" in value or _looks_like_host(value):
                    add(value)
            elif word == "-h" and first in {"nikto", "whatweb", "droopescan"}:
                add(words[index + 1])

        if first in POSITIONAL_HOST_TOOLS:
            skip_next = False
            for word in words[1:]:
                candidate = word.strip("\"'")
                if skip_next:
                    skip_next = False
                    continue
                if candidate.startswith("-"):
                    skip_next = candidate in FLAGS_WITH_VALUES
                    continue
                if candidate.startswith(("<", "$")):
                    continue
                if _looks_like_host(candidate):
                    add(candidate)

        return hosts


def _first_executable(words: list[str]) -> str:
    skip_prefixes = {"sudo", "env", "time", "nohup", "command", "timeout", "stdbuf", "nice"}
    index = 0
    while index < len(words) and (words[index] in skip_prefixes or "=" in words[index]):
        index += 1
    if index >= len(words):
        return ""
    name = words[index].rsplit("/", 1)[-1].lower()
    return name


def _looks_like_host(token: str) -> bool:
    token = token.strip("\"'`")
    if not token or token.startswith("-") or "=" in token:
        return False
    candidate = token.split("://")[-1].split("/")[0]
    if "@" in candidate:
        candidate = candidate.split("@")[-1]
    if ":" in candidate:
        candidate = candidate.split(":")[0]
    if not candidate or len(candidate) > 253:
        return False
    if candidate.lower().endswith(tuple(FILE_SUFFIXES)):
        return False
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?", candidate):
        return True
    if re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,24}", candidate):
        return True
    # Single-label name (docker service, /etc/hosts entry, NetBIOS name).
    return bool(re.fullmatch(r"[a-zA-Z][a-zA-Z0-9-]{1,62}", candidate))


def _looks_private_name(host: str) -> bool:
    return host.endswith((".local", ".internal", ".lan", ".home", ".localdomain"))


def _is_private(ip) -> bool:
    return bool(
        ip.is_private
        or ip.is_link_local
        or (ip.version == 6 and ip.is_private)
        or ip in ipaddress.ip_network("100.64.0.0/10")
    )

