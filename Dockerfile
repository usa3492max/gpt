# redloop — autonomous offensive-security agent
#
# The image is a Kali toolchain plus the agent. Build once, then run it against
# whatever you are authorised to test:
#
#   docker build -t redloop .
#   docker run --rm -it --env-file .env -v "$PWD/runs:/app/runs" \
#     --add-host host.docker.internal:host-gateway \
#     --cap-add NET_RAW --cap-add NET_ADMIN \
#     redloop --target 10.10.11.42 --i-am-authorized
#
# Build args:
#   TOOLSET=slim   only the core tools (nmap, curl, nc, gobuster, python) — much smaller
#   TOOLSET=full   adds forensics, cracking and reversing tooling (default)
#   BASE_IMAGE=... use a different Kali tag or your own Kali-based base

FROM kalilinux/kali-rolling

ARG DEBIAN_FRONTEND=noninteractive
ARG TOOLSET=full

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/venv/bin:/usr/local/bin:$PATH" \
    REDLOOP_IN_DOCKER=1 \
    WORDLIST=/usr/share/wordlists/dirb/common.txt \
    TERM=xterm-256color \
    LANG=C.UTF-8

WORKDIR /app

# ---------------------------------------------------------------------------
# Base runtime + networking tools. Installed one package at a time so that a
# package renamed in a future Kali snapshot cannot break the whole build.
# ---------------------------------------------------------------------------
RUN set -eux; \
    apt-get update; \
    for pkg in \
        ca-certificates curl wget git jq less file xxd procps iproute2 tcpdump \
        python3 python3-venv python3-dev build-essential libc6-dev pkg-config \
        nmap masscan netcat-traditional socat rlwrap dnsutils whois openssl \
        gobuster ffuf dirb whatweb nikto sqlmap hydra wordlists \
        smbclient smbmap enum4linux ldap-utils snmp redis-tools \
    ; do \
        apt-get install -y --no-install-recommends "$pkg" || echo "redloop: package $pkg unavailable, continuing"; \
    done; \
    rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# CTF / forensics / reversing extras. Skip with --build-arg TOOLSET=slim.
# ---------------------------------------------------------------------------
RUN set -eux; \
    if [ "$TOOLSET" = "full" ]; then \
        apt-get update; \
        for pkg in \
            gdb binutils radare2 strace ltrace binwalk foremost steghide pngcheck \
            libimage-exiftool-perl john hashcat seclists \
            python3-pwntools \
        ; do \
            apt-get install -y --no-install-recommends "$pkg" || echo "redloop: package $pkg unavailable, continuing"; \
        done; \
        rm -rf /var/lib/apt/lists/*; \
    else \
        echo "redloop: slim toolset selected"; \
    fi

# ---------------------------------------------------------------------------
# Python environment for the agent itself.
# ---------------------------------------------------------------------------
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel

COPY pyproject.toml README.md ./
COPY redloop ./redloop
COPY tests ./tests
# The dev extra (pytest, ruff) is installed so `make test` works inside the image.
RUN /opt/venv/bin/pip install --no-cache-dir ".[dev]"

# Libraries that are useful in almost every CTF category, installed after the
# agent so that an install failure here cannot break the CLI.
RUN /opt/venv/bin/pip install --no-cache-dir \
        requests beautifulsoup4 pycryptodome sympy z3-solver pwntools pillow capstone \
    || echo "redloop: some optional CTF libraries failed to install"

COPY docker/entrypoint.sh /usr/local/bin/redloop-entrypoint
COPY labs ./labs
COPY Makefile ./

RUN chmod +x /usr/local/bin/redloop-entrypoint && \
    mkdir -p /app/runs && \
    (command -v setcap >/dev/null && setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap 2>/dev/null || true)

# Run as root inside the container on purpose: raw-socket scanners, binding
# low ports and reading /etc/shadow after a privesc all need it. The container
# is the security boundary — do not add --privileged or mount sensitive paths.
WORKDIR /app
VOLUME ["/app/runs"]
ENTRYPOINT ["/usr/local/bin/redloop-entrypoint"]
CMD ["--help"]
