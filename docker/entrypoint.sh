#!/usr/bin/env bash
# Container entrypoint: tiny sanity checks, then hand over to the agent.
set -euo pipefail

if [ ! -w /app/runs ] 2>/dev/null; then
    echo "redloop: /app/runs is not writable — mount a volume there, e.g." >&2
    echo "  docker run -v \"\$PWD/runs:/app/runs\" ..." >&2
fi

# Ollama on the host is not reachable as "localhost" from inside the container.
if [ "${REDLOOP_PROVIDER:-${1:-}}" = "ollama" ] && [ -z "${OLLAMA_HOST:-}" ] && [ -z "${REDLOOP_BASE_URL:-}" ]; then
    if ! getent hosts host.docker.internal >/dev/null 2>&1; then
        echo "redloop: provider is ollama but host.docker.internal does not resolve." >&2
        echo "  start the container with:  --add-host host.docker.internal:host-gateway" >&2
    else
        export OLLAMA_HOST="${OLLAMA_HOST:-http://host.docker.internal:11434}"
        echo "redloop: using Ollama at $OLLAMA_HOST" >&2
    fi
fi

# NET_ADMIN (bit 12) is not in Docker's default capability set. Without it nmap
# falls back from SYN scans and masscan refuses to start.
caps="${REDLOOP_CAPS_WARNING:-1}"
if [ "$caps" = "1" ]; then
    eff="$(awk '/^CapEff:/{print $2}' /proc/self/status 2>/dev/null || true)"
    if [ -n "$eff" ] && [ "$eff" != "0000000000000000" ]; then
        value=$((16#$eff)) 2>/dev/null || value=0
        if [ $(( (value >> 12) & 1 )) -eq 0 ]; then
            echo "redloop: NET_ADMIN is not granted — nmap will use connect() scans and masscan" >&2
            echo "  will not run. Re-run with --cap-add NET_RAW --cap-add NET_ADMIN for full uptime." >&2
        fi
    fi
fi

exec redloop "$@"
