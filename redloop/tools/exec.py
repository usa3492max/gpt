"""Subprocess execution with hard timeouts, output caps and clean teardown."""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from dataclasses import dataclass
from pathlib import Path

#: Never buffer more than this per command; a runaway ``cat /dev/zero`` must not
#: be able to exhaust the container's memory.
STREAM_CAP = 2 * 1024 * 1024
READ_CHUNK = 65536


@dataclass
class ProcResult:
    output: str
    exit_code: int | None
    timed_out: bool
    overflow: bool
    duration: float

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


def shell_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "TERM": "xterm-256color",
            "PAGER": "cat",
            "GIT_PAGER": "cat",
            "LESS": "-R",
            "DEBIAN_FRONTEND": "noninteractive",
            "PYTHONUNBUFFERED": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "NO_COLOR": "",
            "REDLOOP_AGENT": "1",
        }
    )
    env.pop("NO_COLOR", None)
    if extra:
        env.update(extra)
    return env


async def _read_capped(stream: asyncio.StreamReader | None, cap: int) -> tuple[bytes, bool]:
    if stream is None:
        return b"", False
    buffer = bytearray()
    overflow = False
    while True:
        try:
            chunk = await stream.read(READ_CHUNK)
        except (asyncio.IncompleteReadError, ConnectionResetError, ValueError):
            break
        if not chunk:
            break
        if len(buffer) < cap:
            buffer.extend(chunk[: cap - len(buffer)])
        else:
            overflow = True
        if len(buffer) >= cap:
            overflow = True
    return bytes(buffer), overflow


def kill_tree(proc: asyncio.subprocess.Process) -> None:
    """Kill the process *and* anything it spawned (nmap piping into tee, etc.)."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        return
    except (ProcessLookupError, PermissionError, AttributeError, OSError):
        pass
    try:
        proc.kill()
    except (ProcessLookupError, PermissionError):
        pass


async def run_process(
    spec: str | list[str],
    *,
    cwd: Path | str,
    timeout: float,
    cap: int = STREAM_CAP,
    env_extra: dict[str, str] | None = None,
    use_shell: bool | None = None,
) -> ProcResult:
    """Run a command, returning captured output plus a timeout/overflow verdict."""
    import time

    started = time.monotonic()
    if use_shell is None:
        use_shell = isinstance(spec, str)

    kwargs = {}
    if sys.platform != "win32":
        kwargs["start_new_session"] = True

    try:
        proc = await asyncio.create_subprocess_shell(
            spec,  # type: ignore[arg-type]
            cwd=str(cwd),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=shell_env(env_extra),
            **kwargs,
        ) if use_shell else await asyncio.create_subprocess_exec(
            *spec,  # type: ignore[misc]
            cwd=str(cwd),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=shell_env(env_extra),
            **kwargs,
        )
    except FileNotFoundError as exc:
        return ProcResult(f"command not found: {exc}", 127, False, False, 0.0)
    except PermissionError as exc:
        return ProcResult(f"permission denied: {exc}", 126, False, False, 0.0)
    except OSError as exc:
        return ProcResult(f"could not start command: {exc}", 126, False, False, 0.0)

    reader = asyncio.create_task(_read_capped(proc.stdout, cap))
    timed_out = False
    overrun = False
    try:
        await asyncio.wait_for(proc.wait(), timeout=max(1.0, float(timeout)))
    except asyncio.TimeoutError:
        timed_out = True
        kill_tree(proc)
        try:
            await asyncio.wait_for(proc.wait(), 5.0)
        except asyncio.TimeoutError:  # pragma: no cover - extremely rare
            pass
    try:
        data, overrun = await asyncio.wait_for(reader, 10.0)
    except asyncio.TimeoutError:  # pragma: no cover
        reader.cancel()
        data, overrun = b"", True

    # If we killed it for overflow, make sure nothing is left running.
    if overrun and not timed_out:
        if proc.returncode is None:
            kill_tree(proc)
        else:
            kill_tree(proc)

    text = _decode(data)
    if timed_out:
        text += f"\n[redloop] command exceeded the {int(timeout)}s timeout and was killed."
    if overrun:
        text += "\n[redloop] output exceeded the capture limit and was truncated."
    return ProcResult(
        output=text,
        exit_code=proc.returncode,
        timed_out=timed_out,
        overflow=overrun,
        duration=time.monotonic() - started,
    )


def _decode(data: bytes) -> str:
    if not data:
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")
