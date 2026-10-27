"""File tools for reading notes, payloads and challenge artefacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .base import Tool, ToolContext, ToolResult, strip_ansi, truncate

READ_LIMIT = 200_000


class ReadFileTool(Tool):
    name = "read_file"
    summary = "Read a text or binary file inside the container (challenge files, source, wordlists)."
    args = {"path": "absolute path, or a path relative to the current work directory"}
    required = ("path",)
    side_effect_free = True

    async def run(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        path = _resolve_read(args.get("path", ""), ctx)
        if path is None:
            return ToolResult(False, "no such file (give an absolute path inside the container)")
        if not path.exists():
            return ToolResult(False, f"{path} does not exist")
        if path.is_dir():
            return ToolResult(False, f"{path} is a directory — use list_dir")
        try:
            data = path.read_bytes()[:READ_LIMIT]
        except OSError as exc:
            return ToolResult(False, f"cannot read {path}: {exc}")

        if _is_binary(data):
            preview = data[:1024]
            text = (
                f"{path} ({path.stat().st_size} bytes, binary)\n"
                f"hex:\n{preview.hex(' ')}\n"
                f'printable:\n{preview.decode("latin-1").translate(_PRINTABLE)}'
            )
            return ToolResult(True, text, meta={"path": str(path), "binary": True})

        text = strip_ansi(data.decode("utf-8", errors="replace"))
        payload, truncated = truncate(text, ctx.config.max_output_chars)
        if truncated:
            text = payload
        return ToolResult(
            True,
            f"{path} ({len(data)} bytes)\n" + "─" * 40 + "\n" + text,
            meta={"path": str(path), "bytes": len(data)},
            truncated=truncated,
        )


class WriteFileTool(Tool):
    name = "write_file"
    summary = "Write a file (exploit script, payload, notes) into the run's work directory."
    args = {
        "path": "file name or path; relative paths land in the work directory",
        "content": "exact file content",
    }
    required = ("path", "content")

    async def run(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        raw = str(args.get("path", "")).strip()
        content = str(args.get("content", ""))
        if not raw:
            return ToolResult(False, "missing path")
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = ctx.work_dir / candidate
        target = candidate.resolve()
        allowed_roots = [ctx.run_dir.resolve(), Path("/tmp").resolve()]
        if not any(_is_within(target, root) for root in allowed_roots):
            return ToolResult(
                False,
                f"Refused: writes are confined to the run directory ({ctx.run_dir}) and /tmp. "
                f"Use a relative path to write into {ctx.work_dir}.",
            )
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        except OSError as exc:
            return ToolResult(False, f"cannot write {target}: {exc}")
        return ToolResult(
            True, f"wrote {len(content)} bytes to {target}", meta={"path": str(target)}
        )


class ListDirTool(Tool):
    name = "list_dir"
    summary = "List a directory (challenge files, loot, wordlists)."
    args = {"path": "directory path; defaults to the work directory"}
    side_effect_free = True

    async def run(self, args: dict[str, Any], ctx: ToolContext) -> ToolResult:
        raw = str(args.get("path") or ".").strip()
        path = Path(raw)
        if not path.is_absolute():
            path = ctx.work_dir / path
        try:
            path = path.resolve()
        except OSError as exc:
            return ToolResult(False, f"bad path: {exc}")
        if not path.exists():
            return ToolResult(False, f"{path} does not exist")
        if not path.is_dir():
            return ToolResult(False, f"{path} is a file — use read_file")
        entries = []
        try:
            for child in sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name))[:400]:
                try:
                    size = child.stat().st_size if child.is_file() else 0
                except OSError:
                    size = 0
                marker = "/" if child.is_dir() else ""
                entries.append(f"{child.name}{marker}" + (f"  ({size}B)" if size else ""))
        except OSError as exc:
            return ToolResult(False, f"cannot list {path}: {exc}")
        body = "\n".join(entries) if entries else "[empty directory]"
        return ToolResult(True, f"{path}:\n{body}", meta={"path": str(path), "count": len(entries)})


_PRINTABLE = {i: (i if 32 <= i < 127 else ord(".")) for i in range(256)}


def _resolve_read(raw: Any, ctx: ToolContext) -> Path | None:
    text = str(raw or "").strip()
    if not text:
        return None
    path = Path(text)
    if not path.is_absolute():
        path = ctx.work_dir / path
    try:
        return path.resolve()
    except OSError:
        return None


def _is_binary(data: bytes) -> bool:
    if b"\x00" in data[:4096]:
        return True
    sample = data[:4096]
    if not sample:
        return False
    printable = sum(1 for byte in sample if 32 <= byte < 127 or byte in (9, 10, 13))
    return printable / len(sample) < 0.85


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
