"""Tool registry."""

from __future__ import annotations

from .base import Tool, ToolContext, ToolResult, truncate
from .code import PythonTool
from .control import GiveUpTool, SubmitFlagTool
from .files import ListDirTool, ReadFileTool, WriteFileTool
from .http import HttpTool
from .memory_tools import FindingTool, NoteTool
from .shell import ShellTool


def build_registry() -> dict[str, Tool]:
    tools: list[Tool] = [
        ShellTool(),
        PythonTool(),
        HttpTool(),
        ReadFileTool(),
        WriteFileTool(),
        ListDirTool(),
        NoteTool(),
        FindingTool(),
        SubmitFlagTool(),
        GiveUpTool(),
    ]
    return {tool.name: tool for tool in tools}


def tool_help(registry: dict[str, Tool]) -> str:
    return "\n".join(tool.help_text() for tool in registry.values())


def tool_names(registry: dict[str, Tool]) -> list[str]:
    return list(registry)


__all__ = [
    "Tool",
    "ToolContext",
    "ToolResult",
    "build_registry",
    "tool_help",
    "tool_names",
    "truncate",
]
