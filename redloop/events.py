"""A tiny synchronous event bus.

The agent never talks to the terminal, the session log or the report writer
directly: it emits events.  Renderers, the transcript recorder and any future
consumer subscribe to those events.  Keeping the boundary this narrow means the
whole agent can be driven head-less in tests (``NullRenderer``) or streamed to a
web UI later without touching the loop.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Event:
    type: str
    data: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)


Listener = Callable[[Event], None]


class EventBus:
    """Fan-out dispatcher. A broken listener must never take down a run."""

    #: Event types worth persisting to the session transcript.
    PERSISTED = {
        "session_start",
        "step_start",
        "thought",
        "action",
        "observation",
        "finding",
        "flag",
        "blocked",
        "warning",
        "error",
        "compaction",
        "session_end",
    }

    def __init__(self) -> None:
        self._listeners: list[Listener] = []
        self.errors: list[tuple[str, Exception]] = []

    def subscribe(self, listener: Listener) -> None:
        self._listeners.append(listener)

    def emit(self, type_: str, **data: Any) -> Event:
        event = Event(type=type_, data=data)
        for listener in list(self._listeners):
            try:
                listener(event)
            except Exception as exc:  # pragma: no cover - defensive
                self.errors.append((type_, exc))
        return event

    @property
    def listeners(self) -> list[Listener]:
        return list(self._listeners)


class NullRenderer:
    """A renderer that records events instead of drawing them."""

    def __init__(self) -> None:
        self.events: list[Event] = []

    def handle(self, event: Event) -> None:
        self.events.append(event)

    # Convenience helpers used in tests.
    def of_type(self, type_: str) -> list[Event]:
        return [e for e in self.events if e.type == type_]

    def types(self) -> list[str]:
        return [e.type for e in self.events]
