"""Durable recording of the live feed.

Two artefacts per run:

* ``transcript.jsonl`` — every event, machine readable, for later analysis.
* ``feed.txt`` — exactly what the terminal showed, so a run can be reviewed after
  the scrollback is gone (and so ``docker logs`` has a file twin).
"""

from __future__ import annotations

import dataclasses
import json
import time
from pathlib import Path
from typing import Any

from .config import Config
from .events import Event
from .render import PlainRenderer


def _default(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    if isinstance(value, Path):
        return str(value)
    return str(value)


class Transcript:
    def __init__(self, run_dir: Path, config: Config) -> None:
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl = self.run_dir / "transcript.jsonl"
        self.feed_path = self.run_dir / "feed.txt"
        self._jsonl_fh = self.jsonl.open("a", encoding="utf-8")
        self._feed_fh = self.feed_path.open("a", encoding="utf-8")
        self._plain = PlainRenderer(config, stream=self._feed_fh)
        self.started = time.time()

    def handle(self, event: Event) -> None:
        record = {"ts": round(event.ts, 4), "event": event.type, "data": event.data}
        try:
            self._jsonl_fh.write(json.dumps(record, default=_default, ensure_ascii=False) + "\n")
            self._jsonl_fh.flush()
        except (OSError, TypeError, ValueError):
            pass
        try:
            self._plain.handle(event)
            self._feed_fh.flush()
        except (OSError, ValueError):
            pass

    def close(self) -> None:
        for handle in (self._jsonl_fh, self._feed_fh):
            try:
                handle.close()
            except OSError:
                pass

    def __enter__(self) -> Transcript:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
