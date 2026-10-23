"""Append-only JSONL audit logger.

Every agent action — LLM calls, tool calls, exploit attempts — is recorded
to `.phalanx/audit-<run_id>.jsonl`. Never rewritten, never truncated.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class AuditLogger:
    """Append-only JSONL audit trail for one agent run."""

    def __init__(self, directory: str | Path, run_id: str | None = None) -> None:
        self.run_id = run_id or uuid.uuid4().hex[:12]
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / f"audit-{self.run_id}.jsonl"
        self._seq = 0
        self._lock = threading.Lock()
        self._fh = self._path.open("a", encoding="utf-8")

    @property
    def path(self) -> Path:
        return self._path

    def log(self, event: str, **data: Any) -> dict[str, Any]:
        """Append one audit record. Returns the record for convenience."""
        with self._lock:
            self._seq += 1
            record = {
                "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
                "run_id": self.run_id,
                "seq": self._seq,
                "pid": os.getpid(),
                "event": event,
                "data": data,
            }
            self._fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
            self._fh.flush()
            return record

    @contextmanager
    def step(self, event: str, **data: Any) -> Iterator[None]:
        """Audit a duration-bearing step: logs `<event>_start` and `<event>_end`."""
        start = time.monotonic()
        self.log(f"{event}_start", **data)
        try:
            yield
        except Exception as exc:  # noqa: BLE001 - audit must capture failures
            self.log(f"{event}_end", status="error", error=str(exc),
                     duration_ms=int((time.monotonic() - start) * 1000), **data)
            raise
        else:
            self.log(f"{event}_end", status="ok",
                     duration_ms=int((time.monotonic() - start) * 1000), **data)

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.close()

    def __enter__(self) -> AuditLogger:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
