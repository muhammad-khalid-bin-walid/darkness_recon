from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

PRIORITY_MAP: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

_lock = threading.Lock()
_base_dir = Path("output/.queues")


def _queue_path(queue_name: str) -> Path:
    return _base_dir / f"{queue_name}.jsonl"


def enqueue(result: dict, queue_name: str = "default") -> dict:
    """Append a result to the named queue with auto-assigned metadata."""
    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "priority": PRIORITY_MAP.get(result.get("priority", "medium"), 2),
        **result,
    }
    with _lock:
        path = _queue_path(queue_name)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


def dequeue(queue_name: str = "default") -> dict | None:
    """Pop the highest-priority (lowest number) entry from the queue."""
    with _lock:
        path = _queue_path(queue_name)
        if not path.exists():
            return None
        lines = path.read_text(encoding="utf-8").splitlines()
        if not lines:
            return None
        entries = [json.loads(line) for line in lines if line.strip()]
        entries.sort(key=lambda e: (e.get("priority", 4), e.get("timestamp", "")))
        chosen = entries.pop(0)
        path.write_text(
            "\n".join(json.dumps(e, ensure_ascii=False) for e in entries) + "\n"
            if entries
            else "",
            encoding="utf-8",
        )
        return chosen


def peek(queue_name: str = "default", n: int = 5) -> list[dict]:
    """Return up to *n* entries without removing them, sorted by priority."""
    with _lock:
        path = _queue_path(queue_name)
        if not path.exists():
            return []
        lines = path.read_text(encoding="utf-8").splitlines()
        entries = [json.loads(line) for line in lines if line.strip()]
        entries.sort(key=lambda e: (e.get("priority", 4), e.get("timestamp", "")))
        return entries[:n]


def size(queue_name: str = "default") -> int:
    """Return the number of entries in the queue."""
    with _lock:
        path = _queue_path(queue_name)
        if not path.exists():
            return 0
        lines = path.read_text(encoding="utf-8").splitlines()
        return sum(1 for line in lines if line.strip())


def clear(queue_name: str = "default") -> None:
    """Remove all entries from the queue."""
    with _lock:
        path = _queue_path(queue_name)
        if path.exists():
            path.write_text("", encoding="utf-8")


def list_queues() -> list[str]:
    """Return names of all existing queues."""
    if not _base_dir.exists():
        return []
    return sorted(p.stem for p in _base_dir.glob("*.jsonl"))
