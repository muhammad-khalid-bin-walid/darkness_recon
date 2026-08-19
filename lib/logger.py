"""
lib/logger.py — Structured JSON logging for Dark Recon Framework (plan Phase 7)

Emits log records with: level, phase, target, event, duration_ms, timestamp
Compatible with the shell log() function in core.sh.
"""
from __future__ import annotations

import json
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _emit(record: dict, file=None) -> None:
    """Write a JSON log record to file (default: stdout)."""
    if file is None:
        file = sys.stdout
    print(json.dumps(record, default=str), file=file, flush=True)


def log(
    level: str,
    event: str,
    *,
    phase: str = "",
    target: str = "",
    duration_ms: float | None = None,
    extra: dict[str, Any] | None = None,
    file=None,
) -> None:
    """
    Emit a structured JSON log record.

    Parameters
    ----------
    level:      Log level string: INFO, WARN, ERROR, DEBUG
    event:      Human-readable event description
    phase:      Framework phase name (e.g. "subdomain", "fuzz")
    target:     Target domain or IP
    duration_ms: Elapsed time in milliseconds for the logged operation
    extra:      Additional key/value pairs to include in the record
    file:       Output file-like object (default stdout)
    """
    record: dict[str, Any] = {
        "timestamp": _utcnow_iso(),
        "level": level.upper(),
        "event": event,
    }
    if phase:
        record["phase"] = phase
    if target:
        record["target"] = target
    if duration_ms is not None:
        record["duration_ms"] = round(duration_ms, 2)
    if extra:
        record.update(extra)

    _emit(record, file=file)


def info(event: str, **kwargs) -> None:
    log("INFO", event, **kwargs)


def warn(event: str, **kwargs) -> None:
    log("WARN", event, **kwargs)


def error(event: str, **kwargs) -> None:
    log("ERROR", event, **kwargs)


def debug(event: str, **kwargs) -> None:
    log("DEBUG", event, **kwargs)


@contextmanager
def timed(event: str, phase: str = "", target: str = "", level: str = "INFO", **kwargs):
    """
    Context manager that logs an event with its elapsed duration.

    Usage:
        with timed("nuclei_scan", phase="nuclei", target="example.com"):
            run_nuclei(...)
    """
    start = time.monotonic()
    try:
        yield
    finally:
        elapsed_ms = (time.monotonic() - start) * 1000
        log(level, event, phase=phase, target=target, duration_ms=elapsed_ms, **kwargs)


class PhaseLogger:
    """
    Convenience logger bound to a specific phase and target.
    Reduces repetitive kwarg passing.
    """

    def __init__(self, phase: str, target: str = "", file=None):
        self.phase = phase
        self.target = target
        self.file = file

    def info(self, event: str, **extra) -> None:
        log("INFO", event, phase=self.phase, target=self.target, extra=extra or None, file=self.file)

    def warn(self, event: str, **extra) -> None:
        log("WARN", event, phase=self.phase, target=self.target, extra=extra or None, file=self.file)

    def error(self, event: str, **extra) -> None:
        log("ERROR", event, phase=self.phase, target=self.target, extra=extra or None, file=self.file)

    def debug(self, event: str, **extra) -> None:
        log("DEBUG", event, phase=self.phase, target=self.target, extra=extra or None, file=self.file)

    @contextmanager
    def timed(self, event: str, level: str = "INFO", **extra):
        start = time.monotonic()
        try:
            yield
        finally:
            elapsed_ms = (time.monotonic() - start) * 1000
            log(
                level, event,
                phase=self.phase, target=self.target,
                duration_ms=elapsed_ms,
                extra=extra or None,
                file=self.file,
            )
