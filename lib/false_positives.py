"""
lib/false_positives.py — Persistent false-positive suppression (plan Phase 18)

Per-program FP lists stored in cache/fp/<program>.json
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def _fp_path(program: str, cache_dir: str = "cache") -> Path:
    return Path(cache_dir) / "fp" / f"{program}.json"


def _load(program: str, cache_dir: str = "cache") -> list[dict]:
    p = _fp_path(program, cache_dir)
    if not p.exists():
        return []
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return []


def _save(program: str, entries: list[dict], cache_dir: str = "cache") -> None:
    p = _fp_path(program, cache_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(entries, indent=2), encoding="utf-8")


def add_false_positive(
    program: str,
    fingerprint: str,
    reason: str = "",
    operator: str = "",
    cache_dir: str = "cache",
) -> None:
    """Add a fingerprint to the program's FP suppression list."""
    entries = _load(program, cache_dir)
    # Avoid duplicates
    if any(e["fingerprint"] == fingerprint for e in entries):
        return
    entries.append({
        "fingerprint": fingerprint,
        "reason": reason,
        "operator": operator,
        "added_at": datetime.now(timezone.utc).isoformat(),
    })
    _save(program, entries, cache_dir)


def is_false_positive(program: str, fingerprint: str, cache_dir: str = "cache") -> bool:
    """Return True if the fingerprint is in the program's FP list."""
    return any(e["fingerprint"] == fingerprint for e in _load(program, cache_dir))


def list_false_positives(program: str, cache_dir: str = "cache") -> list[dict]:
    """Return all FP entries for a program."""
    return _load(program, cache_dir)


def remove_false_positive(program: str, fingerprint: str, cache_dir: str = "cache") -> bool:
    """Remove a fingerprint from the FP list. Returns True if removed."""
    entries = _load(program, cache_dir)
    filtered = [e for e in entries if e["fingerprint"] != fingerprint]
    if len(filtered) == len(entries):
        return False
    _save(program, filtered, cache_dir)
    return True


def filter_findings(
    program: str,
    findings: list[dict],
    cache_dir: str = "cache",
) -> tuple[list[dict], list[dict]]:
    """
    Split findings into (valid, suppressed) based on FP list.
    Returns (non-fp findings, fp-suppressed findings).
    """
    fp_fps = {e["fingerprint"] for e in _load(program, cache_dir)}
    valid, suppressed = [], []
    for f in findings:
        fp = f.get("fingerprint") or f"{f.get('title','')}|{f.get('asset_id','')}"
        if fp in fp_fps:
            suppressed.append(f)
        else:
            valid.append(f)
    return valid, suppressed
