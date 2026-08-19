"""
lib/delta.py — Delta/diff engine (plan Phase 19)

Every re-scan diffs against last known-good state.
Baselines stored in cache/baselines/<target>/<phase>.json
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def _load_json(path: Path) -> list | dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _fingerprint(item: dict) -> str:
    """Generate a stable fingerprint for a finding/asset dict."""
    return item.get("fingerprint") or item.get("id") or f"{item.get('title','')}|{item.get('asset_id','')}"


def load_baseline(target: str, phase: str, cache_dir: str = "cache") -> list[dict] | None:
    """Load the last known-good baseline for target+phase."""
    p = Path(cache_dir) / "baselines" / target / f"{phase}.json"
    data = _load_json(p)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("findings", [])
    return None


def save_baseline(target: str, phase: str, findings: list[dict], cache_dir: str = "cache") -> None:
    """Persist current scan results as the new baseline."""
    p = Path(cache_dir) / "baselines" / target / f"{phase}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps({"target": target, "phase": phase, "saved_at": datetime.now(timezone.utc).isoformat(), "findings": findings}, indent=2),
        encoding="utf-8",
    )


def diff(
    baseline: list[dict],
    current: list[dict],
) -> dict:
    """
    Compare current scan results against baseline.

    Returns:
        {
            "new":      [...],   # in current but not in baseline
            "resolved": [...],   # in baseline but not in current
            "unchanged":[...],   # in both
            "changed":  [...],   # fingerprint same but content differs
        }
    """
    base_map = {_fingerprint(f): f for f in baseline}
    curr_map = {_fingerprint(f): f for f in current}

    new_fps = set(curr_map) - set(base_map)
    resolved_fps = set(base_map) - set(curr_map)
    shared_fps = set(base_map) & set(curr_map)

    changed = []
    unchanged = []
    for fp in shared_fps:
        if json.dumps(base_map[fp], sort_keys=True) != json.dumps(curr_map[fp], sort_keys=True):
            changed.append({"before": base_map[fp], "after": curr_map[fp]})
        else:
            unchanged.append(curr_map[fp])

    return {
        "new": [curr_map[fp] for fp in new_fps],
        "resolved": [base_map[fp] for fp in resolved_fps],
        "unchanged": unchanged,
        "changed": changed,
        "summary": {
            "new_count": len(new_fps),
            "resolved_count": len(resolved_fps),
            "changed_count": len(changed),
            "unchanged_count": len(unchanged),
        },
    }


def has_meaningful_delta(delta_result: dict) -> bool:
    """Return True if there are new or changed findings worth deep-scanning."""
    return (delta_result["summary"]["new_count"] + delta_result["summary"]["changed_count"]) > 0
