"""
lib/trend_store.py — Historical trend store (plan Phase 23)

Records findings/hour, false-positive rate, mean-time-to-validate.
Stored in cache/trends/<program>.jsonl
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean


def _trend_path(program: str, cache_dir: str = "cache") -> Path:
    return Path(cache_dir) / "trends" / f"{program}.jsonl"


def record_scan(
    program: str,
    scan_run_id: str,
    findings_count: int,
    false_positive_count: int,
    duration_hours: float,
    validated_count: int = 0,
    mean_time_to_validate_hours: float = 0.0,
    cache_dir: str = "cache",
) -> None:
    """Append a scan metrics record to the trend store."""
    p = _trend_path(program, cache_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_run_id": scan_run_id,
        "findings_count": findings_count,
        "false_positive_count": false_positive_count,
        "duration_hours": duration_hours,
        "findings_per_hour": round(findings_count / duration_hours, 2) if duration_hours > 0 else 0.0,
        "fp_rate": round(false_positive_count / findings_count, 4) if findings_count > 0 else 0.0,
        "validated_count": validated_count,
        "mean_time_to_validate_hours": mean_time_to_validate_hours,
    }
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def load_trends(program: str, cache_dir: str = "cache") -> list[dict]:
    """Load all trend records for a program."""
    p = _trend_path(program, cache_dir)
    if not p.exists():
        return []
    records = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def summarize_trends(program: str, cache_dir: str = "cache") -> dict:
    """Return aggregate trend metrics for a program."""
    records = load_trends(program, cache_dir)
    if not records:
        return {"program": program, "scans": 0}

    fps_per_hour = [r["findings_per_hour"] for r in records if r.get("findings_per_hour") is not None]
    fp_rates = [r["fp_rate"] for r in records if r.get("fp_rate") is not None]
    mttv = [r["mean_time_to_validate_hours"] for r in records if r.get("mean_time_to_validate_hours", 0) > 0]

    return {
        "program": program,
        "scans": len(records),
        "avg_findings_per_hour": round(mean(fps_per_hour), 2) if fps_per_hour else 0.0,
        "avg_fp_rate": round(mean(fp_rates), 4) if fp_rates else 0.0,
        "avg_mttv_hours": round(mean(mttv), 2) if mttv else 0.0,
        "total_findings": sum(r.get("findings_count", 0) for r in records),
        "total_false_positives": sum(r.get("false_positive_count", 0) for r in records),
    }
