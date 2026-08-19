from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

_ANALYTICS_DIR = Path("output/.analytics")


@dataclass
class RunMetrics:
    target: str
    timestamp: str
    phases_run: list[str]
    duration_seconds: float
    cpu_seconds: float
    peak_memory_mb: float
    disk_bytes: int
    network_bytes: int


def _metrics_path(target: str) -> Path:
    safe = target.replace("/", "_").replace("\\", "_")
    return _ANALYTICS_DIR / f"{safe}_metrics.jsonl"


def record_run(target: str, metrics: dict) -> None:
    """Append a metrics record for the given target."""
    entry = {
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **metrics,
    }
    _ANALYTICS_DIR.mkdir(parents=True, exist_ok=True)
    path = _metrics_path(target)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def get_usage_history(target: str) -> list[dict]:
    """Return all recorded metric entries for a target."""
    path = _metrics_path(target)
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def analyze_trends(target: str) -> dict:
    """Summarise trend data across recorded runs."""
    history = get_usage_history(target)
    if not history:
        return {"runs": 0, "avg_duration": 0, "avg_memory": 0, "trend": "no data"}
    durations = [h.get("duration_seconds", 0) for h in history]
    memories = [h.get("peak_memory_mb", 0) for h in history]
    avg_dur = sum(durations) / len(durations)
    avg_mem = sum(memories) / len(memories)
    trend = "stable"
    if len(durations) >= 2:
        recent = durations[-1]
        previous = durations[-2]
        if previous > 0:
            change = (recent - previous) / previous
            if change > 0.2:
                trend = "increasing"
            elif change < -0.2:
                trend = "decreasing"
    return {
        "runs": len(history),
        "avg_duration": round(avg_dur, 2),
        "avg_memory": round(avg_mem, 2),
        "trend": trend,
    }


def suggest_optimization(target: str) -> list[str]:
    """Return actionable optimisation suggestions based on history."""
    trends = analyze_trends(target)
    suggestions: list[str] = []
    if trends["runs"] == 0:
        suggestions.append("No run data available – run a scan first.")
        return suggestions
    if trends["avg_duration"] > 300:
        suggestions.append("Consider reducing phase scope to cut duration below 5 min.")
    if trends["avg_memory"] > 512:
        suggestions.append("Peak memory is high – enable streaming for large responses.")
    if trends["trend"] == "increasing":
        suggestions.append("Durations are increasing – investigate new slow endpoints.")
    if not suggestions:
        suggestions.append("Resource usage is within normal ranges.")
    return suggestions
