"""
lib/feedback.py — Feedback loop: triager verdicts update scoring weights (plan Phase 30)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

_FEEDBACK_PATH_TPL = "cache/feedback/{program}.jsonl"
_WEIGHT_ADJUSTMENT = 0.02  # nudge per verdict


def record_verdict(
    program: str,
    tool: str,
    finding_id: str,
    verdict: str,  # "accepted" | "rejected" | "duplicate" | "informational"
    operator: str = "",
    cache_dir: str = "cache",
) -> None:
    """Record a triager verdict for a finding."""
    p = Path(cache_dir) / "feedback" / f"{program}.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "program": program,
        "tool": tool,
        "finding_id": finding_id,
        "verdict": verdict,
        "operator": operator,
    }
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def compute_weight_adjustments(program: str, cache_dir: str = "cache") -> dict[str, float]:
    """
    Compute tool weight nudges based on accepted/rejected verdicts.
    Returns {tool_name: delta} — positive = more reliable, negative = less.
    """
    p = Path(cache_dir) / "feedback" / f"{program}.jsonl"
    if not p.exists():
        return {}

    tool_accepted: dict[str, int] = {}
    tool_rejected: dict[str, int] = {}

    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        tool = r.get("tool", "unknown")
        verdict = r.get("verdict", "")
        if verdict == "accepted":
            tool_accepted[tool] = tool_accepted.get(tool, 0) + 1
        elif verdict == "rejected":
            tool_rejected[tool] = tool_rejected.get(tool, 0) + 1

    adjustments: dict[str, float] = {}
    all_tools = set(tool_accepted) | set(tool_rejected)
    for tool in all_tools:
        accepted = tool_accepted.get(tool, 0)
        rejected = tool_rejected.get(tool, 0)
        total = accepted + rejected
        if total == 0:
            continue
        acceptance_rate = accepted / total
        # Nudge by ±WEIGHT_ADJUSTMENT scaled by deviation from 0.5 baseline
        delta = _WEIGHT_ADJUSTMENT * (acceptance_rate - 0.5) * 2
        adjustments[tool] = round(delta, 4)

    return adjustments


def apply_feedback_to_weights(
    program: str,
    current_weights: dict[str, float],
    cache_dir: str = "cache",
) -> dict[str, float]:
    """
    Apply feedback-based adjustments to tool weights.
    Weights are clamped to [0.1, 0.99].
    """
    adjustments = compute_weight_adjustments(program, cache_dir)
    updated = dict(current_weights)
    for tool, delta in adjustments.items():
        if tool in updated:
            updated[tool] = round(max(0.1, min(0.99, updated[tool] + delta)), 4)
    return updated
