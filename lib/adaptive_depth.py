"""
lib/adaptive_depth.py — Adaptive scan depth (plan Phase 20)
Expensive phases fire only on delta or explicit flag.
"""
from __future__ import annotations

from lib.delta import has_meaningful_delta, load_baseline, diff


def should_run_deep_phase(
    target: str,
    phase: str,
    current_findings: list[dict],
    cache_dir: str = "cache",
    force: bool = False,
) -> bool:
    """
    Return True if a deep/expensive phase should run for target.

    Rules:
    1. If force=True, always run.
    2. If no baseline exists, run (first scan).
    3. If there is meaningful delta (new/changed findings), run.
    4. Otherwise skip.
    """
    if force:
        return True

    baseline = load_baseline(target, phase, cache_dir)
    if baseline is None:
        return True  # First scan — no baseline

    delta_result = diff(baseline, current_findings)
    return has_meaningful_delta(delta_result)


def get_adaptive_depth(
    target: str,
    baseline_findings: list[dict] | None,
    current_findings: list[dict],
) -> str:
    """
    Return recommended scan depth: "deep" | "light" | "skip".

    - deep: significant new findings (>5 new) or first scan
    - light: some delta (1-5 new findings)
    - skip: no delta
    """
    if baseline_findings is None:
        return "deep"

    delta = diff(baseline_findings, current_findings)
    new_count = delta["summary"]["new_count"]
    changed_count = delta["summary"]["changed_count"]
    total_delta = new_count + changed_count

    if total_delta == 0:
        return "skip"
    if total_delta <= 5:
        return "light"
    return "deep"
