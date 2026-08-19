"""
lib/scoring.py — Confidence-scoring engine (plan Phase 16 + 27)

Weights tool reliability, not raw source count.
Also implements confidence decay over time (Phase 27).
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Default tool reliability coefficients (0.0–1.0)
# Loaded from config/tool_weights.conf if present, else these defaults apply.
# ---------------------------------------------------------------------------

DEFAULT_TOOL_WEIGHTS: dict[str, float] = {
    "subfinder":    0.85,
    "assetfinder":  0.80,
    "amass":        0.88,
    "findomain":    0.82,
    "httpx":        0.95,
    "nuclei":       0.80,
    "katana":       0.90,
    "gospider":     0.78,
    "hakrawler":    0.75,
    "dnsx":         0.90,
    "ffuf":         0.85,
    "gobuster":     0.82,
    "nmap":         0.92,
    "naabu":        0.85,
    "trufflehog":   0.82,
    "gitrob":       0.78,
    "subjack":      0.80,
    "subzy":        0.78,
    "manual":       0.99,
    "unknown":      0.50,
}

# Evidence quality multipliers
EVIDENCE_QUALITY_MULTIPLIERS: dict[str, float] = {
    "reproduced":   1.0,
    "strong":       0.90,
    "moderate":     0.70,
    "weak":         0.40,
    "inferred":     0.25,
    "none":         0.10,
}

# Decay settings (Phase 27)
DEFAULT_DECAY_HALF_LIFE_DAYS = 30   # confidence halves every 30 days without validation
MIN_CONFIDENCE_AFTER_DECAY = 0.05   # never decays below this


def _load_weights(weights_file: str | Path | None = None) -> dict[str, float]:
    """Load tool weights from config/tool_weights.conf or return defaults."""
    if weights_file is None:
        weights_file = Path("config/tool_weights.conf")
    p = Path(weights_file)
    if not p.exists():
        return dict(DEFAULT_TOOL_WEIGHTS)
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return dict(DEFAULT_TOOL_WEIGHTS)


class ConfidenceEngine:
    """
    Computes confidence scores for findings based on tool reliability,
    source corroboration, and evidence quality.
    """

    def __init__(self, weights_file: str | Path | None = None):
        self.weights = _load_weights(weights_file)

    def tool_weight(self, tool: str) -> float:
        """Return reliability coefficient for a tool (0.0–1.0)."""
        return self.weights.get(tool.lower(), self.weights.get("unknown", 0.50))

    def score(
        self,
        sources: list[str],
        evidence_quality: str = "moderate",
        cross_validated: bool = False,
        manual_verified: bool = False,
    ) -> float:
        """
        Compute a confidence score 0.0–1.0.

        Parameters
        ----------
        sources:          List of tool names that detected the finding.
        evidence_quality: One of: reproduced, strong, moderate, weak, inferred, none.
        cross_validated:  True if independently confirmed via a second method.
        manual_verified:  True if a human analyst confirmed the finding.
        """
        if not sources:
            return 0.0

        # Average tool reliability across sources
        tool_avg = sum(self.tool_weight(t) for t in sources) / len(sources)

        # Source count multiplier (more corroboration = higher score)
        count = len(sources)
        if count >= 4:
            count_mult = 1.00
        elif count == 3:
            count_mult = 0.92
        elif count == 2:
            count_mult = 0.82
        else:
            count_mult = 0.65

        # Evidence quality multiplier
        qual_mult = EVIDENCE_QUALITY_MULTIPLIERS.get(evidence_quality.lower(), 0.50)

        # Base score
        base = tool_avg * count_mult * qual_mult

        # Bonuses
        if cross_validated:
            base = min(1.0, base + 0.10)
        if manual_verified:
            base = min(1.0, base + 0.15)

        return round(min(1.0, max(0.0, base)), 4)

    def score_finding(self, finding: dict) -> float:
        """Convenience: score a Finding dict using its tool/evidence fields."""
        tool = finding.get("tool") or "unknown"
        sources = [tool]
        if "corroborating_tools" in finding:
            sources += list(finding["corroborating_tools"])
        evidence_quality = finding.get("evidence_quality", "moderate")
        cross_validated = bool(finding.get("cross_validated", False))
        manual_verified = bool(finding.get("status") == "validated")
        return self.score(sources, evidence_quality, cross_validated, manual_verified)


# ---------------------------------------------------------------------------
# Confidence decay (Phase 27)
# ---------------------------------------------------------------------------

def apply_decay(
    confidence: float,
    last_validated: datetime,
    half_life_days: int = DEFAULT_DECAY_HALF_LIFE_DAYS,
    now: datetime | None = None,
) -> float:
    """
    Apply exponential decay to a confidence score based on time since last validation.

    confidence * 0.5^(days_elapsed / half_life_days)

    Returns decayed confidence, never below MIN_CONFIDENCE_AFTER_DECAY.
    """
    if now is None:
        now = datetime.now(timezone.utc)
    # Ensure both are timezone-aware
    if last_validated.tzinfo is None:
        last_validated = last_validated.replace(tzinfo=timezone.utc)
    days_elapsed = (now - last_validated).total_seconds() / 86400.0
    if days_elapsed <= 0:
        return confidence
    decayed = confidence * (0.5 ** (days_elapsed / half_life_days))
    return round(max(MIN_CONFIDENCE_AFTER_DECAY, decayed), 4)


def is_stale(
    last_validated: datetime,
    stale_threshold_days: int = 60,
    now: datetime | None = None,
) -> bool:
    """Return True if a finding hasn't been validated in stale_threshold_days."""
    if now is None:
        now = datetime.now(timezone.utc)
    if last_validated.tzinfo is None:
        last_validated = last_validated.replace(tzinfo=timezone.utc)
    return (now - last_validated).days >= stale_threshold_days
