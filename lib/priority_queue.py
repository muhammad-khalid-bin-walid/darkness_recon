"""
lib/priority_queue.py — Risk-based target prioritization (plan Phase 25)
"""
from __future__ import annotations

from dataclasses import dataclass, field


_CRITICALITY_SCORES = {"prod": 30, "staging": 15, "dev": 5}
_TYPE_SCORES = {"api": 20, "web": 15, "infra": 10}
_TAG_SCORES = {"auth-gated": 10, "public": 5, "external": 8}


@dataclass(order=True)
class PrioritizedTarget:
    priority: float = field(compare=True)
    target: str = field(compare=False)
    asset: dict = field(compare=False, default_factory=dict)

    def __post_init__(self):
        # Invert so highest priority sorts first in a min-heap
        self.priority = -self.priority


def score_target(asset: dict) -> float:
    """Compute a numeric priority score for an asset."""
    score = 0.0
    criticality = asset.get("criticality", "prod")
    score += _CRITICALITY_SCORES.get(criticality, 10)
    asset_type = asset.get("type", "web")
    score += _TYPE_SCORES.get(asset_type, 10)
    for tag in asset.get("tags", []):
        score += _TAG_SCORES.get(tag, 0)
    # Recent findings count bumps priority
    score += min(20, asset.get("findings_count", 0) * 2)
    return score


def prioritize(assets: list[dict]) -> list[dict]:
    """Return assets sorted by priority score, highest first."""
    scored = [(score_target(a), a) for a in assets]
    scored.sort(key=lambda x: x[0], reverse=True)
    return [a for _, a in scored]


def top_n(assets: list[dict], n: int) -> list[dict]:
    """Return top-N highest priority assets."""
    return prioritize(assets)[:n]
