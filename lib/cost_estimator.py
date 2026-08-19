from __future__ import annotations

from dataclasses import dataclass, field

PHASE_COST: dict[str, float] = {
    "nuclei": 0.05,
    "fuzz": 0.10,
    "recon": 0.02,
    "scan": 0.03,
    "exploit": 0.15,
    "enum": 0.04,
    "brute": 0.08,
    "report": 0.01,
}

COST_PER_API_CALL = 0.001
COST_PER_COMPUTE_SEC = 0.0001
COST_PER_GB_STORAGE = 0.023

_DEFAULT_CONFIG: dict = {
    "api_calls": 50,
    "compute_seconds": 120,
    "storage_gb": 0.1,
}


@dataclass
class CostEstimate:
    total_cost_usd: float
    time_breakdown: dict[str, float]
    api_calls: int
    bandwidth_mb: float
    warnings: list[str] = field(default_factory=list)


def _phase_time(phase: str) -> float:
    """Return estimated seconds for a phase."""
    return PHASE_COST.get(phase, 0.03) / COST_PER_COMPUTE_SEC


def estimate_cost(
    target: str, phases: list[str], config: dict | None = None
) -> CostEstimate:
    """Produce a full cost estimate for the requested phases."""
    cfg = {**_DEFAULT_CONFIG, **(config or {})}
    phase_costs: dict[str, float] = {}
    total_compute = 0.0
    for phase in phases:
        c = PHASE_COST.get(phase, 0.03)
        phase_costs[phase] = c
        total_compute += _phase_time(phase)
    api_cost = cfg["api_calls"] * COST_PER_API_CALL
    compute_cost = total_compute * COST_PER_COMPUTE_SEC
    storage_cost = cfg["storage_gb"] * COST_PER_GB_STORAGE
    total = sum(phase_costs.values()) + api_cost + compute_cost + storage_cost
    bandwidth_mb = cfg.get("bandwidth_mb", cfg["api_calls"] * 0.5)
    warnings: list[str] = []
    if total > 1.0:
        warnings.append(f"Estimated cost ${total:.2f} exceeds $1.00 threshold.")
    if total_compute > 600:
        warnings.append(f"Compute time {total_compute:.0f}s exceeds 10-min target.")
    return CostEstimate(
        total_cost_usd=round(total, 4),
        time_breakdown=phase_costs,
        api_calls=cfg["api_calls"],
        bandwidth_mb=bandwidth_mb,
        warnings=warnings,
    )


def estimate_time(phases: list[str]) -> float:
    """Return total estimated seconds for the given phases."""
    return sum(_phase_time(p) for p in phases)


def estimate_api_calls(phases: list[str]) -> int:
    """Return a rough API-call count for the given phases."""
    calls_per: dict[str, int] = {
        "nuclei": 30,
        "fuzz": 50,
        "recon": 15,
        "scan": 20,
        "exploit": 10,
        "enum": 25,
        "brute": 40,
        "report": 5,
    }
    return sum(calls_per.get(p, 10) for p in phases)
