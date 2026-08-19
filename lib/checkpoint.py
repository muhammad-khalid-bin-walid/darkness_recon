"""
lib/checkpoint.py — Per-target per-phase checkpoint/resume for Dark Recon Framework

Stores checkpoint state as JSON files in output/{target}/.checkpoints/{phase}.json
Enables phases to resume from the last saved state on re-run.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utcnow_iso() -> str:
    return _utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _output_root() -> Path:
    """Return the base output directory (relative to project root)."""
    return Path("output")


def _checkpoint_dir(target: str) -> Path:
    """Return the checkpoint directory for a given target."""
    return _output_root() / target / ".checkpoints"


def _checkpoint_path(phase: str, target: str) -> Path:
    """Return the full path to a phase checkpoint file."""
    return _checkpoint_dir(target) / f"{phase}.json"


# ---------------------------------------------------------------------------
# Checkpoint data model
# ---------------------------------------------------------------------------


@dataclass
class Checkpoint:
    """A single phase checkpoint record."""

    phase: str
    target: str
    status: str  # "running" | "completed" | "failed"
    started_at: str
    completed_at: str | None = None
    last_file: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Checkpoint":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


# ---------------------------------------------------------------------------
# Core checkpoint I/O
# ---------------------------------------------------------------------------


def save_checkpoint(
    phase: str,
    target: str,
    status: str,
    metadata: dict[str, Any] | None = None,
    *,
    last_file: str | None = None,
) -> Checkpoint:
    """
    Save or update a checkpoint for *phase*/*target*.

    Parameters
    ----------
    phase:      Framework phase name (e.g. "subdomain", "fuzz")
    target:     Target domain or IP
    status:     One of "running", "completed", "failed"
    metadata:   Arbitrary key/value data to persist with the checkpoint
    last_file:  Path to the last output file written by the phase

    Returns
    -------
    The saved Checkpoint instance.
    """
    path = _checkpoint_path(phase, target)
    path.parent.mkdir(parents=True, exist_ok=True)

    now = _utcnow_iso()

    # If an existing checkpoint exists, preserve its started_at
    started_at = now
    if path.exists():
        try:
            existing = load_checkpoint(phase, target)
            started_at = existing.started_at
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    completed_at = now if status in ("completed", "failed") else None

    ckpt = Checkpoint(
        phase=phase,
        target=target,
        status=status,
        started_at=started_at,
        completed_at=completed_at,
        last_file=last_file,
        metadata=metadata or {},
    )

    path.write_text(json.dumps(ckpt.to_dict(), indent=2, default=str), encoding="utf-8")
    return ckpt


def load_checkpoint(phase: str, target: str) -> Checkpoint:
    """
    Load a checkpoint from disk.

    Parameters
    ----------
    phase:  Framework phase name
    target: Target domain or IP

    Raises
    ------
    FileNotFoundError:  If no checkpoint exists for this phase/target
    json.JSONDecodeError: If the checkpoint file is malformed
    """
    path = _checkpoint_path(phase, target)
    if not path.exists():
        raise FileNotFoundError(f"No checkpoint for phase={phase!r}, target={target!r}")

    data = json.loads(path.read_text(encoding="utf-8"))
    return Checkpoint.from_dict(data)


def is_completed(phase: str, target: str) -> bool:
    """
    Return True if the phase has a "completed" checkpoint on disk.

    Parameters
    ----------
    phase:  Framework phase name
    target: Target domain or IP
    """
    try:
        ckpt = load_checkpoint(phase, target)
        return ckpt.status == "completed"
    except FileNotFoundError:
        return False


def clear_checkpoint(phase: str, target: str) -> bool:
    """
    Remove a checkpoint file if it exists.

    Parameters
    ----------
    phase:  Framework phase name
    target: Target domain or IP

    Returns
    -------
    True if a file was removed, False if it didn't exist.
    """
    path = _checkpoint_path(phase, target)
    if path.exists():
        path.unlink()
        return True
    return False


def get_all_checkpoints(target: str) -> list[Checkpoint]:
    """
    List every checkpoint stored for *target*, sorted by phase name.

    Parameters
    ----------
    target: Target domain or IP
    """
    ckpt_dir = _checkpoint_dir(target)
    if not ckpt_dir.exists():
        return []

    checkpoints: list[Checkpoint] = []
    for f in sorted(ckpt_dir.glob("*.json")):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            checkpoints.append(Checkpoint.from_dict(data))
        except (json.JSONDecodeError, KeyError, TypeError):
            continue
    return checkpoints


def list_stale_checkpoints(target: str, max_age_hours: int = 24) -> list[Checkpoint]:
    """
    Find incomplete checkpoints older than *max_age_hours*.

    A checkpoint is considered stale if its status is "running" and
    its started_at timestamp is older than the specified threshold.

    Parameters
    ----------
    target:         Target domain or IP
    max_age_hours:  Maximum age in hours before a running checkpoint is stale

    Returns
    -------
    List of stale Checkpoint instances, oldest first.
    """
    all_ckpts = get_all_checkpoints(target)
    cutoff = _utcnow() - timedelta(hours=max_age_hours)
    stale: list[Checkpoint] = []

    for ckpt in all_ckpts:
        if ckpt.status != "running":
            continue
        try:
            started = datetime.fromisoformat(ckpt.started_at.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            continue
        if started < cutoff:
            stale.append(ckpt)

    return stale
