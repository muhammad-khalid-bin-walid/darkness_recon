from __future__ import annotations

import json
from pathlib import Path

_PROFILES_DIR = Path("config/profiles")


def _ensure_dir() -> None:
    _PROFILES_DIR.mkdir(parents=True, exist_ok=True)


def load_profile(program_name: str) -> dict:
    """Load a named profile from disk."""
    path = _PROFILES_DIR / f"{program_name}.json"
    if not path.exists():
        return create_default_profile()
    return json.loads(path.read_text(encoding="utf-8"))


def save_profile(program_name: str, config: dict) -> None:
    """Persist a profile to disk."""
    _ensure_dir()
    path = _PROFILES_DIR / f"{program_name}.json"
    path.write_text(json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8")


def list_profiles() -> list[str]:
    """Return names of all stored profiles."""
    _ensure_dir()
    return sorted(p.stem for p in _PROFILES_DIR.glob("*.json"))


def get_rate_limits(profile: dict) -> dict:
    """Extract rate-limit settings from a profile."""
    return profile.get("rate_limits", {"rate_limit": 10, "timeout": 300})


def get_scope_rules(profile: dict) -> dict:
    """Extract scope rules from a profile."""
    return profile.get("scope", {"max_depth": 3, "allowed_tools": ["*"]})


def merge_profiles(base: dict, override: dict) -> dict:
    """Deep-merge *override* into *base*, returning a new dict."""
    merged = {**base}
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = merge_profiles(merged[key], value)
        else:
            merged[key] = value
    return merged


def create_default_profile() -> dict:
    """Return the factory-default profile."""
    return {
        "rate_limits": {
            "rate_limit": 10,
            "timeout": 300,
        },
        "scope": {
            "max_depth": 3,
            "allowed_tools": ["*"],
        },
        "notes": "Default profile – edit and save with save_profile().",
    }
