"""
lib/scope_engine.py — Per-program scope enforcement (plan Phase 24)

Enforces in-scope/out-of-scope rules before any active phase fires.
Scope rules stored in config/scopes/<program>.json
"""
from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path
from urllib.parse import urlparse


def _scope_path(program: str, config_dir: str = "config") -> Path:
    return Path(config_dir) / "scopes" / f"{program}.json"


def _load_scope(program: str, config_dir: str = "config") -> dict:
    p = _scope_path(program, config_dir)
    if not p.exists():
        return {"in_scope": [], "out_of_scope": [], "wildcards": []}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {"in_scope": [], "out_of_scope": [], "wildcards": []}


def save_scope(program: str, scope: dict, config_dir: str = "config") -> None:
    """Persist scope rules for a program."""
    p = _scope_path(program, config_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(scope, indent=2), encoding="utf-8")


def _extract_host(target: str) -> str:
    """Extract hostname from a URL or return the target as-is."""
    if "://" in target:
        return urlparse(target).netloc.split(":")[0].lower()
    return target.lower().split(":")[0].split("/")[0]


def _matches(host: str, pattern: str) -> bool:
    """Match host against a pattern. Supports wildcards and CIDR-like prefixes."""
    pattern = pattern.lower().lstrip("*.")
    return host == pattern or host.endswith("." + pattern) or fnmatch.fnmatch(host, pattern)


def is_in_scope(target: str, program: str, config_dir: str = "config") -> bool:
    """
    Return True if target is within the program's declared scope.
    Out-of-scope rules take precedence over in-scope rules.
    """
    scope = _load_scope(program, config_dir)
    host = _extract_host(target)

    # Check out-of-scope first (explicit exclusions win)
    for oos in scope.get("out_of_scope", []):
        if _matches(host, oos):
            return False

    # Check in-scope
    in_scope_rules = scope.get("in_scope", []) + scope.get("wildcards", [])
    if not in_scope_rules:
        # No rules defined — allow everything (open scope)
        return True
    return any(_matches(host, rule) for rule in in_scope_rules)


def filter_in_scope(
    targets: list[str],
    program: str,
    config_dir: str = "config",
) -> tuple[list[str], list[str]]:
    """
    Split targets into (in_scope, out_of_scope) lists.
    """
    in_s, out_s = [], []
    for t in targets:
        (in_s if is_in_scope(t, program, config_dir) else out_s).append(t)
    return in_s, out_s


def load_scope_rules(program: str, config_dir: str = "config") -> dict:
    """Return the raw scope dict for a program."""
    return _load_scope(program, config_dir)
