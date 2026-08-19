"""
lib/dedup.py — Finding deduplication with normalized fingerprints (plan Phase 22)

Uses normalized fingerprints, not exact string match.
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode


def _normalize_url(url: str) -> str:
    """Normalize a URL for fingerprinting (lowercase, sorted params, no fragment)."""
    try:
        p = urlparse(url.strip().lower())
        sorted_qs = urlencode(sorted(parse_qs(p.query).items()))
        return urlunparse((p.scheme, p.netloc, p.path.rstrip("/") or "/", "", sorted_qs, ""))
    except Exception:
        return url.lower().strip()


def _normalize_title(title: str) -> str:
    """Lowercase and strip whitespace/punctuation from a finding title."""
    return re.sub(r'[^a-z0-9]', '', title.lower())


def fingerprint_finding(finding: dict) -> str:
    """
    Generate a normalized fingerprint for a finding.

    Priority:
    1. Use existing fingerprint field if present
    2. Hash of (normalized_title + asset_id + severity + phase)
    """
    if finding.get("fingerprint"):
        return finding["fingerprint"]

    parts = [
        _normalize_title(finding.get("title", "")),
        str(finding.get("asset_id", "")).lower(),
        str(finding.get("severity", "")).lower(),
        str(finding.get("phase", "")).lower(),
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def fingerprint_asset(asset: dict) -> str:
    """Generate a normalized fingerprint for an asset."""
    if asset.get("id"):
        return asset["id"]
    parts = [
        str(asset.get("domain", "")).lower().strip().rstrip("."),
        str(asset.get("ip", "")).strip(),
        str(asset.get("type", "")).lower(),
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def deduplicate(items: list[dict], fp_func=fingerprint_finding) -> list[dict]:
    """
    Deduplicate a list of findings or assets using normalized fingerprints.
    First occurrence wins; later duplicates are dropped.
    """
    seen: set[str] = set()
    result: list[dict] = []
    for item in items:
        fp = fp_func(item)
        if fp not in seen:
            seen.add(fp)
            # Attach fingerprint to item if not already present
            if "fingerprint" not in item:
                item = {**item, "fingerprint": fp}
            result.append(item)
    return result


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Deduplicate a list of Finding dicts."""
    return deduplicate(findings, fingerprint_finding)


def deduplicate_assets(assets: list[dict]) -> list[dict]:
    """Deduplicate a list of Asset dicts."""
    return deduplicate(assets, fingerprint_asset)


def group_by_fingerprint(findings: list[dict]) -> dict[str, list[dict]]:
    """Group findings by normalized fingerprint (shows duplicate clusters)."""
    groups: dict[str, list[dict]] = {}
    for f in findings:
        fp = fingerprint_finding(f)
        groups.setdefault(fp, []).append(f)
    return groups
