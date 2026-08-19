"""
lib/entity_resolution.py — Merge duplicate assets from different naming conventions (plan Phase 26)
"""
from __future__ import annotations

import re
from collections import defaultdict


def _canonical_domain(raw: str) -> str:
    """Strip protocol, trailing slash, port, www. prefix and lowercase."""
    raw = raw.lower().strip()
    raw = re.sub(r'^https?://', '', raw)
    raw = raw.split('/')[0].split('?')[0].split('#')[0]
    raw = re.sub(r':\d+$', '', raw)  # remove port
    raw = re.sub(r'^www\.', '', raw)
    return raw.rstrip('.')


def _canonical_ip(raw: str) -> str:
    return raw.strip().lower()


def resolve_assets(assets: list[dict]) -> list[dict]:
    """
    Merge assets that refer to the same logical entity.
    Merges by canonical domain, then by IP if domain is absent.
    Returns deduplicated list with merged tags/sources.
    """
    # Group by canonical key
    groups: dict[str, list[dict]] = defaultdict(list)
    for asset in assets:
        domain = asset.get("domain", "")
        ip = asset.get("ip", "")
        if domain:
            key = f"domain:{_canonical_domain(domain)}"
        elif ip:
            key = f"ip:{_canonical_ip(ip)}"
        else:
            key = f"id:{asset.get('id', id(asset))}"
        groups[key].append(asset)

    merged: list[dict] = []
    for key, group in groups.items():
        if len(group) == 1:
            merged.append(group[0])
        else:
            merged.append(_merge_group(group))
    return merged


def _merge_group(assets: list[dict]) -> dict:
    """Merge a group of duplicate assets into one canonical record."""
    # Use first asset as base, then merge fields from others
    base = dict(assets[0])
    all_tags: list[str] = list(base.get("tags", []))
    all_sources: list[str] = [base.get("source", "")] if base.get("source") else []

    for other in assets[1:]:
        # Merge tags (dedup)
        for tag in other.get("tags", []):
            if tag not in all_tags:
                all_tags.append(tag)
        # Merge sources
        src = other.get("source", "")
        if src and src not in all_sources:
            all_sources.append(src)
        # Fill in missing fields from other
        for field in ("domain", "ip", "asn", "criticality", "type"):
            if not base.get(field) and other.get(field):
                base[field] = other[field]

    base["tags"] = all_tags
    base["source"] = ", ".join(filter(None, all_sources))
    base["merged_count"] = len(assets)
    return base
