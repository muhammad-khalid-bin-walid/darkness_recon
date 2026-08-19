"""
lib/wayback_utils.py — URL normalization and dedup for historical endpoint mining (plan Phase 36)
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode


_IGNORE_EXTENSIONS = {
    "css", "js", "png", "jpg", "jpeg", "gif", "svg", "ico",
    "woff", "woff2", "ttf", "eot", "mp4", "mp3", "pdf", "zip",
    "gz", "tar", "map", "min", "bundle",
}


def normalize_wayback_url(url: str) -> str:
    """Normalize a Wayback/gau URL for deduplication."""
    url = url.strip()
    try:
        p = urlparse(url)
        scheme = p.scheme.lower() or "https"
        netloc = p.netloc.lower()
        path = p.path.rstrip("/") if p.path not in ("", "/") else "/"
        # Sort + deduplicate query params
        qs = urlencode(sorted(parse_qs(p.query).items()))
        return urlunparse((scheme, netloc, path, "", qs, ""))
    except Exception:
        return url.lower().strip()


def is_interesting_url(url: str) -> bool:
    """Return True if a URL is worth keeping (has interesting extension or no extension)."""
    try:
        path = urlparse(url).path.lower()
        ext = path.rsplit(".", 1)[-1] if "." in path.split("/")[-1] else ""
        return ext not in _IGNORE_EXTENSIONS
    except Exception:
        return True


def deduplicate_with_live(wayback_urls: list[str], live_urls: list[str]) -> list[str]:
    """
    Return URLs from wayback_urls that are NOT already in live_urls (normalized).
    These are historical/deprecated endpoints not found in current crawl.
    """
    live_normalized = {normalize_wayback_url(u) for u in live_urls}
    result = []
    seen: set[str] = set()
    for url in wayback_urls:
        norm = normalize_wayback_url(url)
        if norm not in live_normalized and norm not in seen:
            seen.add(norm)
            result.append(url)
    return result


def extract_unique_paths(urls: list[str]) -> list[str]:
    """Extract unique path components from a URL list."""
    paths: set[str] = set()
    for url in urls:
        try:
            path = urlparse(url).path
            if path and path != "/":
                paths.add(path)
        except Exception:
            pass
    return sorted(paths)
