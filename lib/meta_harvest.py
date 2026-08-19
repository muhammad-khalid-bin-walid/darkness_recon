"""
lib/meta_harvest.py — robots.txt / sitemap.xml / security.txt harvesting (plan Phase 44)
"""
from __future__ import annotations

import re
import urllib.request
import urllib.error
from urllib.parse import urljoin, urlparse


_WELL_KNOWN = [
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/.well-known/change-password",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/humans.txt",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]


def _fetch(url: str, timeout: int = 10) -> dict:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (DarkRecon/1.0.2)"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(1024 * 512).decode("utf-8", errors="replace")
            return {"url": url, "status": resp.status, "body": body, "error": None}
    except urllib.error.HTTPError as e:
        return {"url": url, "status": e.code, "body": "", "error": str(e)}
    except Exception as e:
        return {"url": url, "status": 0, "body": "", "error": str(e)}


def parse_robots(content: str) -> dict:
    """Parse robots.txt into disallowed paths and sitemaps."""
    disallowed: list[str] = []
    allowed: list[str] = []
    sitemaps: list[str] = []
    for line in content.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line[9:].strip()
            if path:
                disallowed.append(path)
        elif line.lower().startswith("allow:"):
            path = line[6:].strip()
            if path:
                allowed.append(path)
        elif line.lower().startswith("sitemap:"):
            url = line[8:].strip()
            if url:
                sitemaps.append(url)
    return {"disallowed": disallowed, "allowed": allowed, "sitemaps": sitemaps}


def parse_sitemap(content: str) -> list[str]:
    """Extract URLs from a sitemap XML."""
    return re.findall(r'<loc>\s*(https?://[^\s<>]+)\s*</loc>', content, re.I)


def parse_security_txt(content: str) -> dict:
    """Parse security.txt fields."""
    fields: dict[str, list[str]] = {}
    for line in content.splitlines():
        line = line.strip()
        if ":" in line and not line.startswith("#"):
            key, _, val = line.partition(":")
            key = key.strip().lower()
            fields.setdefault(key, []).append(val.strip())
    return fields


def harvest(base_url: str, timeout: int = 10) -> dict:
    """
    Fetch all well-known meta files from base_url.
    Returns {path: {status, parsed, raw}} for each discovered file.
    """
    base_url = base_url.rstrip("/")
    results: dict[str, dict] = {}

    for path in _WELL_KNOWN:
        url = base_url + path
        resp = _fetch(url, timeout=timeout)
        if resp["status"] not in (200, 301, 302):
            continue

        entry: dict = {"status": resp["status"], "url": url, "raw": resp["body"][:2000]}

        # Parse known files
        if "robots.txt" in path:
            entry["parsed"] = parse_robots(resp["body"])
        elif "sitemap" in path:
            entry["parsed"] = {"urls": parse_sitemap(resp["body"])}
        elif "security.txt" in path:
            entry["parsed"] = parse_security_txt(resp["body"])
        else:
            entry["parsed"] = {}

        results[path] = entry

    return results
