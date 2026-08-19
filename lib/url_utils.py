"""
lib/url_utils.py — URL utility functions for Dark Recon Framework
Extracted from inline shell heredocs per plan Phase 3.
"""
from __future__ import annotations

import re
import sys
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------

_ENDPOINT_PATTERNS = [
    re.compile(r'(?:url|href|src|action|endpoint|api)\s*[:=]\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'["\'](\/?(?:api|v\d+|graphql|rest|endpoint)[^"\']{0,200})["\']', re.I),
    re.compile(r'["\']([^"\']*\/[a-zA-Z0-9_-]+\.[a-zA-Z]{2,4}[^"\']*)["\']'),
    re.compile(r'(https?://[^\s"\'`<>]{5,200})'),
]

_INTERESTING_EXTENSIONS = {
    "php", "asp", "aspx", "jsp", "jspx", "cfm", "cgi", "pl", "py",
    "rb", "sh", "json", "xml", "yaml", "yml", "config", "conf", "ini",
    "bak", "old", "backup", "sql", "db", "env", "log", "txt", "csv",
    "do", "action", "api", "graphql",
}

_STATIC_EXTENSIONS = {
    "css", "js", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff",
    "woff2", "ttf", "eot", "pdf", "zip", "gz", "mp4", "mp3", "avi",
    "mov", "webm", "map", "min", "bundle",
}


def extract_endpoints(js_content: str) -> list[str]:
    """Extract URL/endpoint strings from JS content using regex patterns."""
    found: set[str] = set()
    for pattern in _ENDPOINT_PATTERNS:
        for match in pattern.finditer(js_content):
            url = match.group(1).strip()
            if url and len(url) > 1 and not url.startswith("//"):
                found.add(url)
    return sorted(found)


def normalize_url(url: str, base_domain: str = "") -> str:
    """Normalize a URL: lowercase scheme+host, strip trailing slash, sort params."""
    url = url.strip()
    if not re.match(r'^https?://', url, re.I):
        if url.startswith("//"):
            url = "https:" + url
        elif base_domain:
            url = f"https://{base_domain.rstrip('/')}/{url.lstrip('/')}"
        else:
            url = "https://" + url
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip("/") if parsed.path != "/" else "/"
        params_sorted = urlencode(sorted(parse_qs(parsed.query).items()))
        return urlunparse((scheme, netloc, path, parsed.params, params_sorted, ""))
    except Exception:
        return url.lower().rstrip("/")


def deduplicate_urls(urls: list[str]) -> list[str]:
    """Return unique normalized URLs preserving first-seen order."""
    seen: set[str] = set()
    result: list[str] = []
    for url in urls:
        norm = normalize_url(url)
        if norm not in seen:
            seen.add(norm)
            result.append(url)
    return result


def filter_interesting_extensions(urls: list[str]) -> list[str]:
    """Keep only URLs with security-relevant extensions; drop known static assets."""
    result = []
    for url in urls:
        path = urlparse(url).path.lower()
        ext = path.rsplit(".", 1)[-1] if "." in path.split("/")[-1] else ""
        # Keep if no extension (dynamic route) or interesting extension
        if not ext or ext in _INTERESTING_EXTENSIONS:
            if ext not in _STATIC_EXTENSIONS:
                result.append(url)
    return result


def extract_params(url: str) -> dict:
    """Return query parameters as a dict (multi-value params as lists)."""
    try:
        qs = urlparse(url).query
        return {k: v[0] if len(v) == 1 else v for k, v in parse_qs(qs).items()}
    except Exception:
        return {}


def is_in_scope(url: str, domain: str) -> bool:
    """Return True if the URL's hostname is within domain or a subdomain of it."""
    try:
        host = urlparse(url).netloc.lower().split(":")[0]
        domain = domain.lower().lstrip("*.")
        return host == domain or host.endswith("." + domain)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _cli_main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("Usage: python3 -m lib.url_utils <command> <input>", file=sys.stderr)
        print("Commands: extract-endpoints, normalize, deduplicate", file=sys.stderr)
        return 2

    cmd = argv[0]
    arg = argv[1]

    if cmd == "extract-endpoints":
        try:
            content = open(arg, encoding="utf-8", errors="replace").read()
        except OSError as e:
            print(f"Error reading {arg}: {e}", file=sys.stderr)
            return 1
        for ep in extract_endpoints(content):
            print(ep)

    elif cmd == "normalize":
        print(normalize_url(arg))

    elif cmd == "deduplicate":
        try:
            lines = open(arg, encoding="utf-8").read().splitlines()
        except OSError as e:
            print(f"Error reading {arg}: {e}", file=sys.stderr)
            return 1
        for url in deduplicate_urls(lines):
            print(url)

    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(_cli_main(sys.argv[1:]))
