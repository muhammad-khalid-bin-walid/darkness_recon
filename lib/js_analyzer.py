"""
lib/js_analyzer.py — JS file analysis pipeline (plan Phase 37)
Endpoint extraction, secret regex, dependency/version fingerprinting.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# Endpoint patterns
_EP_PATTERNS = [
    re.compile(r'["\'`](/[a-zA-Z0-9_/.-]{2,200})[\"\'`]'),
    re.compile(r'["\'`](https?://[^\s"\'`<>]{5,200})[\"\'`]'),
    re.compile(r'(?:url|href|endpoint|path|api)\s*[:=]\s*["\'`]([^"\'`\s]{2,200})[\"\'`]', re.I),
    re.compile(r'fetch\s*\(\s*["\'`]([^"\'`]{2,200})[\"\'`]', re.I),
    re.compile(r'axios\.[a-z]+\s*\(\s*["\'`]([^"\'`]{2,200})[\"\'`]', re.I),
]

# Secret patterns (detection only — not validation)
_SECRET_PATTERNS = [
    ("aws_key",       re.compile(r'AKIA[0-9A-Z]{16}')),
    ("github_token",  re.compile(r'gh[pousr]_[A-Za-z0-9]{36,}')),
    ("jwt",           re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')),
    ("api_key",       re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\'][A-Za-z0-9_\-]{16,}["\']')),
    ("generic_secret",re.compile(r'(?i)(secret|token|password)\s*[=:]\s*["\'][^"\']{8,}["\']')),
    ("stripe",        re.compile(r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}')),
    ("google_api",    re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
]

# Dependency patterns: "library": "version" or require('lib')
_DEP_PATTERNS = [
    re.compile(r'"([a-z@][a-z0-9_/.-]{1,60})"\s*:\s*"([~^*>=<]?[0-9a-z.\-+*]{1,30})"', re.I),
    re.compile(r"require\s*\(\s*['\"]([a-z@][a-z0-9_/.-]{1,60})['\"]", re.I),
    re.compile(r"import\s+.+\s+from\s+['\"]([a-z@][a-z0-9_/.-]{1,60})['\"]", re.I),
]


def extract_endpoints(content: str) -> list[str]:
    """Extract URL/endpoint strings from JS content."""
    found: set[str] = set()
    for pattern in _EP_PATTERNS:
        for m in pattern.finditer(content):
            url = m.group(1).strip()
            if url and len(url) > 1:
                found.add(url)
    return sorted(found)


def detect_secrets(content: str) -> list[dict]:
    """
    Scan JS content for secret patterns.
    Returns list of {pattern_name, match_snippet, line}.
    Does NOT return actual values — only detection signals.
    """
    findings = []
    lines = content.splitlines()
    for lineno, line in enumerate(lines, 1):
        for name, pattern in _SECRET_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "pattern_name": name,
                    "line": lineno,
                    "snippet": line.strip()[:100],
                })
    return findings


def extract_dependencies(content: str) -> list[dict]:
    """Extract npm/library dependency names and versions from JS/package.json content."""
    deps: dict[str, str] = {}
    for pattern in _DEP_PATTERNS:
        for m in pattern.finditer(content):
            name = m.group(1)
            version = m.group(2) if m.lastindex >= 2 else "unknown"
            if name not in deps:
                deps[name] = version
    return [{"name": k, "version": v} for k, v in deps.items()]


def analyze_file(path: str | Path) -> dict:
    """Analyze a single JS file. Returns {endpoints, secrets, dependencies}."""
    p = Path(path)
    try:
        content = p.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return {"error": str(e), "endpoints": [], "secrets": [], "dependencies": []}
    return {
        "file": str(p),
        "endpoints": extract_endpoints(content),
        "secrets": detect_secrets(content),
        "dependencies": extract_dependencies(content),
    }


if __name__ == "__main__":
    import json
    if len(sys.argv) < 2:
        print("Usage: python3 -m lib.js_analyzer <file.js>", file=sys.stderr)
        sys.exit(2)
    print(json.dumps(analyze_file(sys.argv[1]), indent=2))
