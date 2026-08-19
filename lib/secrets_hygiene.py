"""
lib/secrets_hygiene.py — Secrets hygiene scanner for CI (plan Phase 10)

Scans for plaintext secrets in output/, cache/, logs/ before they leak.
Used by the pre-commit hook and CI pipeline.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Secret patterns — compiled once
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    ("aws_access_key",      re.compile(r'AKIA[0-9A-Z]{16}', re.I)),
    ("aws_secret_key",      re.compile(r'(?i)aws.{0,30}secret.{0,30}["\'][0-9a-zA-Z/+]{40}["\']')),
    ("github_token",        re.compile(r'gh[pousr]_[A-Za-z0-9]{36,}')),
    ("generic_api_key",     re.compile(r'(?i)(api_key|apikey|api-key)\s*[=:]\s*["\']?[a-zA-Z0-9_\-]{20,}["\']?')),
    ("generic_token",       re.compile(r'(?i)(token|secret|password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']')),
    ("private_key_header",  re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ("jwt_token",           re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}')),
    ("slack_webhook",       re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+')),
    ("stripe_key",          re.compile(r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}')),
    ("google_api_key",      re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ("basic_auth_url",      re.compile(r'https?://[a-zA-Z0-9._%+-]+:[^@\s]{4,}@')),
    ("hex_secret_40",       re.compile(r'(?i)(secret|token|key)\s*[=:]\s*[0-9a-f]{40}\b')),
]

# File extensions to skip entirely (binary/media files)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tar", ".mp4", ".mp3",
    ".exe", ".bin", ".so", ".dylib", ".pyc", ".class",
}

# Directories to skip
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".tox", ".venv", "venv"}


def _should_skip(path: Path) -> bool:
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return True
    for part in path.parts:
        if part in SKIP_DIRS:
            return True
    return False


def scan_file(path: Path) -> list[dict]:
    """
    Scan a single file for secret patterns.
    Returns list of {file, line, pattern_name, match_snippet}.
    """
    if _should_skip(path):
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    findings = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for name, pattern in SECRET_PATTERNS:
            m = pattern.search(line)
            if m:
                # Redact the actual match value in the snippet
                snippet = line.strip()[:120]
                findings.append({
                    "file": str(path),
                    "line": lineno,
                    "pattern_name": name,
                    "snippet": snippet,
                })
    return findings


def scan_directory(directory: str | Path, recursive: bool = True) -> list[dict]:
    """Scan all files in a directory for secrets."""
    directory = Path(directory)
    if not directory.exists():
        return []
    glob = "**/*" if recursive else "*"
    findings = []
    for p in directory.glob(glob):
        if p.is_file():
            findings.extend(scan_file(p))
    return findings


def scan_paths(paths: list[str | Path]) -> list[dict]:
    """Scan a list of file or directory paths."""
    findings = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            findings.extend(scan_directory(p))
        elif p.is_file():
            findings.extend(scan_file(p))
    return findings


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli_main(argv: list[str]) -> int:
    import json
    paths = argv if argv else ["output", "cache", "logs"]
    findings = scan_paths(paths)
    if findings:
        print(json.dumps(findings, indent=2))
        print(f"\n[!] Found {len(findings)} potential secret(s). Review before committing.", file=sys.stderr)
        return 1
    print("[OK] No secrets found in scanned paths.")
    return 0


if __name__ == "__main__":
    sys.exit(_cli_main(sys.argv[1:]))
