"""
lib/config_validator.py — Config validation on startup (plan Phase 5)

Validates all .conf files in the config/ directory before any scan run begins.
Checks required keys, types, and value constraints.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Required keys per conf file
# ---------------------------------------------------------------------------

REQUIRED_SETTINGS = {
    "THREADS": int,
    "TIMEOUT": int,
    "RATE_LIMIT": int,
}

REQUIRED_TOOLS_ARRAYS = ["ESSENTIAL_TOOLS", "OPTIONAL_TOOLS"]

# Keys that must not be empty strings when set
NON_EMPTY_KEYS = ["DOMAIN"]

# Boolean keys
BOOL_KEYS = {
    "QUIET", "JSON_OUTPUT", "WAF_CHECK", "NUCLEI_CHECK", "PORT_SCAN",
    "SSL_CHECK", "API_SCAN", "GIT_SCAN", "SECRETS_SCAN", "CLOUD_SCAN",
    "VULN_SCAN", "SERVICE_SCAN", "DNS_SSL_WHOIS_SCAN", "DISTRIBUTED_SCAN",
    "OSINT_INTEL", "THREAT_INTEL", "BUSINESS_LOGIC", "ADVANCED_EXPLOITATION",
    "DATABASE_SCAN", "WEBHOOKS_SCAN", "CICD_SCAN", "ML_ANALYSIS",
    "COMPLIANCE_SCAN", "SCOPE_PROGRAM", "TARGET_INTAKE", "HISTORICAL_RECON",
    "THIRD_PARTY", "EXPLOITATION_VALIDATION", "POST_EXPLOITATION",
    "DATA_EXFILTRATION", "CONTINUOUS_MONITORING",
}

_INT_PATTERN = re.compile(r'^\d+$')
_BOOL_PATTERN = re.compile(r'^(true|false)$', re.IGNORECASE)
_ASSIGN_PATTERN = re.compile(r'^([A-Z_][A-Z_0-9]*)=(.*)$')


def _parse_conf_file(path: Path) -> dict[str, str]:
    """
    Parse a bash-style key=value config file.
    Returns a dict of {KEY: value_string}.
    Strips inline comments and quotes.
    """
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        # Skip blank lines and comments
        if not line or line.startswith("#"):
            continue
        m = _ASSIGN_PATTERN.match(line)
        if not m:
            continue
        key = m.group(1)
        val = m.group(2).strip()
        # Strip inline comments
        if " #" in val:
            val = val[:val.index(" #")].strip()
        # Strip surrounding quotes
        for q in ('"', "'"):
            if val.startswith(q) and val.endswith(q) and len(val) >= 2:
                val = val[1:-1]
                break
        values[key] = val
    return values


def validate_settings_conf(path: Path) -> list[str]:
    """
    Validate config/settings.conf.
    Returns list of error strings (empty = valid).
    """
    errors: list[str] = []

    if not path.exists():
        return [f"Config file not found: {path}"]

    try:
        values = _parse_conf_file(path)
    except Exception as e:
        return [f"Cannot parse {path}: {e}"]

    # Check integer keys
    for key, expected_type in REQUIRED_SETTINGS.items():
        if key not in values:
            errors.append(f"{path.name}: missing required key '{key}'")
            continue
        val = values[key]
        if expected_type is int and not _INT_PATTERN.match(val):
            errors.append(f"{path.name}: '{key}' must be an integer, got '{val}'")
        elif expected_type is int:
            n = int(val)
            if key == "THREADS" and not (1 <= n <= 2000):
                errors.append(f"{path.name}: THREADS must be 1–2000, got {n}")
            elif key == "TIMEOUT" and not (1 <= n <= 3600):
                errors.append(f"{path.name}: TIMEOUT must be 1–3600s, got {n}")
            elif key == "RATE_LIMIT" and not (1 <= n <= 100000):
                errors.append(f"{path.name}: RATE_LIMIT must be 1–100000, got {n}")

    # Check boolean keys
    for key in BOOL_KEYS:
        if key in values and not _BOOL_PATTERN.match(values[key]):
            errors.append(f"{path.name}: '{key}' must be true/false, got '{values[key]}'")

    return errors


def validate_tools_conf(path: Path) -> list[str]:
    """Validate config/tools.conf — must define ESSENTIAL_TOOLS array."""
    errors: list[str] = []
    if not path.exists():
        return [f"Config file not found: {path}"]
    content = path.read_text(encoding="utf-8")
    for arr in REQUIRED_TOOLS_ARRAYS:
        if arr not in content:
            errors.append(f"{path.name}: missing required array '{arr}'")
    return errors


def validate_profile_conf(path: Path) -> list[str]:
    """Validate a profile conf file — must be parseable."""
    errors: list[str] = []
    if not path.exists():
        return [f"Profile file not found: {path}"]
    try:
        _parse_conf_file(path)
    except Exception as e:
        errors.append(f"{path.name}: parse error: {e}")
    return errors


def validate_all(config_dir: str | Path) -> dict[str, list[str]]:
    """
    Validate all .conf files under config_dir.
    Returns {filename: [errors]} — files with no errors have empty lists.
    """
    config_dir = Path(config_dir)
    results: dict[str, list[str]] = {}

    settings = config_dir / "settings.conf"
    results["settings.conf"] = validate_settings_conf(settings)

    tools = config_dir / "tools.conf"
    results["tools.conf"] = validate_tools_conf(tools)

    profiles_dir = config_dir / "profiles"
    if profiles_dir.exists():
        for profile in profiles_dir.glob("*.conf"):
            errs = validate_profile_conf(profile)
            results[f"profiles/{profile.name}"] = errs

    return results


def is_valid(config_dir: str | Path) -> bool:
    """Return True if all config files pass validation."""
    return all(len(e) == 0 for e in validate_all(config_dir).values())


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _cli_main(argv: list[str]) -> int:
    config_dir = argv[0] if argv else "config"
    results = validate_all(config_dir)
    all_ok = True
    for fname, errors in results.items():
        if errors:
            all_ok = False
            for err in errors:
                print(f"[ERROR] {err}", file=sys.stderr)
        else:
            print(f"[OK] {fname}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(_cli_main(sys.argv[1:]))
