"""
lib/dns_utils.py — DNS utility functions for Dark Recon Framework
Extracted from inline shell heredocs per plan Phase 3.
"""
from __future__ import annotations

import re
import subprocess
import sys

# ---------------------------------------------------------------------------
# Known cloud provider dangling-CNAME indicators (passive detection only)
# ---------------------------------------------------------------------------

DEFAULT_DANGLING_PROVIDERS = [
    "amazonaws.com", "azurewebsites.net", "cloudapp.net",
    "herokussl.com", "herokudns.com", "herokuapp.com",
    "github.io", "fastly.net", "surge.sh", "netlify.app",
    "bitbucket.io", "wpengine.com", "zendesk.com",
    "desk.com", "freshdesk.com", "helpjuice.com",
]

# dnsx output patterns: "subdomain.example.com A 1.2.3.4"
_DNSX_LINE = re.compile(r'^(\S+)\s+(\w+)\s+(\S+)$')
# dig short output: just a value per line
_DIG_LINE = re.compile(r'^\s*(\S+)\s*$')


def parse_dns_records(raw_output: str) -> list[dict]:
    """Parse raw dnsx/dig output lines into {name, type, value} dicts."""
    records = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        m = _DNSX_LINE.match(line)
        if m:
            records.append({"name": m.group(1), "type": m.group(2).upper(), "value": m.group(3)})
            continue
        # Fallback: try to detect type from value shape
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
            records.append({"name": "", "type": "A", "value": line})
        elif re.match(r'^[0-9a-fA-F:]{2,}$', line) and ":" in line:
            records.append({"name": "", "type": "AAAA", "value": line})
        elif "." in line:
            records.append({"name": "", "type": "CNAME", "value": line})
    return records


def extract_cnames(records: list[dict]) -> list[str]:
    """Return CNAME target values from a records list."""
    return [r["value"] for r in records if r.get("type") == "CNAME"]


def is_dangling_cname(cname: str, known_providers: list[str] | None = None) -> bool:
    """
    Heuristic passive check: does this CNAME point to a provider endpoint
    that could be unclaimed (potential subdomain takeover)?
    """
    if known_providers is None:
        known_providers = DEFAULT_DANGLING_PROVIDERS
    cname_lower = cname.lower().rstrip(".")
    return any(cname_lower.endswith(p) for p in known_providers)


def normalize_subdomain(subdomain: str, domain: str) -> str:
    """Lowercase, strip whitespace, ensure result ends with domain."""
    subdomain = subdomain.strip().lower().rstrip(".")
    domain = domain.strip().lower().rstrip(".")
    if not subdomain.endswith(domain):
        if subdomain:
            return f"{subdomain}.{domain}"
        return domain
    return subdomain


def extract_ips(records: list[dict]) -> list[str]:
    """Return A and AAAA record IP values."""
    return [r["value"] for r in records if r.get("type") in ("A", "AAAA")]


def check_zone_transfer(domain: str) -> dict:
    """
    Attempt an AXFR zone transfer via `dig` (non-destructive, read-only DNS query).
    Returns {"success": bool, "records": list, "error": str|None}.
    """
    result: dict = {"success": False, "records": [], "error": None}
    try:
        proc = subprocess.run(
            ["dig", "AXFR", domain, f"@{domain}"],
            capture_output=True, text=True, timeout=15
        )
        output = proc.stdout
        if "Transfer failed" in output or "REFUSED" in output or not output.strip():
            result["error"] = "Zone transfer refused or failed"
            return result
        records = parse_dns_records(output)
        if records:
            result["success"] = True
            result["records"] = records
        else:
            result["error"] = "No records returned"
    except FileNotFoundError:
        result["error"] = "dig not found in PATH"
    except subprocess.TimeoutExpired:
        result["error"] = "Zone transfer timed out"
    except Exception as e:
        result["error"] = str(e)
    return result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 -m lib.dns_utils <command> [args]", file=sys.stderr)
        sys.exit(2)
    cmd = sys.argv[1]
    if cmd == "parse" and len(sys.argv) >= 3:
        import json
        raw = open(sys.argv[2]).read()
        print(json.dumps(parse_dns_records(raw), indent=2))
    elif cmd == "check-takeover" and len(sys.argv) >= 3:
        cname = sys.argv[2]
        print("dangling" if is_dangling_cname(cname) else "ok")
    else:
        print(f"Unknown command: {cmd}", file=sys.stderr)
        sys.exit(2)
