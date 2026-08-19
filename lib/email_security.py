"""
lib/email_security.py — SPF/DKIM/DMARC posture checks (plan Phase 48)
"""
from __future__ import annotations

import re
import subprocess


def _dig_txt(domain: str, timeout: int = 10) -> list[str]:
    """Query TXT records for a domain using dig."""
    try:
        result = subprocess.run(
            ["dig", "+short", "TXT", domain],
            capture_output=True, text=True, timeout=timeout
        )
        return [line.strip().strip('"') for line in result.stdout.splitlines() if line.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        return []


def check_spf(domain: str) -> dict:
    """Check SPF record presence and basic validity."""
    records = _dig_txt(domain)
    spf_records = [r for r in records if r.lower().startswith("v=spf1")]
    if not spf_records:
        return {"present": False, "valid": False, "record": None, "issues": ["No SPF record found"]}
    record = spf_records[0]
    issues = []
    if "~all" in record:
        issues.append("soft-fail (~all) — consider -all for stricter enforcement")
    elif "+all" in record:
        issues.append("CRITICAL: +all allows any server to send as this domain")
    return {"present": True, "valid": True, "record": record, "issues": issues}


def check_dmarc(domain: str) -> dict:
    """Check DMARC record presence and policy."""
    dmarc_domain = f"_dmarc.{domain}"
    records = _dig_txt(dmarc_domain)
    dmarc_records = [r for r in records if r.lower().startswith("v=dmarc1")]
    if not dmarc_records:
        return {"present": False, "policy": None, "record": None, "issues": ["No DMARC record found"]}
    record = dmarc_records[0]
    policy_match = re.search(r'p=(\w+)', record, re.I)
    policy = policy_match.group(1).lower() if policy_match else "none"
    issues = []
    if policy == "none":
        issues.append("DMARC policy=none — no enforcement, monitoring only")
    elif policy == "quarantine":
        issues.append("DMARC policy=quarantine — consider reject for strongest protection")
    return {"present": True, "policy": policy, "record": record, "issues": issues}


def check_dkim(domain: str, selector: str = "default") -> dict:
    """Check for a DKIM record at selector._domainkey.domain."""
    dkim_domain = f"{selector}._domainkey.{domain}"
    records = _dig_txt(dkim_domain)
    dkim_records = [r for r in records if "v=dkim1" in r.lower() or "p=" in r.lower()]
    if not dkim_records:
        return {"present": False, "selector": selector, "record": None,
                "issues": [f"No DKIM record found for selector '{selector}'"]}
    return {"present": True, "selector": selector, "record": dkim_records[0], "issues": []}


def full_email_audit(domain: str) -> dict:
    """Run SPF + DMARC + DKIM checks and return combined posture."""
    spf = check_spf(domain)
    dmarc = check_dmarc(domain)
    dkim = check_dkim(domain)
    all_issues = spf["issues"] + dmarc["issues"] + dkim["issues"]
    return {
        "domain": domain,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "overall_issues": all_issues,
        "posture": "good" if not all_issues else ("warn" if len(all_issues) <= 2 else "poor"),
    }
