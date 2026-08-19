"""
lib/header_audit.py — Response-header security posture audit (plan Phase 74)
Checks: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, etc.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class HeaderFinding:
    header: str
    severity: str
    issue: str
    recommendation: str


def audit_headers(headers: dict) -> list[HeaderFinding]:
    """
    Audit HTTP response headers for security issues.
    Returns list of HeaderFinding objects.
    """
    lh = {k.lower(): v for k, v in headers.items()}
    findings: list[HeaderFinding] = []

    # Strict-Transport-Security (HSTS)
    hsts = lh.get("strict-transport-security", "")
    if not hsts:
        findings.append(HeaderFinding("Strict-Transport-Security", "medium",
            "HSTS header missing", "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"))
    elif "max-age=0" in hsts:
        findings.append(HeaderFinding("Strict-Transport-Security", "medium",
            "HSTS max-age=0 effectively disables HSTS", "Use max-age >= 31536000"))

    # X-Frame-Options
    xfo = lh.get("x-frame-options", "")
    csp = lh.get("content-security-policy", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    if not xfo and not has_frame_ancestors:
        findings.append(HeaderFinding("X-Frame-Options", "medium",
            "Clickjacking protection missing (no X-Frame-Options or CSP frame-ancestors)",
            "Add: X-Frame-Options: DENY or CSP: frame-ancestors 'none'"))
    elif xfo.upper() not in ("DENY", "SAMEORIGIN") and not has_frame_ancestors:
        findings.append(HeaderFinding("X-Frame-Options", "low",
            f"Permissive X-Frame-Options value: {xfo}",
            "Use DENY or SAMEORIGIN"))

    # X-Content-Type-Options
    xcto = lh.get("x-content-type-options", "")
    if xcto.lower() != "nosniff":
        findings.append(HeaderFinding("X-Content-Type-Options", "low",
            "X-Content-Type-Options: nosniff missing or incorrect",
            "Add: X-Content-Type-Options: nosniff"))

    # Content-Security-Policy
    if not csp:
        findings.append(HeaderFinding("Content-Security-Policy", "medium",
            "Content-Security-Policy header missing",
            "Implement a CSP to restrict script/resource sources"))
    elif "unsafe-inline" in csp and "unsafe-eval" in csp:
        findings.append(HeaderFinding("Content-Security-Policy", "medium",
            "CSP allows 'unsafe-inline' and 'unsafe-eval' — XSS protection weakened",
            "Remove unsafe-inline/unsafe-eval from script-src"))
    elif "unsafe-inline" in csp:
        findings.append(HeaderFinding("Content-Security-Policy", "low",
            "CSP allows 'unsafe-inline'",
            "Remove unsafe-inline or use nonces/hashes"))

    # Referrer-Policy
    rp = lh.get("referrer-policy", "")
    if not rp:
        findings.append(HeaderFinding("Referrer-Policy", "low",
            "Referrer-Policy header missing",
            "Add: Referrer-Policy: strict-origin-when-cross-origin"))

    # Permissions-Policy
    pp = lh.get("permissions-policy", "") or lh.get("feature-policy", "")
    if not pp:
        findings.append(HeaderFinding("Permissions-Policy", "info",
            "Permissions-Policy header missing",
            "Consider adding Permissions-Policy to restrict browser features"))

    # Server header disclosure
    server = lh.get("server", "")
    if server and any(v in server.lower() for v in ("apache/", "nginx/", "iis/", "openssl/")):
        findings.append(HeaderFinding("Server", "info",
            f"Server header reveals version info: {server}",
            "Configure server to not disclose version numbers"))

    # X-Powered-By
    xpb = lh.get("x-powered-by", "")
    if xpb:
        findings.append(HeaderFinding("X-Powered-By", "info",
            f"X-Powered-By header reveals tech stack: {xpb}",
            "Remove or mask X-Powered-By header"))

    return findings


def summarize_audit(headers: dict) -> dict:
    """Return structured audit summary."""
    findings = audit_headers(headers)
    by_severity: dict[str, list[str]] = {}
    for f in findings:
        by_severity.setdefault(f.severity, []).append(f.header)
    return {
        "total_issues": len(findings),
        "by_severity": by_severity,
        "findings": [{"header": f.header, "severity": f.severity, "issue": f.issue,
                      "recommendation": f.recommendation} for f in findings],
        "score": max(0, 100 - len(findings) * 10),
    }
