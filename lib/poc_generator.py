"""
lib/poc_generator.py — Automated PoC generation (plan Phase 112)
Generates curl/Python snippets for every validated finding.
Non-destructive: generates proof snippets, not exploit payloads.
"""
from __future__ import annotations

import json
from pathlib import Path


_TEMPLATES: dict[str, str] = {
    "open_redirect": (
        "# Open Redirect PoC\n"
        "curl -v -L '{url}?{param}=https://evil.example.com'\n\n"
        "# Expected: 302 redirect to attacker-controlled domain"
    ),
    "cors_misconfiguration": (
        "# CORS Misconfiguration PoC\n"
        "curl -H 'Origin: https://evil.example.com' \\\n"
        "     -H 'Access-Control-Request-Method: GET' \\\n"
        "     -v '{url}'\n\n"
        "# Check: does Access-Control-Allow-Origin echo the origin?"
    ),
    "host_header_injection": (
        "# Host Header Injection PoC\n"
        "curl -H 'Host: evil.example.com' -v '{url}'\n\n"
        "# Check: does the response reflect the Host header value?"
    ),
    "missing_security_headers": (
        "# Missing Security Headers — verification\n"
        "curl -I '{url}' | grep -iE 'x-frame-options|content-security-policy|strict-transport-security'"
    ),
    "subdomain_takeover": (
        "# Subdomain Takeover PoC\n"
        "# 1. Verify CNAME points to unclaimed provider:\n"
        "dig CNAME {subdomain}\n\n"
        "# 2. Confirm provider shows 'resource not found':\n"
        "curl -v 'https://{subdomain}'\n\n"
        "# 3. Claim the resource at the provider to demonstrate impact"
    ),
    "information_disclosure": (
        "# Information Disclosure PoC\n"
        "curl -v '{url}' | python3 -m json.tool\n\n"
        "# Document the sensitive fields returned in the response"
    ),
    "idor": (
        "# IDOR PoC (Insecure Direct Object Reference)\n"
        "# Authenticated as User A — access User B's resource:\n"
        "curl -H 'Authorization: Bearer {token_a}' \\\n"
        "     '{url}/{id_b}'\n\n"
        "# Expected: 403 Forbidden — actual: 200 OK with User B's data"
    ),
    "default": (
        "# Generic finding verification\n"
        "curl -v '{url}'\n\n"
        "# Review response for: {evidence_summary}"
    ),
}


def generate_poc(finding: dict) -> dict:
    """
    Generate a PoC snippet for a validated finding.
    Returns {finding_id, title, severity, poc_curl, poc_python, template_used}.
    """
    title = (finding.get("title") or "").lower()
    url = finding.get("evidence", {}).get("url") or finding.get("url") or "{url}"
    template_key = "default"

    # Match finding type to template
    if "redirect" in title:
        template_key = "open_redirect"
    elif "cors" in title:
        template_key = "cors_misconfiguration"
    elif "host header" in title:
        template_key = "host_header_injection"
    elif "header" in title or "csp" in title or "hsts" in title:
        template_key = "missing_security_headers"
    elif "takeover" in title:
        template_key = "subdomain_takeover"
    elif "disclosure" in title or "exposure" in title:
        template_key = "information_disclosure"
    elif "idor" in title or "access control" in title:
        template_key = "idor"

    template = _TEMPLATES.get(template_key, _TEMPLATES["default"])
    poc_curl = template.format(
        url=url,
        param=finding.get("evidence", {}).get("param", "next"),
        subdomain=url,
        id_b="{victim_id}",
        token_a="{your_token}",
        evidence_summary=str(finding.get("evidence", {}))[:100],
    )

    poc_python = (
        f"import requests\n\n"
        f"# {finding.get('title', 'Finding')} — Verification\n"
        f"r = requests.get('{url}', verify=True, allow_redirects=False)\n"
        f"print(f'Status: {{r.status_code}}')\n"
        f"print(f'Headers: {{dict(r.headers)}}')\n"
    )

    return {
        "finding_id": finding.get("id", ""),
        "title": finding.get("title", ""),
        "severity": finding.get("severity", ""),
        "poc_curl": poc_curl,
        "poc_python": poc_python,
        "template_used": template_key,
    }


def generate_all_pocs(findings: list[dict], output_dir: str = "output", target: str = "") -> list[dict]:
    """Generate PoCs for all validated findings and write to disk."""
    pocs = []
    for f in findings:
        if f.get("status") != "validated":
            continue
        poc = generate_poc(f)
        pocs.append(poc)

    if target and pocs:
        p = Path(output_dir) / target / "pocs.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(pocs, indent=2), encoding="utf-8")

    return pocs
