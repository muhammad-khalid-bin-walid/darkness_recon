"""
lib/submission_drafter.py — Auto-drafted vulnerability submission templates.
Generates formatted reports for HackerOne, Bugcrowd, and generic platforms.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .cvss_mapper import map_cvss, severity_from_score


@dataclass
class SubmissionDraft:
    """A vulnerability submission ready for platform posting."""
    title: str
    severity: str
    summary: str
    description: str
    impact: str
    steps_to_reproduce: str
    evidence: list[str] = field(default_factory=list)
    platform: str = ""
    bounty_tier: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    remediation: str = ""
    metadata: dict[str, str] = field(default_factory=dict)


# HackerOne severity to bounty tier mapping
_H1_SEVERITY_TIERS = {
    "Critical": "Critical (CVSS 9.0–10.0)",
    "High": "High (CVSS 7.0–8.9)",
    "Medium": "Medium (CVSS 4.0–6.9)",
    "Low": "Low (CVSS 0.1–3.9)",
    "None": "Informational",
}

# Bugcrowd priority to tier mapping
_BUGCROWD_SEVERITY_TIERS = {
    "Critical": "P1 — Critical",
    "High": "P2 — High",
    "Medium": "P3 — Medium",
    "Low": "P4 — Low",
    "None": "P5 — Informational",
}

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _derive_severity(finding: dict) -> str:
    """Derive a human-readable severity label from a finding."""
    if finding.get("severity"):
        return finding["severity"].capitalize()
    cvss = map_cvss(finding)
    return cvss.severity


def _derive_bounty_tier(severity: str, platform: str) -> str:
    """Map severity to a platform-specific bounty tier."""
    if platform == "hackerone":
        return _H1_SEVERITY_TIERS.get(severity, "Informational")
    elif platform == "bugcrowd":
        return _BUGCROWD_SEVERITY_TIERS.get(severity, "P5 — Informational")
    return severity


def _build_impact_section(finding: dict, severity: str) -> str:
    """Generate the impact section from finding context."""
    parts = []
    cvss = map_cvss(finding)
    impact = finding.get("impact", "")

    if impact:
        parts.append(impact)
    else:
        sev_lower = severity.lower()
        if sev_lower == "critical":
            parts.append(
                "This vulnerability allows full compromise of the affected system. "
                "An attacker can gain unauthorized access to sensitive data, modify system state, "
                "or pivot to other systems within the network."
            )
        elif sev_lower == "high":
            parts.append(
                "This vulnerability enables significant unauthorized access or data exposure. "
                "An attacker can read sensitive information, impersonate users, or perform "
                "privileged actions on the affected system."
            )
        elif sev_lower == "medium":
            parts.append(
                "This vulnerability allows limited unauthorized access or information disclosure. "
                "An attacker may be able to access non-critical data or perform actions "
                "within the context of a low-privileged user."
            )
        elif sev_lower == "low":
            parts.append(
                "This vulnerability has limited direct security impact but may aid an attacker "
                "in reconnaissance or combined exploitation with other findings."
            )
        else:
            parts.append(
                "This finding represents a potential security concern that does not directly "
                "lead to a compromise but may increase the attack surface."
            )

    parts.append(f"\nCVSS Score: {cvss.score} ({cvss.severity})")
    parts.append(f"CVSS Vector: {cvss.vector_string}")

    return "\n".join(parts)


def _build_remediation(finding: dict) -> str:
    """Generate remediation guidance based on vulnerability class."""
    title = (finding.get("title") or "").lower()
    desc = (finding.get("description") or "").lower()
    text = f"{title} {desc}"

    if "xss" in text or "cross-site" in text:
        return (
            "1. Implement context-aware output encoding on all user-supplied data.\n"
            "2. Use Content Security Policy (CSP) headers to restrict script execution.\n"
            "3. Sanitize HTML input using a vetted library (e.g., DOMPurify).\n"
            "4. Validate and sanitize all user inputs server-side."
        )
    elif "sqli" in text or "sql injection" in text:
        return (
            "1. Use parameterized queries or prepared statements for all database interactions.\n"
            "2. Implement input validation with allow-list approach.\n"
            "3. Apply least-privilege database permissions.\n"
            "4. Deploy a Web Application Firewall (WAF) as defense-in-depth."
        )
    elif "ssrf" in text:
        return (
            "1. Validate and sanitize all URLs before making server-side requests.\n"
            "2. Implement allow-lists for permitted domains/IP ranges.\n"
            "3. Block requests to internal/private IP addresses.\n"
            "4. Use network segmentation to limit server-side access."
        )
    elif "idor" in text:
        return (
            "1. Implement proper authorization checks for all object access.\n"
            "2. Use indirect references (e.g., UUIDs) instead of sequential IDs.\n"
            "3. Verify ownership on every request, not just at the route level.\n"
            "4. Implement access control testing in CI/CD pipeline."
        )
    elif "redirect" in text:
        return (
            "1. Validate redirect targets against an allow-list of trusted domains.\n"
            "2. Use relative URLs or internal route identifiers.\n"
            "3. Warn users when navigating to external domains."
        )
    elif "csrf" in text:
        return (
            "1. Implement anti-CSRF tokens on all state-changing requests.\n"
            "2. Use SameSite cookie attribute (Strict or Lax).\n"
            "3. Verify Origin/Referer headers on sensitive endpoints.\n"
            "4. Require re-authentication for critical actions."
        )
    elif "command" in text or "rce" in text:
        return (
            "1. Avoid passing user input to system commands.\n"
            "2. Use language-native APIs instead of shell execution.\n"
            "3. Apply strict input validation with allow-lists.\n"
            "4. Run services with minimal OS privileges."
        )
    else:
        return (
            "1. Review the vulnerable code and apply the principle of least privilege.\n"
            "2. Implement proper input validation and output encoding.\n"
            "3. Add security monitoring and alerting for this vulnerability class.\n"
            "4. Conduct a thorough security review of related code paths."
        )


def draft_hackerone(finding: dict, program_info: dict[str, str] | None = None) -> SubmissionDraft:
    """Draft a HackerOne submission formatted in their markdown style."""
    severity = _derive_severity(finding)
    cvss = map_cvss(finding)
    bounty_tier = _derive_bounty_tier(severity, "hackerone")
    title = finding.get("title", "Untitled Vulnerability")
    asset = finding.get("asset_id", "N/A")
    description = finding.get("description", "No description provided.")
    steps = finding.get("steps_to_reproduce", "No steps provided.")
    evidence = finding.get("evidence", "")

    summary = f"[{severity}] {title} on {asset}"

    description_md = f"""**Vulnerability Type:** {finding.get('vuln_class', 'N/A')}
**Affected Asset:** `{asset}`
**Severity:** {severity} ({cvss.score})

## Description
{description}

## Steps to Reproduce
{steps}

## Impact
{_build_impact_section(finding, severity)}

## Remediation
{_build_remediation(finding)}
"""

    evidence_list = []
    if evidence:
        evidence_list.append(f"```\n{evidence}\n```")

    if program_info:
        description_md += f"\n## Program Notes\n"
        for key, val in program_info.items():
            description_md += f"- **{key}:** {val}\n"

    return SubmissionDraft(
        title=summary,
        severity=severity,
        summary=summary,
        description=description_md,
        impact=_build_impact_section(finding, severity),
        steps_to_reproduce=steps,
        evidence=evidence_list,
        platform="hackerone",
        bounty_tier=bounty_tier,
        cvss_score=cvss.score,
        cvss_vector=cvss.vector_string,
        remediation=_build_remediation(finding),
    )


def draft_bugcrowd(finding: dict, program_info: dict[str, str] | None = None) -> SubmissionDraft:
    """Draft a Bugcrowd submission in their markdown format."""
    severity = _derive_severity(finding)
    cvss = map_cvss(finding)
    bounty_tier = _derive_bounty_tier(severity, "bugcrowd")
    title = finding.get("title", "Untitled Vulnerability")
    asset = finding.get("asset_id", "N/A")
    description = finding.get("description", "No description provided.")
    steps = finding.get("steps_to_reproduce", "No steps provided.")
    evidence = finding.get("evidence", "")

    summary = f"{title} — {asset}"

    description_md = f"""## Summary
{description}

## Vulnerability Type
{finding.get('vuln_class', 'N/A')}

## Affected Asset
`{asset}`

## Severity
{severity} (CVSS: {cvss.score})

## Steps to Reproduce
{steps}

## Impact
{_build_impact_section(finding, severity)}

## Remediation
{_build_remediation(finding)}
"""

    evidence_list = []
    if evidence:
        evidence_list.append(f"```\n{evidence}\n```")

    if program_info:
        description_md += f"\n## Additional Context\n"
        for key, val in program_info.items():
            description_md += f"- **{key}:** {val}\n"

    return SubmissionDraft(
        title=summary,
        severity=severity,
        summary=summary,
        description=description_md,
        impact=_build_impact_section(finding, severity),
        steps_to_reproduce=steps,
        evidence=evidence_list,
        platform="bugcrowd",
        bounty_tier=bounty_tier,
        cvss_score=cvss.score,
        cvss_vector=cvss.vector_string,
        remediation=_build_remediation(finding),
    )


def draft_generic(finding: dict) -> SubmissionDraft:
    """Draft a platform-agnostic submission in clean markdown."""
    severity = _derive_severity(finding)
    cvss = map_cvss(finding)
    title = finding.get("title", "Untitled Vulnerability")
    asset = finding.get("asset_id", "N/A")
    description = finding.get("description", "No description provided.")
    steps = finding.get("steps_to_reproduce", "No steps provided.")
    evidence = finding.get("evidence", "")

    summary = f"[{severity}] {title}"

    description_md = f"""# {title}

**Severity:** {severity} (CVSS: {cvss.score})
**Asset:** `{asset}`
**Vulnerability Class:** {finding.get('vuln_class', 'N/A')}

## Description
{description}

## Steps to Reproduce
{steps}

## Impact
{_build_impact_section(finding, severity)}

## Remediation
{_build_remediation(finding)}

## CVSS Vector
`{cvss.vector_string}`
"""

    evidence_list = []
    if evidence:
        evidence_list.append(f"```\n{evidence}\n```")

    return SubmissionDraft(
        title=summary,
        severity=severity,
        summary=summary,
        description=description_md,
        impact=_build_impact_section(finding, severity),
        steps_to_reproduce=steps,
        evidence=evidence_list,
        platform="generic",
        bounty_tier=severity,
        cvss_score=cvss.score,
        cvss_vector=cvss.vector_string,
        remediation=_build_remediation(finding),
    )


def validate_submission(draft: SubmissionDraft, platform: str) -> list[str]:
    """Validate a draft for a given platform. Returns list of issues (empty = valid)."""
    issues: list[str] = []

    if not draft.title or len(draft.title.strip()) < 10:
        issues.append("Title must be at least 10 characters.")
    if not draft.description or len(draft.description.strip()) < 50:
        issues.append("Description must be at least 50 characters.")
    if not draft.steps_to_reproduce or len(draft.steps_to_reproduce.strip()) < 20:
        issues.append("Steps to reproduce must be at least 20 characters.")
    if not draft.severity:
        issues.append("Severity must be specified.")

    if platform == "hackerone":
        if not draft.evidence:
            issues.append("HackerOne requires at least one piece of evidence.")
        if draft.cvss_score < 4.0:
            issues.append("HackerOne may not accept findings below CVSS 4.0.")

    elif platform == "bugcrowd":
        if not draft.evidence:
            issues.append("Bugcrowd strongly recommends including evidence.")
        if len(draft.title) > 100:
            issues.append("Bugcrowd title should be under 100 characters.")

    if draft.title and len(draft.title) > 200:
        issues.append("Title exceeds 200 character limit.")

    return issues


def add_evidence(draft: SubmissionDraft, evidence: str) -> SubmissionDraft:
    """Append evidence (code blocks, screenshots, logs) to the draft."""
    if evidence and evidence not in draft.evidence:
        draft.evidence.append(evidence)
    return draft


def draft_multi_platform(finding: dict, platforms: list[str], program_info: dict[str, str] | None = None) -> dict[str, SubmissionDraft]:
    """Draft submissions for multiple platforms at once."""
    drafts: dict[str, SubmissionDraft] = {}
    for platform in platforms:
        if platform == "hackerone":
            drafts["hackerone"] = draft_hackerone(finding, program_info)
        elif platform == "bugcrowd":
            drafts["bugcrowd"] = draft_bugcrowd(finding, program_info)
        else:
            drafts[platform] = draft_generic(finding)
    return drafts
