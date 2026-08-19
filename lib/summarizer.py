"""lib/summarizer.py — Natural-language finding summarization (plan Phase 159)"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Severity templates
# ---------------------------------------------------------------------------

_SEVERITY_TEMPLATES: dict[str, dict[str, str]] = {
    "critical": {
        "technical": (
            "**[{severity.upper()}]** {title}\n"
            "- **Vulnerability class:** {vuln_class}\n"
            "- **CVSS/Score:** {cvss}\n"
            "- **Tool source:** {tool}\n"
            "- **Affected:** {target}\n"
            "- **Details:** {description}"
        ),
        "nontechnical": (
            "**CRITICAL — Immediate action required**\n"
            "{title}\n"
            "Business impact: This issue poses a severe risk to the organisation and "
            "could lead to full system compromise, data breach, or service outage if "
            "exploited. Immediate remediation is essential."
        ),
    },
    "high": {
        "technical": (
            "**[{severity.upper()}]** {title}\n"
            "- **Vulnerability class:** {vuln_class}\n"
            "- **CVSS/Score:** {cvss}\n"
            "- **Tool source:** {tool}\n"
            "- **Affected:** {target}\n"
            "- **Details:** {description}"
        ),
        "nontechnical": (
            "**HIGH — Prompt attention needed**\n"
            "{title}\n"
            "Business impact: This vulnerability significantly increases the attack "
            "surface and could be leveraged to gain elevated access or extract "
            "sensitive data. Remediation should be scheduled promptly."
        ),
    },
    "medium": {
        "technical": (
            "**[{severity.upper()}]** {title}\n"
            "- **Vulnerability class:** {vuln_class}\n"
            "- **CVSS/Score:** {cvss}\n"
            "- **Tool source:** {tool}\n"
            "- **Affected:** {target}\n"
            "- **Details:** {description}"
        ),
        "nontechnical": (
            "**MEDIUM — Address during normal maintenance**\n"
            "{title}\n"
            "Business impact: This issue presents a moderate risk. While not "
            "immediately exploitable in most scenarios, it should be resolved "
            "as part of regular patching cycles."
        ),
    },
    "low": {
        "technical": (
            "**[{severity.upper()}]** {title}\n"
            "- **Vulnerability class:** {vuln_class}\n"
            "- **CVSS/Score:** {cvss}\n"
            "- **Tool source:** {tool}\n"
            "- **Affected:** {target}\n"
            "- **Details:** {description}"
        ),
        "nontechnical": (
            "**LOW — Minor risk**\n"
            "{title}\n"
            "Business impact: This finding represents a limited risk. It may be "
            "useful for hardening but does not pose an immediate business threat."
        ),
    },
    "info": {
        "technical": (
            "**[{severity.upper()}]** {title}\n"
            "- **Vulnerability class:** {vuln_class}\n"
            "- **Tool source:** {tool}\n"
            "- **Affected:** {target}\n"
            "- **Details:** {description}"
        ),
        "nontechnical": (
            "**INFO — For awareness**\n"
            "{title}\n"
            "This is an informational finding. It does not represent a direct "
            "vulnerability but may be relevant context for the assessment."
        ),
    },
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_severity_template(severity: str) -> dict[str, str]:
    """Return the template dict (technical + nontechnical) for *severity*."""
    return _SEVERITY_TEMPLATES.get(severity.lower(), _SEVERITY_TEMPLATES["info"])


def _fmt_finding(finding: dict[str, Any], audience: str) -> str:
    """Render a single finding using the appropriate severity template."""
    severity = str(finding.get("severity", "info")).lower()
    templates = _get_severity_template(severity)

    key = "technical" if audience == "technical" else "nontechnical"
    template = templates[key]

    values = {
        "severity": severity,
        "title": finding.get("title", "Untitled finding"),
        "vuln_class": finding.get("vuln_class", "N/A"),
        "cvss": str(finding.get("cvss", finding.get("confidence", "N/A"))),
        "tool": finding.get("tool", "N/A"),
        "target": finding.get("target", "N/A"),
        "description": finding.get("description", "No description available."),
    }

    try:
        return template.format(**values)
    except KeyError:
        return template


def _severity_stats(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for f in findings:
        counts[str(f.get("severity", "info")).lower()] += 1
    return dict(counts)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def summarize_finding(finding: dict[str, Any]) -> str:
    """Return a natural-language summary of a single finding (technical audience)."""
    return _fmt_finding(finding, audience="technical")


def summarize_scan(findings: list[dict[str, Any]]) -> str:
    """Return an overall summary of a scan's findings with statistics."""
    total = len(findings)
    stats = _severity_stats(findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "## Scan Summary",
        "",
        f"**Total findings:** {total}",
        f"**Generated:** {now}",
        "",
        "### Severity Breakdown",
        "",
    ]

    for sev in ("critical", "high", "medium", "low", "info"):
        count = stats.get(sev, 0)
        if count:
            lines.append(f"- **{sev.capitalize()}:** {count}")

    if not any(stats.get(s) for s in ("critical", "high")):
        lines.append("\nNo critical or high severity issues were identified.")
    else:
        crit = stats.get("critical", 0)
        high = stats.get("high", 0)
        lines.append(
            f"\n**{crit} critical** and **{high} high** severity findings "
            f"require immediate attention."
        )

    return "\n".join(lines)


def summarize_for_stakeholder(
    findings: list[dict[str, Any]],
    audience: str = "technical",
) -> str:
    """Produce a stakeholder-oriented summary of all findings.

    Parameters
    ----------
    findings:
        List of finding dicts.
    audience:
        ``"technical"`` for engineers (includes vuln class, CVSS, tool source);
        ``"nontechnical"`` for executives (focuses on business impact, risk, and
        recommended actions).
    """
    parts: list[str] = []

    # overall statistics header
    parts.append(summarize_scan(findings))
    parts.append("")

    # per-finding details
    if audience == "technical":
        parts.append("### Detailed Findings (Technical)")
    else:
        parts.append("### Detailed Findings (Executive)")

    parts.append("")

    for i, finding in enumerate(findings, 1):
        rendered = _fmt_finding(finding, audience)
        parts.append(f"#### Finding {i}")
        parts.append(rendered)
        parts.append("")

    # closing recommendation
    if audience == "nontechnical":
        parts.append("---")
        parts.append(
            "We recommend scheduling a remediation planning session to address "
            "the identified issues in order of severity. Please reach out with "
            "any questions."
        )

    return "\n".join(parts)
