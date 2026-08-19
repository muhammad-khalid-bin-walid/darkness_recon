"""lib/llm_reporter.py — LLM-assisted report generation (plan Phase 163)"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

PROMPT_TEMPLATES: dict[str, str] = {
    "executive_summary": (
        "You are a senior security analyst. Based on the following vulnerability "
        "findings, write a concise executive summary (3-5 paragraphs) suitable "
        "for a CISO audience. Highlight overall risk posture, most critical issues, "
        "and recommended immediate actions.\n\nFindings:\n{findings_text}"
    ),
    "finding_detail": (
        "You are a penetration tester. Write a detailed technical finding report "
        "for the following vulnerability. Include title, severity, affected component, "
        "description, proof-of-concept steps, impact analysis, and remediation.\n\n"
        "Finding:\n{finding_text}"
    ),
    "remediation": (
        "You are a security consultant. Provide clear, actionable remediation "
        "guidance for the following vulnerability. Include short-term mitigations "
        "and long-term fixes. Be specific about configuration changes or code "
        "modifications.\n\nVulnerability:\n{finding_text}"
    ),
    "report_structure": (
        "You are a report architect. Given the following scope and findings summary, "
        "propose a structured report outline with section headings and brief "
        "descriptions of what each section should contain.\n\nScope: {scope}\n"
        "Findings summary: {findings_summary}"
    ),
}


@dataclass
class ReportDraft:
    """Container for a generated security report draft."""

    title: str = ""
    executive_summary: str = ""
    findings_section: str = ""
    remediation: str = ""
    appendices: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_markdown(self) -> str:
        parts = [
            f"# {self.title}",
            "",
            "## Executive Summary",
            self.executive_summary,
            "",
            "## Findings",
            self.findings_section,
            "",
            "## Remediation",
            self.remediation,
        ]
        if self.appendices:
            parts.extend(["", "## Appendices", self.appendices])
        if self.metadata:
            parts.extend(["", "---", f"*Generated: {self.metadata.get('generated_at', 'N/A')}*"])
        return "\n".join(parts)


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Simple token-bucket rate limiter (10 requests / 60 s)."""

    def __init__(self, max_requests: int = 10, window: float = 60.0) -> None:
        self.max_requests = max_requests
        self.window = window
        self._timestamps: list[float] = []

    def wait_if_needed(self) -> None:
        now = time.monotonic()
        self._timestamps = [t for t in self._timestamps if now - t < self.window]
        if len(self._timestamps) >= self.max_requests:
            sleep_for = self.window - (now - self._timestamps[0]) + 0.1
            time.sleep(max(sleep_for, 0))
        self._timestamps.append(time.monotonic())


_rate_limiter = _RateLimiter()


# ---------------------------------------------------------------------------
# LLM call abstraction
# ---------------------------------------------------------------------------

def _call_llm(
    prompt: str,
    model: str = "gpt-4o-mini",
    api_key: str | None = None,
    provider: str = "openai",
    temperature: float = 0.3,
) -> str:
    """Send a prompt to an LLM API and return the response text.

    Supports ``openai`` and ``anthropic`` providers.  Raises on HTTP errors
    after retry attempts are exhausted.
    """
    if not api_key:
        return ""

    _rate_limiter.wait_if_needed()

    max_retries = 3
    last_error: Exception | None = None

    for attempt in range(max_retries):
        try:
            if provider == "anthropic":
                return _call_anthropic(prompt, model, api_key, temperature)
            return _call_openai(prompt, model, api_key, temperature)
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            last_error = exc
            if isinstance(exc, urllib.error.HTTPError) and exc.code == 429:
                wait = 2 ** attempt
                time.sleep(wait)
                continue
            break

    raise RuntimeError(f"LLM call failed after {max_retries} attempts: {last_error}")


def _call_openai(
    prompt: str, model: str, api_key: str, temperature: float
) -> str:
    url = "https://api.openai.com/v1/chat/completions"
    payload = json.dumps({
        "model": model,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read())
    return data["choices"][0]["message"]["content"]


def _call_anthropic(
    prompt: str, model: str, api_key: str, temperature: float
) -> str:
    url = "https://api.anthropic.com/v1/messages"
    payload = json.dumps({
        "model": model,
        "max_tokens": 4096,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read())
    return data["content"][0]["text"]


# ---------------------------------------------------------------------------
# Template-based fallbacks
# ---------------------------------------------------------------------------

def _template_executive_summary(findings: list[dict[str, Any]]) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1

    total = len(findings)
    critical = counts.get("critical", 0)
    high = counts.get("high", 0)

    lines = [
        f"This report presents the results of a security assessment covering "
        f"{total} identified finding(s).",
        "",
    ]

    if critical:
        lines.append(
            f"**{critical} critical** and **{high} high** severity issues require "
            f"immediate attention."
        )
    elif high:
        lines.append(f"**{high} high** severity issues were identified.")
    else:
        lines.append("No critical or high severity issues were found.")

    lines.append(
        "\nOverall risk posture is assessed based on the severity distribution "
        "above. Detailed findings and remediation guidance follow."
    )
    return "\n".join(lines)


def _template_remediation(finding: dict[str, Any]) -> str:
    severity = str(finding.get("severity", "medium")).lower()
    title = finding.get("title", "Unknown vulnerability")

    lines = [
        f"### Remediation: {title}",
        "",
        f"**Severity:** {severity.capitalize()}",
        "",
        "**Short-term mitigation:**",
        "- Apply vendor patches or updates immediately",
        "- Implement WAF rules if available",
        "- Restrict access to affected components",
        "",
        "**Long-term fix:**",
        "- Address root cause in application code",
        "- Add automated security testing to CI/CD pipeline",
        "- Schedule follow-up assessment after remediation",
    ]
    return "\n".join(lines)


def _template_finding_detail(finding: dict[str, Any]) -> str:
    lines = [
        f"### {finding.get('title', 'Untitled Finding')}",
        "",
        f"**Severity:** {finding.get('severity', 'N/A')}",
        f"**Affected Component:** {finding.get('target', 'N/A')}",
        f"**Tool:** {finding.get('tool', 'N/A')}",
        "",
        "**Description:**",
        finding.get("description", "No description provided."),
        "",
        "**Remediation:**",
        "Refer to the remediation section for guidance.",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_executive_summary(findings: list[dict[str, Any]], api_key: str | None = None) -> str:
    """Return an executive summary string for the given findings."""
    findings_text = "\n".join(
        f"- [{f.get('severity', '?').upper()}] {f.get('title', 'N/A')}"
        for f in findings
    )

    if api_key:
        prompt = PROMPT_TEMPLATES["executive_summary"].format(findings_text=findings_text)
        try:
            return _call_llm(prompt, api_key=api_key)
        except Exception:
            pass

    return _template_executive_summary(findings)


def generate_remediation(finding: dict[str, Any], api_key: str | None = None) -> str:
    """Return remediation guidance for a single finding."""
    finding_text = json.dumps(finding, indent=2, default=str)

    if api_key:
        prompt = PROMPT_TEMPLATES["remediation"].format(finding_text=finding_text)
        try:
            return _call_llm(prompt, api_key=api_key)
        except Exception:
            pass

    return _template_remediation(finding)


def generate_report(
    findings: list[dict[str, Any]],
    program_info: dict[str, Any] | None = None,
    format: str = "markdown",
    api_key: str | None = None,
) -> ReportDraft:
    """Produce a full ReportDraft for the supplied findings.

    If an ``api_key`` is provided the LLM backend is called; otherwise a
    template-based draft is returned immediately.
    """
    program_info = program_info or {}
    now = datetime.now(timezone.utc).isoformat()

    title = program_info.get("title", "Security Assessment Report")
    scope = program_info.get("scope", "Unknown scope")

    executive_summary = generate_executive_summary(findings, api_key=api_key)

    findings_lines = [f"### Finding {i + 1}" for i, f in enumerate(findings, 1)]
    findings_section = "\n\n".join(_template_finding_detail(f) for f in findings)

    remediation_parts = [generate_remediation(f, api_key=api_key) for f in findings]
    remediation = "\n\n---\n\n".join(remediation_parts)

    metadata = {
        "generated_at": now,
        "total_findings": len(findings),
        "scope": scope,
        "format": format,
        "llm_used": bool(api_key),
    }

    return ReportDraft(
        title=title,
        executive_summary=executive_summary,
        findings_section=findings_section,
        remediation=remediation,
        metadata=metadata,
    )
