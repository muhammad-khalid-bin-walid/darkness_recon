"""
lib/report_utils.py — Reporting utility functions for Dark Recon Framework
Extracted from inline shell heredocs per plan Phase 3.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

# Severity ordering (higher index = higher severity)
_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_SEVERITY_WEIGHTS = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 1.0, "info": 0.1}


def generate_summary(findings: list[dict]) -> dict:
    """Return {total, by_severity, by_phase, by_status} counts."""
    by_severity: dict[str, int] = {}
    by_phase: dict[str, int] = {}
    by_status: dict[str, int] = {}

    for f in findings:
        sev = (f.get("severity") or "info").lower()
        phase = f.get("phase") or "unknown"
        status = (f.get("status") or "new").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_phase[phase] = by_phase.get(phase, 0) + 1
        by_status[status] = by_status.get(status, 0) + 1

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_phase": by_phase,
        "by_status": by_status,
    }


def severity_counts(findings: list[dict]) -> dict:
    """Return {critical, high, medium, low, info} counts."""
    counts = {s: 0 for s in _SEVERITY_ORDER}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["info"] += 1
    return counts


def format_markdown_report(scan_run: dict, findings: list[dict]) -> str:
    """Generate a markdown report string from scan_run metadata and findings."""
    target = scan_run.get("target", "Unknown")
    profile = scan_run.get("profile", "default")
    started = scan_run.get("started_at", "")
    completed = scan_run.get("completed_at", "")
    phases = scan_run.get("phases_run", [])
    schema_ver = scan_run.get("schema_version", "1.0.2")

    counts = severity_counts(findings)
    lines = [
        f"# Dark Recon Framework — Engagement Report",
        f"",
        f"**Target:** `{target}`  ",
        f"**Profile:** `{profile}`  ",
        f"**Schema:** `{schema_ver}`  ",
        f"**Started:** {started}  ",
        f"**Completed:** {completed}  ",
        f"**Phases Run:** {', '.join(phases) if phases else 'N/A'}  ",
        f"",
        f"---",
        f"",
        f"## Executive Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {sev.capitalize()} | {counts[sev]} |")

    lines += ["", f"**Total Findings:** {len(findings)}", "", "---", "", "## Findings", ""]

    sorted_findings = sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER.get((f.get("severity") or "info").lower(), 0),
        reverse=True,
    )

    for i, f in enumerate(sorted_findings, 1):
        title = f.get("title", "Untitled")
        sev = (f.get("severity") or "info").upper()
        asset = f.get("asset_id", "")
        phase = f.get("phase", "")
        tool = f.get("tool", "")
        desc = f.get("description", "")
        confidence = f.get("confidence", 0.0)

        lines += [
            f"### {i}. {title}",
            f"",
            f"- **Severity:** {sev}",
            f"- **Asset:** `{asset}`",
            f"- **Phase:** `{phase}`",
            f"- **Tool:** `{tool}`",
            f"- **Confidence:** {confidence:.0%}",
            f"",
        ]
        if desc:
            lines += [f"{desc}", ""]

    return "\n".join(lines)


def format_json_report(scan_run: dict, findings: list[dict]) -> str:
    """Generate a pretty-printed JSON report string."""
    report = {
        "scan_run": scan_run,
        "summary": generate_summary(findings),
        "severity_counts": severity_counts(findings),
        "risk_score": calculate_risk_score(findings),
        "findings": sorted(
            findings,
            key=lambda f: _SEVERITY_ORDER.get((f.get("severity") or "info").lower(), 0),
            reverse=True,
        ),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    return json.dumps(report, indent=2, default=str)


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Dedup by fingerprint; fallback to title+asset_id composite key."""
    seen: set[str] = set()
    result: list[dict] = []
    for f in findings:
        key = f.get("fingerprint") or f"{f.get('title', '')}|{f.get('asset_id', '')}"
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


def filter_by_severity(findings: list[dict], min_severity: str) -> list[dict]:
    """Return findings at or above min_severity (critical > high > medium > low > info)."""
    min_level = _SEVERITY_ORDER.get(min_severity.lower(), 0)
    return [
        f for f in findings
        if _SEVERITY_ORDER.get((f.get("severity") or "info").lower(), 0) >= min_level
    ]


def calculate_risk_score(findings: list[dict]) -> float:
    """
    Weighted risk score 0–100.
    Weights: critical=10, high=5, medium=2, low=1, info=0.1
    Capped at 100.
    """
    raw = sum(
        _SEVERITY_WEIGHTS.get((f.get("severity") or "info").lower(), 0.1)
        for f in findings
    )
    return min(100.0, round(raw, 2))
