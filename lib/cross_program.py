"""
lib/cross_program.py — Cross-program correlation (plan Phase 28)
Correlates shared infra/vendor findings across multiple bug bounty programs.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path


def _load_findings(program: str, output_dir: str = "output") -> list[dict]:
    """Load all findings for a program from its output directory."""
    findings = []
    base = Path(output_dir) / program
    for f in base.rglob("findings*.json") if base.exists() else []:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(data, list):
                findings.extend(data)
            elif isinstance(data, dict) and "findings" in data:
                findings.extend(data["findings"])
        except Exception:
            pass
    return findings


def correlate_across_programs(
    programs: list[str],
    output_dir: str = "output",
) -> dict:
    """
    Find findings that appear across multiple programs (shared infra/vendor issues).

    Returns {
        "shared_findings": [{fingerprint, programs, count, representative}],
        "shared_assets":   [{domain/ip, programs, count}],
    }
    """
    # Collect fingerprints per program
    fp_to_programs: dict[str, set[str]] = defaultdict(set)
    fp_to_finding: dict[str, dict] = {}
    asset_to_programs: dict[str, set[str]] = defaultdict(set)

    for program in programs:
        findings = _load_findings(program, output_dir)
        for f in findings:
            fp = f.get("fingerprint") or f"{f.get('title','')}|{f.get('severity','')}"
            fp_to_programs[fp].add(program)
            if fp not in fp_to_finding:
                fp_to_finding[fp] = f
            # Track assets
            asset_id = f.get("asset_id", "")
            if asset_id:
                asset_to_programs[asset_id].add(program)

    shared_findings = [
        {
            "fingerprint": fp,
            "programs": sorted(progs),
            "count": len(progs),
            "representative": fp_to_finding[fp],
        }
        for fp, progs in fp_to_programs.items()
        if len(progs) > 1
    ]
    shared_findings.sort(key=lambda x: x["count"], reverse=True)

    shared_assets = [
        {"asset_id": aid, "programs": sorted(progs), "count": len(progs)}
        for aid, progs in asset_to_programs.items()
        if len(progs) > 1
    ]
    shared_assets.sort(key=lambda x: x["count"], reverse=True)

    return {
        "programs_analyzed": programs,
        "shared_findings": shared_findings,
        "shared_assets": shared_assets,
        "summary": {
            "total_shared_findings": len(shared_findings),
            "total_shared_assets": len(shared_assets),
        },
    }
