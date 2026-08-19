"""
lib/correlation.py — Cross-phase correlation graph (plan Phase 17)

Builds: asset -> tech stack -> CVEs -> candidate exploitation phases
Uses a simple adjacency structure (no external graph lib dependency).
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

# Mapping of tech fingerprints to known CVE categories and relevant phases
TECH_TO_PHASES: dict[str, list[str]] = {
    "wordpress":    ["vuln", "nuclei", "secrets", "git"],
    "drupal":       ["vuln", "nuclei"],
    "joomla":       ["vuln", "nuclei"],
    "apache":       ["vuln", "nuclei", "ssl"],
    "nginx":        ["vuln", "ssl", "waf"],
    "iis":          ["vuln", "nuclei"],
    "php":          ["vuln", "fuzz", "secrets"],
    "java":         ["vuln", "nuclei", "api"],
    "nodejs":       ["vuln", "secrets", "api"],
    "spring":       ["vuln", "nuclei", "api"],
    "django":       ["vuln", "api"],
    "rails":        ["vuln", "api"],
    "graphql":      ["api", "nuclei"],
    "jenkins":      ["cicd", "secrets", "vuln"],
    "gitlab":       ["cicd", "git", "secrets"],
    "github":       ["git", "secrets"],
    "aws":          ["cloud", "secrets"],
    "azure":        ["cloud", "secrets"],
    "gcp":          ["cloud", "secrets"],
    "kubernetes":   ["cloud", "secrets"],
    "docker":       ["cloud"],
    "elasticsearch":["database", "vuln"],
    "mongodb":      ["database", "vuln"],
    "redis":        ["database"],
    "mysql":        ["database"],
    "postgres":     ["database"],
    "struts":       ["vuln", "nuclei"],
    "log4j":        ["vuln", "nuclei"],
    "jquery":       ["vuln", "patterns"],
    "react":        ["patterns", "api"],
    "angular":      ["patterns", "api"],
}


class CorrelationGraph:
    """
    Lightweight correlation graph: asset → tech → CVE categories → phases.
    Stored as nested dicts for portability (no networkx requirement).
    """

    def __init__(self):
        # {asset_id: {domain, type, criticality, techs, phases, cve_categories}}
        self._assets: dict[str, dict] = {}
        # {asset_id: [finding_ids]}
        self._findings: dict[str, list[str]] = defaultdict(list)

    def add_asset(self, asset_id: str, domain: str = "", asset_type: str = "web",
                  criticality: str = "prod", techs: list[str] | None = None) -> None:
        techs = [t.lower() for t in (techs or [])]
        phases = self._recommended_phases(techs)
        cve_cats = self._cve_categories(techs)
        self._assets[asset_id] = {
            "asset_id": asset_id,
            "domain": domain,
            "type": asset_type,
            "criticality": criticality,
            "techs": techs,
            "recommended_phases": phases,
            "cve_categories": cve_cats,
        }

    def add_finding(self, asset_id: str, finding_id: str) -> None:
        self._findings[asset_id].append(finding_id)

    def get_asset(self, asset_id: str) -> dict | None:
        return self._assets.get(asset_id)

    def get_recommended_phases(self, asset_id: str) -> list[str]:
        asset = self._assets.get(asset_id, {})
        return asset.get("recommended_phases", [])

    def get_findings(self, asset_id: str) -> list[str]:
        return self._findings.get(asset_id, [])

    def all_assets(self) -> list[dict]:
        return list(self._assets.values())

    def to_dict(self) -> dict:
        return {
            "assets": self._assets,
            "finding_links": dict(self._findings),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: dict) -> "CorrelationGraph":
        g = cls()
        for asset_id, info in data.get("assets", {}).items():
            g._assets[asset_id] = info
        for asset_id, fids in data.get("finding_links", {}).items():
            g._findings[asset_id] = fids
        return g

    def _recommended_phases(self, techs: list[str]) -> list[str]:
        phases: set[str] = set()
        for tech in techs:
            phases.update(TECH_TO_PHASES.get(tech, []))
        return sorted(phases)

    def _cve_categories(self, techs: list[str]) -> list[str]:
        categories: set[str] = set()
        for tech in techs:
            if tech in ("apache", "nginx", "iis"):
                categories.add("web_server_cve")
            if tech in ("php", "java", "nodejs", "python"):
                categories.add("runtime_cve")
            if tech in ("wordpress", "drupal", "joomla"):
                categories.add("cms_cve")
            if tech in ("aws", "azure", "gcp"):
                categories.add("cloud_misconfiguration")
            if tech in ("struts", "log4j", "spring"):
                categories.add("known_rce")
        return sorted(categories)


def build_from_scan(assets: list[dict], findings: list[dict]) -> CorrelationGraph:
    """Build a CorrelationGraph from lists of Asset and Finding dicts."""
    g = CorrelationGraph()
    for asset in assets:
        techs = asset.get("tags", []) + [asset.get("tech", "")] if asset.get("tech") else asset.get("tags", [])
        g.add_asset(
            asset_id=asset.get("id", ""),
            domain=asset.get("domain", ""),
            asset_type=asset.get("type", "web"),
            criticality=asset.get("criticality", "prod"),
            techs=techs,
        )
    for finding in findings:
        g.add_finding(finding.get("asset_id", ""), finding.get("id", ""))
    return g
