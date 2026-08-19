"""
lib/sbom.py — Software Bill of Materials auto-generation (plan Phase 211)
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def _parse_package_json(path: Path) -> list[dict]:
    """Extract dependencies from package.json."""
    deps = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for name, version in data.get(section, {}).items():
                deps.append({"name": name, "version": version, "ecosystem": "npm", "type": section})
    except Exception:
        pass
    return deps


def _parse_requirements_txt(path: Path) -> list[dict]:
    """Extract dependencies from requirements.txt."""
    deps = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            name, version = line.split("==", 1)
            deps.append({"name": name.strip(), "version": version.strip(), "ecosystem": "pypi", "type": "dependencies"})
        elif ">=" in line:
            name = line.split(">=")[0].strip()
            deps.append({"name": name, "version": ">=", "ecosystem": "pypi", "type": "dependencies"})
        else:
            deps.append({"name": line, "version": "unknown", "ecosystem": "pypi", "type": "dependencies"})
    return deps


def generate_sbom(scan_target: str, discovered_files: list[str]) -> dict:
    """
    Generate a basic SBOM from discovered dependency manifests.
    Returns CycloneDX-inspired structure.
    """
    components = []
    for file_path in discovered_files:
        p = Path(file_path)
        if not p.exists():
            continue
        if p.name == "package.json":
            components.extend(_parse_package_json(p))
        elif p.name in ("requirements.txt", "requirements-dev.txt"):
            components.extend(_parse_requirements_txt(p))

    return {
        "bomFormat": "CycloneDX-lite",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {"name": scan_target, "type": "application"},
        },
        "components": components,
        "summary": {
            "total_components": len(components),
            "ecosystems": list({c["ecosystem"] for c in components}),
        },
    }
