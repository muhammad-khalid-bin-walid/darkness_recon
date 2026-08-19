from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

PHASE_TEMPLATE = """\
#!/usr/bin/env bash
set -euo pipefail

# {description}
# Track: {track}

write_finding() {{
    local severity="$1" title="$2" detail="$3"
    py_log "${{severity}}" "${{title}}" "${{detail}}"
}}

main() {{
    write_finding "info" "{name}" "Phase started"
    # TODO: implement phase logic
    write_finding "info" "{name}" "Phase complete"
}}

main "$@"
"""

LIB_MODULE_TEMPLATE = """\
from __future__ import annotations

\"\"\"
{name}: {description}
\"\"\"


def run() -> dict:
    \"\"\"Execute the module and return results.\"\"\"
    return {{"module": "{name}", "status": "ok"}}
"""


@dataclass
class PhaseTemplate:
    name: str
    description: str
    track: int
    dependencies: list[str] = field(default_factory=list)
    tools_required: list[str] = field(default_factory=list)


def scaffold_phase(
    name: str, description: str, track: int, output_dir: str = "phases"
) -> str:
    """Write a phase script to disk and return the file path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    dest = out / f"{name}.sh"
    content = PHASE_TEMPLATE.format(
        name=name, description=description, track=track
    )
    dest.write_text(content, encoding="utf-8")
    return str(dest)


def scaffold_lib_module(
    name: str, description: str, output_dir: str = "lib"
) -> str:
    """Write a Python library module to disk and return the file path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    dest = out / f"{name}.py"
    content = LIB_MODULE_TEMPLATE.format(name=name, description=description)
    dest.write_text(content, encoding="utf-8")
    return str(dest)


def validate_plugin(phase_file: str) -> dict:
    """Validate a phase script for required patterns."""
    errors: list[str] = []
    warnings: list[str] = []
    path = Path(phase_file)
    if not path.exists():
        return {"valid": False, "errors": [f"File not found: {phase_file}"], "warnings": []}
    content = path.read_text(encoding="utf-8")
    if not content.startswith("#!"):
        errors.append("Missing shebang line.")
    if "set -euo pipefail" not in content:
        errors.append("Missing 'set -euo pipefail'.")
    if not re.search(r"function\s+\w+|^\w+\(\)", content, re.MULTILINE):
        warnings.append("No function definition detected.")
    if "write_finding" not in content:
        warnings.append("No call to write_finding().")
    if "py_log" not in content:
        warnings.append("No call to py_log().")
    return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}


def register_plugin(manifest_path: str, phase_info: dict) -> bool:
    """Add or update a plugin entry in the manifest JSON file."""
    path = Path(manifest_path)
    manifest: dict = {}
    if path.exists():
        manifest = json.loads(path.read_text(encoding="utf-8"))
    plugins: list[dict] = manifest.get("plugins", [])
    name = phase_info.get("name", "")
    existing = next((p for p in plugins if p.get("name") == name), None)
    if existing:
        existing.update(phase_info)
    else:
        plugins.append(phase_info)
    manifest["plugins"] = plugins
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return True


def list_plugins(manifest_path: str) -> list[dict]:
    """Return the list of registered plugins from the manifest."""
    path = Path(manifest_path)
    if not path.exists():
        return []
    manifest = json.loads(path.read_text(encoding="utf-8"))
    return manifest.get("plugins", [])
