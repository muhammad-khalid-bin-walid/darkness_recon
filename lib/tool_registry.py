"""
lib/tool_registry.py — Tool auto-detection with graceful degradation (plan Phase 6)

Maps tools to:
- capabilities (what they do)
- fallbacks (alternative tools if missing)
- degraded_mode_warning (what gets skipped)
"""
from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass, field
from enum import Enum


class ToolStatus(str, Enum):
    AVAILABLE = "available"
    MISSING = "missing"
    DEGRADED = "degraded"  # available but an older/limited version


@dataclass
class ToolEntry:
    name: str
    capabilities: list[str]
    fallbacks: list[str] = field(default_factory=list)
    degraded_mode_warning: str = ""
    essential: bool = False
    install_hint: str = ""


# ---------------------------------------------------------------------------
# Registry — maps tool name to ToolEntry
# ---------------------------------------------------------------------------

REGISTRY: dict[str, ToolEntry] = {
    # Subdomain enumeration
    "subfinder": ToolEntry(
        name="subfinder",
        capabilities=["subdomain_enum"],
        fallbacks=["assetfinder", "amass"],
        essential=True,
        install_hint="go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    ),
    "assetfinder": ToolEntry(
        name="assetfinder",
        capabilities=["subdomain_enum"],
        fallbacks=["subfinder"],
        install_hint="go install github.com/tomnomnom/assetfinder@latest",
    ),
    "amass": ToolEntry(
        name="amass",
        capabilities=["subdomain_enum", "osint"],
        fallbacks=["subfinder"],
        degraded_mode_warning="Passive OSINT subdomain sources unavailable",
        install_hint="https://github.com/owasp-amass/amass#installation",
    ),
    "findomain": ToolEntry(
        name="findomain",
        capabilities=["subdomain_enum"],
        fallbacks=["subfinder"],
        essential=True,
        install_hint="https://github.com/Findomain/Findomain/releases",
    ),
    # HTTP probing
    "httpx": ToolEntry(
        name="httpx",
        capabilities=["live_host_detection", "http_probe"],
        fallbacks=[],
        essential=True,
        install_hint="go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    ),
    # Web crawling
    "katana": ToolEntry(
        name="katana",
        capabilities=["crawl", "endpoint_discovery"],
        fallbacks=["gospider", "hakrawler"],
        essential=True,
        degraded_mode_warning="JS-rendered crawling unavailable; falling back to gospider",
        install_hint="go install github.com/projectdiscovery/katana/cmd/katana@latest",
    ),
    "gospider": ToolEntry(
        name="gospider",
        capabilities=["crawl"],
        fallbacks=["hakrawler"],
        install_hint="go install github.com/jaeles-project/gospider@latest",
    ),
    "hakrawler": ToolEntry(
        name="hakrawler",
        capabilities=["crawl"],
        fallbacks=["gospider"],
        install_hint="go install github.com/hakluke/hakrawler@latest",
    ),
    # DNS
    "dnsx": ToolEntry(
        name="dnsx",
        capabilities=["dns_resolution", "dns_brute"],
        fallbacks=[],
        install_hint="go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    ),
    # Fuzzing
    "ffuf": ToolEntry(
        name="ffuf",
        capabilities=["dir_fuzz", "vhost_fuzz", "param_fuzz"],
        fallbacks=["gobuster"],
        degraded_mode_warning="Advanced fuzzing features unavailable; gobuster fallback active",
        install_hint="go install github.com/ffuf/ffuf/v2@latest",
    ),
    "gobuster": ToolEntry(
        name="gobuster",
        capabilities=["dir_fuzz", "dns_enum"],
        fallbacks=["ffuf"],
        install_hint="go install github.com/OJ/gobuster/v3@latest",
    ),
    # Vuln scanning
    "nuclei": ToolEntry(
        name="nuclei",
        capabilities=["vuln_scan", "template_scan"],
        fallbacks=[],
        degraded_mode_warning="Automated vulnerability template scanning unavailable",
        install_hint="go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    ),
    # Port scanning
    "nmap": ToolEntry(
        name="nmap",
        capabilities=["port_scan", "service_detection", "script_scan"],
        fallbacks=["naabu", "masscan"],
        degraded_mode_warning="Service detection scripts unavailable; basic port scan only",
        install_hint="apt install nmap / brew install nmap",
    ),
    "naabu": ToolEntry(
        name="naabu",
        capabilities=["port_scan"],
        fallbacks=["nmap"],
        install_hint="go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    ),
    # Takeover detection
    "subjack": ToolEntry(
        name="subjack",
        capabilities=["takeover_detection"],
        fallbacks=["subzy"],
        install_hint="go install github.com/haccer/subjack@latest",
    ),
    "subzy": ToolEntry(
        name="subzy",
        capabilities=["takeover_detection"],
        fallbacks=["subjack"],
        install_hint="go install github.com/PentestPad/subzy@latest",
    ),
    # Secret scanning
    "trufflehog": ToolEntry(
        name="trufflehog",
        capabilities=["secret_scan", "git_secret_scan"],
        fallbacks=[],
        degraded_mode_warning="Automated secret scanning in git history unavailable",
        install_hint="https://github.com/trufflesecurity/trufflehog#installation",
    ),
    # Utilities
    "jq": ToolEntry(
        name="jq",
        capabilities=["json_processing"],
        fallbacks=[],
        essential=True,
        install_hint="apt install jq / brew install jq",
    ),
    "whatweb": ToolEntry(
        name="whatweb",
        capabilities=["tech_detection"],
        fallbacks=[],
        essential=True,
        install_hint="apt install whatweb / gem install whatweb",
    ),
    "unfurl": ToolEntry(
        name="unfurl",
        capabilities=["url_parsing"],
        fallbacks=[],
        essential=True,
        install_hint="go install github.com/tomnomnom/unfurl@latest",
    ),
    # Historical recon
    "waybackurls": ToolEntry(
        name="waybackurls",
        capabilities=["historical_endpoints"],
        fallbacks=["gauplus"],
        install_hint="go install github.com/tomnomnom/waybackurls@latest",
    ),
    "gauplus": ToolEntry(
        name="gauplus",
        capabilities=["historical_endpoints"],
        fallbacks=["waybackurls"],
        install_hint="go install github.com/bp0lr/gauplus@latest",
    ),
    # Cloud
    "cloud_enum": ToolEntry(
        name="cloud_enum",
        capabilities=["cloud_asset_discovery"],
        fallbacks=[],
        degraded_mode_warning="Cloud asset discovery limited",
        install_hint="pip3 install cloud-enum",
    ),
    # Screenshots
    "aquatone": ToolEntry(
        name="aquatone",
        capabilities=["screenshots"],
        fallbacks=[],
        install_hint="https://github.com/michenriksen/aquatone/releases",
    ),
    # SSL
    "sslyze": ToolEntry(
        name="sslyze",
        capabilities=["ssl_analysis"],
        fallbacks=[],
        install_hint="pip3 install sslyze",
    ),
    # Params
    "arjun": ToolEntry(
        name="arjun",
        capabilities=["param_discovery"],
        fallbacks=[],
        degraded_mode_warning="Parameter discovery limited to wordlist-based fuzzing",
        install_hint="pip3 install arjun",
    ),
    "paramspider": ToolEntry(
        name="paramspider",
        capabilities=["param_discovery"],
        fallbacks=["arjun"],
        install_hint="pip3 install paramspider",
    ),
    # WAF
    "wafw00f": ToolEntry(
        name="wafw00f",
        capabilities=["waf_detection"],
        fallbacks=[],
        install_hint="pip3 install wafw00f",
    ),
    # Git scanning
    "gitrob": ToolEntry(
        name="gitrob",
        capabilities=["git_scan"],
        fallbacks=["trufflehog"],
        install_hint="https://github.com/michenriksen/gitrob",
    ),
    # Misc
    "anew": ToolEntry(
        name="anew",
        capabilities=["dedup"],
        fallbacks=[],
        install_hint="go install github.com/tomnomnom/anew@latest",
    ),
    "gf": ToolEntry(
        name="gf",
        capabilities=["pattern_match"],
        fallbacks=[],
        install_hint="go install github.com/tomnomnom/gf@latest",
    ),
}


def check_tool(name: str) -> ToolStatus:
    """Check whether a tool is available in PATH."""
    if shutil.which(name) is not None:
        return ToolStatus.AVAILABLE
    return ToolStatus.MISSING


def get_available_fallback(name: str) -> str | None:
    """Return first available fallback tool name, or None if all missing."""
    entry = REGISTRY.get(name)
    if not entry:
        return None
    for fallback in entry.fallbacks:
        if check_tool(fallback) == ToolStatus.AVAILABLE:
            return fallback
    return None


def check_all(extra_tools: list[str] | None = None) -> dict[str, dict]:
    """
    Check all registered tools (plus any extra_tools list).
    Returns {tool_name: {status, fallback, warning, essential}}.
    """
    results: dict[str, dict] = {}
    names = list(REGISTRY.keys())
    if extra_tools:
        names += [t for t in extra_tools if t not in REGISTRY]

    for name in names:
        status = check_tool(name)
        entry = REGISTRY.get(name, ToolEntry(name=name, capabilities=[]))
        fallback = None
        warning = ""

        if status == ToolStatus.MISSING:
            fallback = get_available_fallback(name)
            if fallback:
                status = ToolStatus.DEGRADED
                warning = entry.degraded_mode_warning or f"Using {fallback} as fallback for {name}"
            elif entry.essential:
                warning = f"ESSENTIAL tool {name} is missing with no fallback. Run --install."
            else:
                warning = entry.degraded_mode_warning or f"{name} unavailable; related capabilities skipped"

        results[name] = {
            "status": status.value,
            "fallback": fallback,
            "warning": warning,
            "essential": entry.essential,
            "capabilities": entry.capabilities,
            "install_hint": entry.install_hint,
        }
    return results


def get_missing_essentials() -> list[str]:
    """Return list of essential tool names that are missing with no fallback."""
    missing = []
    for name, entry in REGISTRY.items():
        if entry.essential and check_tool(name) == ToolStatus.MISSING:
            if get_available_fallback(name) is None:
                missing.append(name)
    return missing


def log_degraded_mode(tool_name: str) -> None:
    """Emit a structured degradation log line to stdout."""
    entry = REGISTRY.get(tool_name, ToolEntry(name=tool_name, capabilities=[]))
    fallback = get_available_fallback(tool_name)
    record = {
        "level": "WARN",
        "event": "tool_degraded",
        "tool": tool_name,
        "fallback": fallback,
        "capabilities_affected": entry.capabilities,
        "warning": entry.degraded_mode_warning or f"{tool_name} unavailable",
        "install_hint": entry.install_hint,
    }
    print(json.dumps(record))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cli_main(argv: list[str]) -> int:
    import json as _json
    if argv and argv[0] == "check-all":
        results = check_all()
        print(_json.dumps(results, indent=2))
        missing = [n for n, r in results.items() if r["status"] == "missing" and r["essential"]]
        return 1 if missing else 0
    elif argv and argv[0] == "check":
        for tool in argv[1:]:
            status = check_tool(tool)
            print(f"{tool}: {status.value}")
        return 0
    else:
        print("Usage: python3 -m lib.tool_registry check-all", file=sys.stderr)
        print("       python3 -m lib.tool_registry check <tool1> [tool2 ...]", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(_cli_main(sys.argv[1:]))
