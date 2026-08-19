"""
lib/healthcheck.py — Framework health-check command (plan Phase 15)

Checks: tool availability, config validity, disk space, network reachability.
Reports framework readiness before a run starts.
"""
from __future__ import annotations

import json
import shutil
import socket
import sys
from pathlib import Path


def check_tools(essential: list[str], optional: list[str] | None = None) -> dict:
    """Check tool availability. Returns {tool: "ok"|"missing"}."""
    results = {}
    for tool in essential:
        results[tool] = "ok" if shutil.which(tool) else "missing"
    for tool in (optional or []):
        results[tool] = "ok" if shutil.which(tool) else "missing_optional"
    return results


def check_disk_space(path: str = ".", min_mb: int = 500) -> dict:
    """Return disk space info and whether minimum is available."""
    try:
        usage = shutil.disk_usage(path)
        free_mb = usage.free // (1024 * 1024)
        return {
            "path": path,
            "free_mb": free_mb,
            "total_mb": usage.total // (1024 * 1024),
            "ok": free_mb >= min_mb,
            "min_required_mb": min_mb,
        }
    except Exception as e:
        return {"path": path, "error": str(e), "ok": False}


def check_network(hosts: list[str] | None = None, timeout: int = 3) -> dict:
    """Check network reachability for a list of hostnames via TCP port 443."""
    if hosts is None:
        hosts = ["8.8.8.8", "1.1.1.1"]
    results = {}
    for host in hosts:
        try:
            socket.setdefaulttimeout(timeout)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, 53))
            results[host] = "ok"
        except Exception:
            results[host] = "unreachable"
    return results


def check_config(config_dir: str = "config") -> dict:
    """Validate config files and return {ok, errors}."""
    try:
        from lib.config_validator import validate_all
        results = validate_all(config_dir)
        errors = [e for errs in results.values() for e in errs]
        return {"ok": len(errors) == 0, "errors": errors, "files_checked": list(results.keys())}
    except Exception as e:
        return {"ok": False, "errors": [str(e)], "files_checked": []}


def check_directories(dirs: list[str]) -> dict:
    """Check required directories exist and are writable."""
    results = {}
    for d in dirs:
        p = Path(d)
        if not p.exists():
            try:
                p.mkdir(parents=True, exist_ok=True)
                results[d] = "created"
            except Exception:
                results[d] = "cannot_create"
        elif not p.is_dir():
            results[d] = "not_a_directory"
        else:
            # Check write permission
            try:
                test_file = p / ".healthcheck_write_test"
                test_file.touch()
                test_file.unlink()
                results[d] = "ok"
            except Exception:
                results[d] = "not_writable"
    return results


def run_healthcheck(
    config_dir: str = "config",
    output_dir: str = "output",
    cache_dir: str = "cache",
    logs_dir: str = "logs",
    essential_tools: list[str] | None = None,
) -> dict:
    """
    Run all health checks and return a structured report.
    Report format: {ready: bool, checks: {tools, disk, network, config, dirs}}
    """
    if essential_tools is None:
        essential_tools = ["subfinder", "httpx", "jq", "whatweb", "unfurl"]

    checks = {
        "tools": check_tools(essential_tools),
        "disk": check_disk_space(output_dir),
        "network": check_network(),
        "config": check_config(config_dir),
        "dirs": check_directories([output_dir, cache_dir, logs_dir]),
    }

    # Determine overall readiness
    tools_ok = all(v == "ok" for k, v in checks["tools"].items() if not v.endswith("_optional"))
    disk_ok = checks["disk"].get("ok", False)
    config_ok = checks["config"].get("ok", False)
    dirs_ok = all(v in ("ok", "created") for v in checks["dirs"].values())

    ready = tools_ok and disk_ok and config_ok and dirs_ok

    return {
        "ready": ready,
        "checks": checks,
        "summary": {
            "tools_ok": tools_ok,
            "disk_ok": disk_ok,
            "network_ok": any(v == "ok" for v in checks["network"].values()),
            "config_ok": config_ok,
            "dirs_ok": dirs_ok,
        },
    }


def _cli_main(argv: list[str]) -> int:
    report = run_healthcheck()
    print(json.dumps(report, indent=2))
    if not report["ready"]:
        print("\n[!] Framework is NOT ready. Fix the issues above before running.", file=sys.stderr)
        return 1
    print("\n[OK] Framework is ready.")
    return 0


if __name__ == "__main__":
    sys.exit(_cli_main(sys.argv[1:]))
