"""
lib/__main__.py — Entry point dispatcher for `python3 -m lib`
"""
import sys

SUBCOMMANDS = {
    "validator":    "lib.validator",
    "healthcheck":  "lib.healthcheck",
    "config":       "lib.config_validator",
    "tools":        "lib.tool_registry",
    "secrets":      "lib.secrets_hygiene",
    "urls":         "lib.url_utils",
    "dns":          "lib.dns_utils",
    "jwt":          "lib.jwt_tester",
    "js":           "lib.js_analyzer",
    "sbom":         "lib.sbom",
}

if len(sys.argv) < 2 or sys.argv[1] not in SUBCOMMANDS:
    print("Usage: python3 -m lib <subcommand> [args...]")
    print("Subcommands:", ", ".join(sorted(SUBCOMMANDS)))
    sys.exit(2)

cmd = sys.argv.pop(1)
import importlib
mod = importlib.import_module(SUBCOMMANDS[cmd])
if hasattr(mod, "_cli_main"):
    sys.exit(mod._cli_main(sys.argv[1:]))
