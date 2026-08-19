#!/usr/bin/env bash
# Phase 281: Interactive Mode, Guided Scanning, User Prompts
# Track 20 - UX/CLI

ux_interactive() {
    local domain="${1:?Usage: ux_interactive <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/ux_interactive"
    mkdir -p "$phase_dir"

    log "INFO" "[INTERACTIVE] Setting up interactive mode for $domain"

    local interactive_config="$phase_dir/interactive_config.json"
    local user_preferences="$phase_dir/user_preferences.txt"

    local count=0

    cat > "$interactive_config" <<ICEOF
{
  "domain": "$domain",
  "timestamp": "$TIMESTAMP",
  "interactive_mode": {
    "enabled": true,
    "prompts": {
      "scan_scope": {
        "question": "What scan scope would you like?",
        "options": ["passive", "active", "full"],
        "default": "passive"
      },
      "phase_selection": {
        "question": "Which phases to run?",
        "options": ["all", "recon-only", "scan-only", "custom"],
        "default": "all"
      },
      "output_detail": {
        "question": "Output detail level?",
        "options": ["minimal", "standard", "verbose"],
        "default": "standard"
      }
    },
    "guided_flow": [
      "Step 1: Confirm target domain",
      "Step 2: Select scan scope",
      "Step 3: Choose phases",
      "Step 4: Review configuration",
      "Step 5: Execute scan",
      "Step 6: Review results"
    ]
  }
}
ICEOF
    count=$((count + 1))

    log "INFO" "[INTERACTIVE] Generating user preferences"
    {
        echo "=== User Preferences ==="
        echo "Domain: $domain"
        echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "Default Settings:"
        echo "  Scan Scope: passive"
        echo "  Phase Selection: all"
        echo "  Output Detail: standard"
        echo "  Error Handling: continue"
        echo "  Logging Level: INFO"
        echo ""
        echo "Guided Flow:"
        echo "  1. Confirm target domain"
        echo "  2. Select scan scope"
        echo "  3. Choose phases"
        echo "  4. Review configuration"
        echo "  5. Execute scan"
        echo "  6. Review results"
        echo ""
        echo "Customization:"
        echo "  - Override defaults via CLI flags"
        echo "  - Save preferences for reuse"
        echo "  - Skip guided flow with --auto"
    } > "$user_preferences"
    count=$((count + 1))

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_finding "$phase_dir" "INTERACTIVE" "Interactive mode configured" "info" "info"

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "interactive_complete" "Interactive mode setup complete: $count items"
    log "INFO" "[INTERACTIVE] Completed: $count items generated"

    return 0
}
