#!/usr/bin/env bash
# Phase 291: Architecture Documentation, System Diagrams, Component Overview
# Track 21 - Documentation

docs_architecture() {
    local domain="${1:?Usage: docs_architecture <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/docs_architecture"
    mkdir -p "$phase_dir/architecture_docs"

    log "INFO" "[ARCH_DOCS] Generating architecture documentation for $domain"

    local system_diagrams="$phase_dir/system_diagrams.txt"

    local count=0

    cat > "$phase_dir/architecture_docs/architecture.md" <<'ARCHEOF'
# DarkRecon Architecture

## System Overview

DarkRecon is a phase-based security reconnaissance framework organized into tracks.

## Component Structure

```
dark_recon_framework/
├── core/
│   ├── core.sh              # Logging, tool checks, utilities
│   └── phase_bridge.sh      # Output functions (write_finding, write_asset, etc.)
├── phases/
│   ├── recon_*_phase.sh     # Reconnaissance phases (1-50)
│   ├── scan_*_phase.sh      # Scanning phases (51-100)
│   ├── analysis_*_phase.sh  # Analysis phases (101-150)
│   ├── report_*_phase.sh    # Reporting phases (151-200)
│   ├── compliance_*_phase.sh # Compliance phases (261-270)
│   ├── collab_*_phase.sh    # Collaboration phases (271-280)
│   ├── ux_*_phase.sh        # UX/CLI phases (281-290)
│   └── docs_*_phase.sh      # Documentation phases (291-300)
├── plugins/                 # Extensible plugin system
├── config/                  # Configuration files
└── output/                  # Scan results
```

## Data Flow

1. User invokes phase with domain argument
2. Phase sources core.sh for utilities
3. Phase creates output directory structure
4. Phase executes with tool_available checks
5. Phase writes results via phase_bridge functions
6. Phase writes count.txt with result count

## Key Interfaces

### core.sh
- log "LEVEL" "message" - Structured logging
- tool_available "tool" - Tool existence check

### phase_bridge.sh
- write_finding - Document security findings
- write_asset - Document discovered assets
- write_endpoint - Document discovered endpoints

### py_log
- Structured Python logging for machine-readable output
ARCHEOF
    count=$((count + 1))

    log "INFO" "[ARCH_DOCS] Generating system diagrams"
    {
        echo "=== System Diagrams ==="
        echo "Domain: $domain"
        echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "1. Execution Flow:"
        echo "   User -> Phase Script -> core.sh -> Tool Execution -> phase_bridge.sh -> Output"
        echo ""
        echo "2. Output Structure:"
        echo "   OUTPUT_DIR/"
        echo "   └── domain/"
        echo "       └── recon_TIMESTAMP/"
        echo "           ├── phase_name/"
        echo "           │   ├── findings.json"
        echo "           │   ├── assets.json"
        echo "           │   ├── endpoints.json"
        echo "           │   └── count.txt"
        echo "           └── ... (other phases)"
        echo ""
        echo "3. Track Map:"
        echo "   Track 1  (1-50):   Reconnaissance"
        echo "   Track 2  (51-100): Scanning"
        echo "   Track 3  (101-150): Analysis"
        echo "   Track 4  (151-200): Reporting"
        echo "   Track 18 (261-270): Compliance"
        echo "   Track 19 (271-280): Collaboration"
        echo "   Track 20 (281-290): UX/CLI"
        echo "   Track 21 (291-300): Documentation"
    } > "$system_diagrams"
    count=$((count + 1))

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_finding "$phase_dir" "ARCH" "Architecture documentation generated" "info" "info"

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "architecture_complete" "Architecture docs complete: $count items"
    log "INFO" "[ARCH_DOCS] Completed: $count items generated"

    return 0
}
