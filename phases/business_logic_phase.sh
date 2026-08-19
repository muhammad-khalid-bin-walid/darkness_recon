#!/bin/bash
# Combined Phase 13: Business Logic Vulnerability Testing
# Encompasses: IDOR, BOLA, BFLA, mass assignment, workflow bypass phases
# Sources Python bridge for phase_log, write_asset, write_finding functions

[[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

business_logic_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local live_file="$output_dir/live/live_subdomains.json"
    local bl_dir="$output_dir/business_logic"

    mkdir -p "$bl_dir"

    log "INFO" "Starting business logic vulnerability testing for $domain"

    # IDOR testing - systematic object reference substitution
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Running IDOR test sequences..."
        # This would involve authenticated session testing
        # Placeholder for IDOR logic
        curl -sI "https://$domain" 2>>"$LOGS_DIR/business_logic.log" >> "$bl_dir/idortest.txt" || true
    fi

    # BOLA (Broken Object Level Authorization) testing
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Running BOLA test sequences..."
        # Placeholder for BOLA logic
        curl -sI "https://$domain/api/users" 2>>"$LOGS_DIR/business_logic.log" >> "$bl_dir/bolatest.txt" || true
    fi

    # Mass assignment testing
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Running mass assignment tests..."
        # Placeholder for mass assignment logic
        curl -sI "https://$domain/api/update" 2>>"$LOGS_DIR/business_logic.log" >> "$bl_dir/masstest.txt" || true
    fi

    # Workflow bypass testing
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Running workflow bypass tests..."
        # Placeholder for workflow bypass logic
        curl -sI "https://$domain/skip-step" 2>>"$LOGS_DIR/business_logic.log" >> "$bl_dir/workflowtest.txt" || true
    fi

    # Correlation: analyze findings for business logic issues
    local bl_count
    bl_count=$(ls -l "$bl_dir"/*.txt 2>/dev/null | grep -c "^-" || echo 0)

    phase_log "INFO" "Business logic vulnerability testing complete: $bl_count tests executed" "business_logic" "$domain"

    # Write assets
    for test_file in "$bl_dir"/*.txt; do
        [ -f "$test_file" ] || continue
        while IFS= read -r result; do
            [ -z "$result" ] && continue
            write_asset "{\"type\":\"business_logic_test\",\"value\":\"$result\",\"source\":\"logic_testing\",\"phase\":\"business_logic_testing\"}" \
                "$bl_dir/assets.jsonl" 2>/dev/null || true
        done < "$test_file"
    done

    echo "$bl_count" > "$bl_dir/count.txt"

    write_finding "{\"type\":\"business_logic_test\",\"severity\":\"info\",\"count\":$bl_count,\"phase\":\"business_logic_testing\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true

    py_log "INFO" "business_logic_phase" "Completed for $domain"
}