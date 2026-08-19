#!/usr/bin/env bash
# Severity Escalation & CVSS Recalculation
# Recalculates CVSS scores based on context, business impact, and exploitability

severity_escalation_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "severity_escalation_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/severity_escalation"
    mkdir -p "$phase_dir"

    log "INFO" "Starting severity_escalation_phase for $domain"

    local escalated_severity="$phase_dir/escalated_severity.txt"
    local escalation_reasons="$phase_dir/escalation_reasons.txt"
    local count=0

    # --- Collect all findings from other phases ---
    log "INFO" "Collecting findings from other phases..."
    local all_findings="$phase_dir/all_findings.txt"
    find "$output_dir" -name "*_vulns.txt" -exec cat {} \; > "$all_findings" 2>/dev/null || true

    if [[ ! -s "$all_findings" ]]; then
        log "WARN" "No findings to escalate"
        echo "0" > "$phase_dir/count.txt"
        return 0
    fi

    local total_findings
    total_findings=$(wc -l < "$all_findings" | tr -d ' ') || true
    log "INFO" "Found $total_findings findings to evaluate for escalation"

    # --- Determine domain context factors ---
    log "INFO" "Analyzing domain context for escalation..."

    local is_production=false
    local is_financial=false
    local is_healthcare=false
    local is_government=false
    local has_pii=false

    if echo "$domain" | grep -qiE "prod|production|live|www\.|app\."; then
        is_production=true
    fi
    if echo "$domain" | grep -qiE "bank|pay|finance|credit|invest|trading|wallet"; then
        is_financial=true
    fi
    if echo "$domain" | grep -qiE "health|medical|clinic|hospital|patient|hipaa"; then
        is_healthcare=true
    fi
    if echo "$domain" | grep -qiE "gov|mil|army|navy|defense|federal"; then
        is_government=true
    fi

    # --- Check for PII indicators in findings ---
    if grep -qiE "email|password|credential|token|api.key|secret|ssn|credit.card" "$all_findings" 2>/dev/null; then
        has_pii=true
    fi

    # --- Write escalation context ---
    echo "--- SEVERITY ESCALATION CONTEXT ---" > "$escalated_severity"
    echo "domain=$domain" >> "$escalated_severity"
    echo "timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$escalated_severity"
    echo "total_findings=$total_findings" >> "$escalated_severity"
    echo "is_production=$is_production" >> "$escalated_severity"
    echo "is_financial=$is_financial" >> "$escalated_severity"
    echo "is_healthcare=$is_healthcare" >> "$escalated_severity"
    echo "is_government=$is_government" >> "$escalated_severity"
    echo "has_pii=$has_pii" >> "$escalated_severity"

    # --- Calculate escalation multiplier ---
    local multiplier=1.0
    local reasons=()

    if $is_production; then
        multiplier=$(echo "$multiplier + 0.5" | bc 2>/dev/null || echo "$multiplier")
        reasons+=("Production environment: +0.5")
    fi
    if $is_financial; then
        multiplier=$(echo "$multiplier + 1.0" | bc 2>/dev/null || echo "$multiplier")
        reasons+=("Financial/PCI scope: +1.0")
    fi
    if $is_healthcare; then
        multiplier=$(echo "$multiplier + 1.0" | bc 2>/dev/null || echo "$multiplier")
        reasons+=("Healthcare/HIPAA scope: +1.0")
    fi
    if $is_government; then
        multiplier=$(echo "$multiplier + 1.5" | bc 2>/dev/null || echo "$multiplier")
        reasons+=("Government/FedRAMP scope: +1.5")
    fi
    if $has_pii; then
        multiplier=$(echo "$multiplier + 0.5" | bc 2>/dev/null || echo "$multiplier")
        reasons+=("PII exposure detected: +0.5")
    fi

    echo "escalation_multiplier=$multiplier" >> "$escalated_severity"

    # --- Write escalation reasons ---
    echo "--- ESCALATION REASONS ---" > "$escalation_reasons"
    for reason in "${reasons[@]}"; do
        echo "$reason" >> "$escalation_reasons"
    done

    # --- Identify critical findings that warrant escalation ---
    log "INFO" "Identifying critical findings for escalation..."

    local critical_patterns=(
        "SQL injection"
        "remote code execution"
        "RCE"
        "authentication bypass"
        "default credential"
        "open relay"
        "unauthenticated"
        "data exposure"
        "credentials leaked"
        "API key exposed"
        "private key exposed"
        "SSRF"
        "directory traversal"
        "file inclusion"
    )

    for pattern in "${critical_patterns[@]}"; do
        local matched
        matched=$(grep -ci "$pattern" "$all_findings" 2>/dev/null) || true
        if [[ "$matched" -gt 0 ]]; then
            echo "[ESCALATE] $pattern: $matched occurrence(s) found" >> "$escalation_reasons"
            echo "[ESCALATE] Pattern '$pattern' detected $matched times - recommend severity escalation" >> "$escalated_severity"
            ((count++)) || true
        fi
    done

    # --- Determine final severity classification ---
    local severity_class="MEDIUM"
    if $is_government || $is_financial || $is_healthcare; then
        severity_class="CRITICAL"
    elif $is_production && $has_pii; then
        severity_class="HIGH"
    elif $is_production; then
        severity_class="HIGH"
    elif $has_pii; then
        severity_class="MEDIUM"
    fi

    echo "final_severity=$severity_class" >> "$escalated_severity"
    echo "severity_class=$severity_class" >> "$phase_dir/gate_check.txt"

    # --- Generate escalation summary ---
    echo "" >> "$escalated_severity"
    echo "--- ESCALATION SUMMARY ---" >> "$escalated_severity"
    echo "Base finding count: $total_findings" >> "$escalated_severity"
    echo "Context multiplier: $multiplier" >> "$escalated_severity"
    echo "Final severity: $severity_class" >> "$escalated_severity"
    echo "Escalated patterns: $count" >> "$escalated_severity"

    # --- Write structured findings ---
    while IFS= read -r line; do
        write_finding "$phase_dir" "$line" "severity_escalation" "" "" ""
    done < "$escalated_severity"

    write_asset "$phase_dir" "$domain" "severity_escalation" "final_severity=$severity_class" "" ""

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "severity_escalation_phase" "domain=$domain severity=$severity_class multiplier=$multiplier findings=$count"

    log "INFO" "severity_escalation_phase complete: severity=$severity_class (multiplier=$multiplier)"
    return 0
}

severity_escalation_phase "$@"
