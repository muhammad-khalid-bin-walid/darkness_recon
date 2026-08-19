#!/bin/bash
# Track 16 - Secrets Deep | Phase 241: Entropy-Based Secret Detection
# Random string identification, key pattern matching

secrets_entropy_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "secrets_entropy_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/secrets_entropy"
    mkdir -p "$phase_dir"

    log "INFO" "Starting secrets_entropy_phase for $domain"

    local entropy_file="$phase_dir/entropy_secrets.txt"
    local pattern_file="$phase_dir/pattern_matches.txt"
    local count=0

    # --- Entropy-based detection across crawl output ---
    local crawl_dir="$output_dir/crawl"
    if [[ -d "$crawl_dir" ]]; then
        log "INFO" "Running entropy analysis on crawled content..."
        for f in "$crawl_dir"/*.txt; do
            [[ -f "$f" ]] || continue
            grep -oE '[a-zA-Z0-9+/]{32,}={0,2}' "$f" 2>/dev/null | while IFS= read -r candidate; do
                local len=${#candidate}
                if (( len >= 32 )); then
                    # Calculate Shannon entropy via python
                    local entropy
                    entropy=$(python3 -c "
import math, collections
s='$candidate'
freq=collections.Counter(s)
length=float(len(s))
entropy=-sum((c/length)*math.log2(c/length) for c in freq.values())
print(f'{entropy:.2f}')
" 2>/dev/null) || true
                    if [[ -n "$entropy" ]] && python3 -c "exit(0 if float('$entropy') >= 4.0 else 1)" 2>/dev/null; then
                        echo "[ENTROPY] $candidate (entropy=$entropy, source=$(basename "$f"))" >> "$entropy_file"
                        ((count++)) || true
                    fi
                fi
            done
        done
    fi

    # --- Key pattern matching ---
    log "INFO" "Scanning for high-value key patterns..."
    local target_files=()
    if [[ -d "$crawl_dir" ]]; then
        while IFS= read -r -d '' f; do target_files+=("$f"); done < <(find "$crawl_dir" -name '*.txt' -print0 2>/dev/null)
    fi
    if [[ -f "$output_dir/recon_$TIMESTAMP/domains.txt" ]]; then
        target_files+=("$output_dir/recon_$TIMESTAMP/domains.txt")
    fi

    local key_patterns=(
        'AKIA[0-9A-Z]{16}'
        'ghp_[a-zA-Z0-9]{36}'
        'sk-[a-zA-Z0-9]{48}'
        'xox[bpsar]-[a-zA-Z0-9-]+'
        'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*'
        '[0-9]+:[a-zA-Z0-9_\-]{35,}'
        'AIza[0-9A-Za-z_-]{35}'
        'sq0csp-[a-zA-Z0-9_-]{43}'
        'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'
    )

    for tf in "${target_files[@]}"; do
        [[ -f "$tf" ]] || continue
        for pat in "${key_patterns[@]}"; do
            grep -oE "$pat" "$tf" 2>/dev/null | while IFS= read -r match; do
                echo "[PATTERN] $match (pattern=$pat, source=$(basename "$tf"))" >> "$pattern_file"
                ((count++)) || true
            done
        done
    done

    # --- Write structured findings ---
    if [[ -f "$entropy_file" ]]; then
        while IFS= read -r line; do
            write_finding "$phase_dir" "$line" "entropy_secret" "" "" "" || true
        done < "$entropy_file"
    fi

    if [[ -f "$pattern_file" ]]; then
        while IFS= read -r line; do
            write_finding "$phase_dir" "$line" "key_pattern_match" "" "" "" || true
        done < "$pattern_file"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "secrets_entropy_phase" "domain=$domain findings=$count"
    log "INFO" "secrets_entropy_phase complete: $count findings"
    return 0
}

secrets_entropy_phase "$@"
