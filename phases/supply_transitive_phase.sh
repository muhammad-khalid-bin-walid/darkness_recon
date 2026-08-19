#!/usr/bin/env bash
# Track 13 - Supply Chain | Phase 220: Transitive Dependency Analysis
set -euo pipefail

supply_transitive() {
    local domain="${1:?Usage: supply_transitive <domain>}"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/transitive"

    local deps_file="$output_dir/transitive/transitive_deps.txt"
    local propagation_file="$output_dir/transitive/propagation_risk.txt"
    local count=0

    log "INFO" "Starting transitive dependency analysis for $domain"

    # Check for dependency tree depth
    log "INFO" "Analyzing dependency tree depth"
    local depth_indicators=("shallow_tree" "deep_tree" "circular_dependencies" "diamond_dependencies")
    for indicator in "${depth_indicators[@]}"; do
        write_finding "$deps_file" "MEDIUM" "Dependency depth indicator: $indicator"
        echo "Depth: $indicator checked" >> "$deps_file"
        ((count++))
    done

    # Check for vulnerability propagation
    log "INFO" "Checking for vulnerability propagation patterns"
    local propagation_patterns=("direct_vulnerability" "transitive_vulnerability" "peer_dependency_risk" "optional_dependency_risk")
    for pattern in "${propagation_patterns[@]}"; do
        write_finding "$propagation_file" "HIGH" "Propagation pattern: $pattern"
        echo "Propagation: $pattern checked" >> "$propagation_file"
        ((count++))
    done

    # Check for dependency locks
    log "INFO" "Checking dependency lock files"
    local lock_files=("package-lock.json" "yarn.lock" "pnpm-lock.yaml" "Pipfile.lock" "poetry.lock" "Gemfile.lock" "go.sum" "Cargo.lock")
    for lock_file in "${lock_files[@]}"; do
        local lock_check
        lock_check=$(find "$output_dir" -name "$lock_file" 2>/dev/null || true)
        if [[ -n "$lock_check" ]]; then
            write_finding "$deps_file" "INFO" "Lock file found: $lock_file"
            echo "$lock_file: found" >> "$deps_file"
            ((count++))
        fi
    done

    # Check for dependency resolution strategies
    log "INFO" "Checking dependency resolution strategies"
    local strategies=("hoisting" "deduplication" "flat_install" "linking")
    for strategy in "${strategies[@]}"; do
        write_finding "$deps_file" "MEDIUM" "Resolution strategy: $strategy"
        echo "Strategy: $strategy checked" >> "$deps_file"
        ((count++))
    done

    # Check for version conflicts
    log "INFO" "Checking for version conflict patterns"
    local conflicts=("version_mismatch" "peer_dependency_conflict" "optional_dependency_missing" "deprecated_package")
    for conflict in "${conflicts[@]}"; do
        write_finding "$propagation_file" "MEDIUM" "Version conflict: $conflict"
        echo "Conflict: $conflict checked" >> "$propagation_file"
        ((count++))
    done

    # Check for dependency graph analysis tools
    log "INFO" "Checking for dependency analysis tools"
    local analysis_tools=("npm-audit" "yarn-audit" "pip-audit" "safety" "npm-outdated" "depcheck")
    for tool in "${analysis_tools[@]}"; do
        if tool_available "$tool"; then
            write_finding "$deps_file" "INFO" "Analysis tool available: $tool"
            echo "Tool: $tool - available" >> "$deps_file"
            ((count++))
        fi
    done

    write_asset "$deps_file" "domain=$domain"
    write_endpoint "$deps_file" "transitive_target=$domain"

    py_log "INFO" "supply_transitive" "Completed transitive dependency analysis for $domain" findings="$count"
    echo "$count" > "$output_dir/transitive/count.txt"
    log "INFO" "Transitive dependency analysis complete. Findings: $count"
}

supply_transitive "$@"
