#!/bin/bash
# Track 9 - ML/Triage/Future: Intelligent scan scheduling, dependency-aware timing, resource optimization

scan_scheduler_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/scan_scheduler"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$phase_dir"

    log "INFO" "Starting scan scheduler phase for $domain"
    py_log "INFO" "scan_scheduler_phase_start" --phase "scan_scheduler" --target "$domain" 2>/dev/null || true

    local schedule_config="$phase_dir/schedule_config.json"
    local scheduled_tasks="$phase_dir/scheduled_tasks.txt"
    local count=0

    # Collect phase output directories to assess dependencies
    local phase_dependencies=()
    local phase_weights=()

    # Map known phases to their dependency tiers and resource weights
    local -A tier_map=(
        [dns_phase]=1
        [subdomain_phase]=1
        [dns_ssl_whois_phase]=1
        [cert_transparency_phase]=1
        [service_discovery_phase]=2
        [ports_phase]=2
        [live_phase]=2
        [httpx_phase]=2
        [crawl_phase]=3
        [fuzz_phase]=4
        [nuclei_phase]=4
        [vuln_phase]=5
        [exploitation_validation_phase]=6
        [secrets_phase]=4
        [cloud_phase]=4
        [reporting_phase]=9
    )

    local -A weight_map=(
        [dns_phase]=1
        [subdomain_phase]=1
        [dns_ssl_whois_phase]=1
        [cert_transparency_phase]=1
        [service_discovery_phase]=2
        [ports_phase]=2
        [live_phase]=1
        [httpx_phase]=1
        [crawl_phase]=3
        [fuzz_phase]=4
        [nuclei_phase]=5
        [vuln_phase]=4
        [exploitation_validation_phase]=3
        [secrets_phase]=2
        [cloud_phase]=3
        [reporting_phase]=1
    )

    # Build dependency-aware schedule
    log "INFO" "Building dependency-aware scan schedule..."

    python3 -c "
import json, os, sys

domain = '$domain'
output_dir = '$output_dir'
phase_dir = '$phase_dir'

tier_map = {
    'dns_phase': 1, 'subdomain_phase': 1, 'dns_ssl_whois_phase': 1,
    'cert_transparency_phase': 1, 'service_discovery_phase': 2,
    'ports_phase': 2, 'live_phase': 2, 'httpx_phase': 2,
    'crawl_phase': 3, 'fuzz_phase': 4, 'nuclei_phase': 4,
    'vuln_phase': 5, 'exploitation_validation_phase': 6,
    'secrets_phase': 4, 'cloud_phase': 4, 'reporting_phase': 9
}

weight_map = {
    'dns_phase': 1, 'subdomain_phase': 1, 'dns_ssl_whois_phase': 1,
    'cert_transparency_phase': 1, 'service_discovery_phase': 2,
    'ports_phase': 2, 'live_phase': 1, 'httpx_phase': 1,
    'crawl_phase': 3, 'fuzz_phase': 4, 'nuclei_phase': 5,
    'vuln_phase': 4, 'exploitation_validation_phase': 3,
    'secrets_phase': 2, 'cloud_phase': 3, 'reporting_phase': 1
}

# Check which phase outputs already exist
existing_phases = []
phases_dir = os.path.join(output_dir)
if os.path.isdir(phases_dir):
    for entry in os.listdir(phases_dir):
        full = os.path.join(phases_dir, entry)
        if os.path.isdir(full) and entry in tier_map:
            existing_phases.append(entry)

# Build schedule with tiers
schedule = {}
for phase, tier in sorted(tier_map.items(), key=lambda x: x[1]):
    dep_phases = [p for p, t in tier_map.items() if t < tier and p != phase]
    schedule[phase] = {
        'tier': tier,
        'weight': weight_map.get(phase, 1),
        'dependencies': dep_phases,
        'already_completed': phase in existing_phases,
        'estimated_cpu_pct': min(weight_map.get(phase, 1) * 10, 80),
        'priority': max(10 - tier, 1)
    }

config = {
    'domain': domain,
    'total_phases': len(schedule),
    'max_concurrent_tier': 4,
    'resource_limits': {
        'max_cpu_pct': 85,
        'max_memory_mb': 4096,
        'max_bandwidth_mbps': 100
    },
    'schedule': schedule
}

with open(os.path.join(phase_dir, 'schedule_config.json'), 'w') as f:
    json.dump(config, f, indent=2)

# Write scheduled tasks text
with open(os.path.join(phase_dir, 'scheduled_tasks.txt'), 'w') as f:
    for phase in sorted(schedule.keys(), key=lambda p: schedule[p]['tier']):
        s = schedule[phase]
        status = 'COMPLETED' if s['already_completed'] else 'PENDING'
        f.write(f\"Tier {s['tier']} | Priority {s['priority']} | Weight {s['weight']} | {status} | {phase}\n\")

print(len(schedule))
" 2>/dev/null > "$phase_dir/_count.txt" || true

    count=$(cat "$phase_dir/_count.txt" 2>/dev/null || echo 0)
    rm -f "$phase_dir/_count.txt" 2>/dev/null || true

    # Validate outputs with phase_bridge
    if [ -f "$schedule_config" ]; then
        write_finding "{\"type\":\"scan_schedule_generated\",\"target\":\"$domain\",\"phases_scheduled\":$count,\"method\":\"dependency_aware\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
            "$phase_dir/finding_schedule.json" 2>/dev/null || true
    fi

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Scan scheduler phase complete: $count phases scheduled for $domain"
    py_log "INFO" "scan_scheduler_phase_complete" --phase "scan_scheduler" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}
