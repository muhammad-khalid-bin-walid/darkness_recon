#!/bin/bash
# Track 7 - Distributed Scale: Work-stealing queue phase
# Load balancing, idle worker detection, task redistribution

work_stealing_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/work_stealing"

    mkdir -p "$phase_dir"

    if ! declare -f log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    log "INFO" "Starting work-stealing phase for $domain"
    py_log "INFO" "work_stealing_phase_start" --phase "work_stealing" --target "$domain" 2>/dev/null || true

    local stealing_config="$phase_dir/stealing_config.json"
    local stealing_stats="$phase_dir/stealing_stats.txt"
    local count=0

    # Detect available workers
    local worker_count=1
    if command -v nproc >/dev/null 2>&1; then
        worker_count=$(nproc 2>/dev/null || echo 1)
    fi

    # Check for Docker containers
    local docker_workers=0
    if tool_available docker; then
        docker_workers=$(docker ps --filter "name=darkrecon" --format "{{.ID}}" 2>/dev/null | wc -l || echo 0)
    fi

    local total_workers=$((worker_count + docker_workers))

    # Configure work stealing
    local steal_threshold="${STEAL_THRESHOLD:-5}"
    local idle_timeout="${IDLE_TIMEOUT:-30}"
    local max_steal_batch="${MAX_STEAL_BATCH:-10}"
    local steal_strategy="${STEAL_STRATEGY:-nearest_idle}"

    cat > "$stealing_config" <<JSONEOF
{
    "domain": "$domain",
    "total_workers": $total_workers,
    "local_workers": $worker_count,
    "docker_workers": $docker_workers,
    "queue": {
        "type": "deque_per_worker",
        "initial_capacity": 100,
        "overflow_strategy": "work_stealing"
    },
    "stealing_policy": {
        "strategy": "$steal_threshold",
        "idle_threshold_seconds": $idle_timeout,
        "max_steal_batch": $max_steal_batch,
        "steal_strategy": "$steal_strategy",
        "victim_selection": "random",
        "backoff_after_failed_steal_ms": 100
    },
    "load_balancing": {
        "task_granularity": "fine",
        "affinity_enabled": false,
        "work_dampening": true,
        "dampening_factor": 0.8
    },
    "monitoring": {
        "queue_depth Sampling": "10s",
        "worker_heartbeat_interval": "5s",
        "steal_event_logging": true
    },
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSONEOF
    count=$((count + 1))

    # Generate work items for distribution
    local scan_tasks=("dns_enumeration" "port_scan" "web_crawl" "tech_detect" "ssl_check" "vuln_scan" "osint_collect" "subdomain_verify")
    local task_count=${#scan_tasks[@]}
    local tasks_per_worker=$((task_count / total_workers))
    [ "$tasks_per_worker" -lt 1 ] && tasks_per_worker=1

    cat > "$stealing_stats" <<STATUSEOF
Work-Stealing Statistics
========================
Domain: $domain
Total Workers: $total_workers
Local Workers: $worker_count
Docker Workers: $docker_workers
Scan Tasks: $task_count
Tasks Per Worker: ~$tasks_per_worker
Steal Strategy: $steal_strategy
Idle Threshold: ${idle_timeout}s
Max Steal Batch: $max_steal_batch
Status: configured
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
STATUSEOF
    count=$((count + 1))

    write_finding "{\"type\":\"work_stealing_configured\",\"domain\":\"$domain\",\"total_workers\":$total_workers,\"tasks\":$task_count,\"strategy\":\"$steal_strategy\"}" "$phase_dir/finding_stealing.json" 2>/dev/null || true

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Work-stealing phase complete: $count results"
    py_log "INFO" "work_stealing_phase_complete" --phase "work_stealing" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}

export -f work_stealing_phase
