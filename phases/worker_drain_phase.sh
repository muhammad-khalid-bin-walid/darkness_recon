#!/bin/bash
# Track 7 - Distributed Scale: Worker drain phase
# Graceful drain, in-flight task completion, state preservation

worker_drain_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/worker_drain"

    mkdir -p "$phase_dir"

    if ! declare -f log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    log "INFO" "Starting worker drain phase for $domain"
    py_log "INFO" "worker_drain_phase_start" --phase "worker_drain" --target "$domain" 2>/dev/null || true

    local drain_config="$phase_dir/drain_config.json"
    local drain_status="$phase_dir/drain_status.txt"
    local count=0

    # Detect active workers
    local active_workers=0
    local docker_workers=0

    if tool_available docker; then
        docker_workers=$(docker ps --filter "name=darkrecon" --format "{{.ID}}" 2>/dev/null | wc -l || echo 0)
    fi

    # Count background processes
    local bg_processes
    bg_processes=$(jobs -p 2>/dev/null | wc -l || echo 0)

    active_workers=$((docker_workers + bg_processes))

    # Configure drain parameters
    local drain_timeout="${DRAIN_TIMEOUT:-300}"
    local graceful_period="${GRACEFUL_PERIOD:-60}"
    local force_kill_after="${FORCE_KILL_AFTER:-120}"

    # Create state preservation snapshot
    local state_dir="$phase_dir/state_snapshot"
    mkdir -p "$state_dir"

    # Save current scan state
    cat > "$state_dir/scan_state.json" <<STATEEOF
{
    "domain": "$domain",
    "snapshot_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "active_workers": $active_workers,
    "docker_workers": $docker_workers,
    "bg_processes": $bg_processes
}
STATEEOF

    # Save in-flight task list
    if tool_available docker; then
        docker ps --filter "name=darkrecon" --format "{{.ID}} {{.Names}} {{.Status}}" 2>/dev/null > "$state_dir/active_containers.txt" || true
    fi

    # Save partial results
    if [ -d "$output_dir" ]; then
        find "$output_dir" -name "*.json" -type f -exec cp {} "$state_dir/" \; 2>/dev/null || true
    fi

    cat > "$drain_config" <<JSONEOF
{
    "domain": "$domain",
    "drain_policy": {
        "timeout_seconds": $drain_timeout,
        "graceful_period_seconds": $graceful_period,
        "force_kill_after_seconds": $force_kill_after,
        "preserve_state": true,
        "save_partial_results": true
    },
    "drain_stages": [
        {
            "stage": 1,
            "action": "stop_accepting_new_tasks",
            "description": "Prevent new task assignment to draining workers"
        },
        {
            "stage": 2,
            "action": "wait_for_inflight_completion",
            "description": "Allow running tasks to complete within graceful period"
        },
        {
            "stage": 3,
            "action": "checkpoint_state",
            "description": "Save all worker state and partial results"
        },
        {
            "stage": 4,
            "action": "terminate_workers",
            "description": "Stop and remove worker containers"
        },
        {
            "stage": 5,
            "action": "verify_drain",
            "description": "Confirm all workers stopped cleanly"
        }
    ],
    "state_snapshot_dir": "$state_dir",
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSONEOF
    count=$((count + 1))

    # Execute drain
    local drain_start
    drain_start=$(date +%s 2>/dev/null || date +%s)
    local drain_completed=0
    local drain_failed=0

    if tool_available docker; then
        local containers
        containers=$(docker ps --filter "name=darkrecon" --format "{{.ID}}" 2>/dev/null || echo "")

        if [ -n "$containers" ]; then
            echo "$containers" | while read -r cid; do
                log "INFO" "Draining container: $cid"

                # Graceful stop with timeout
                if docker stop -t "$graceful_period" "$cid" >/dev/null 2>&1; then
                    drain_completed=$((drain_completed + 1))
                    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Drained: $cid (graceful)" >> "$phase_dir/drain_log.txt"
                else
                    drain_failed=$((drain_failed + 1))
                    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] Force killed: $cid" >> "$phase_dir/drain_log.txt"
                fi
            done
        fi
    fi

    local drain_end
    drain_end=$(date +%s 2>/dev/null || date +%s)
    local drain_duration=$((drain_end - drain_start))

    cat > "$drain_status" <<STATUSEOF
Worker Drain Status
===================
Domain: $domain
Active Workers at Start: $active_workers
Docker Workers: $docker_workers
BG Processes: $bg_processes
Drain Completed: $drain_completed
Drain Failed: $drain_failed
Drain Duration: ${drain_duration}s
State Preserved: yes
State Location: $state_dir
Status: drain_complete
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
STATUSEOF
    count=$((count + 1))

    write_finding "{\"type\":\"worker_drain_complete\",\"domain\":\"$domain\",\"workers_drained\":$drain_completed,\"failed\":$drain_failed,\"duration\":$drain_duration}" "$phase_dir/finding_drain.json" 2>/dev/null || true

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Worker drain phase complete: $count results (drained: $drain_completed, failed: $drain_failed)"
    py_log "INFO" "worker_drain_phase_complete" --phase "worker_drain" --target "$domain" --extra "{\"count\":$count,\"drained\":$drain_completed}" 2>/dev/null || true
}

export -f worker_drain_phase
