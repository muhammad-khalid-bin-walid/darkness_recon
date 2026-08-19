#!/bin/bash
# Track 7 - Distributed Scale: Redis-based job queue phase
# Job persistence, retry logic, distributed task management

redis_queue_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/redis_queue"

    mkdir -p "$phase_dir"

    # Source core if not already sourced
    if ! declare -f log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    log "INFO" "Starting Redis queue phase for $domain"
    py_log "INFO" "redis_queue_phase_start" --phase "redis_queue" --target "$domain" 2>/dev/null || true

    local queue_config="$phase_dir/queue_config.json"
    local queue_status="$phase_dir/queue_status.txt"
    local count=0

    # Check for Redis availability
    if tool_available redis-cli; then
        local redis_host="${REDIS_HOST:-127.0.0.1}"
        local redis_port="${REDIS_PORT:-6379}"

        # Test Redis connection
        if redis-cli -h "$redis_host" -p "$redis_port" ping >/dev/null 2>&1; then
            log "INFO" "Redis server reachable at $redis_host:$redis_port"

            # Configure job queue
            local queue_name="darkrecon:$domain:jobs"
            local result_queue="darkrecon:$domain:results"
            local retry_queue="darkrecon:$domain:retries"

            cat > "$queue_config" <<JSONEOF
{
    "queue_name": "$queue_name",
    "result_queue": "$result_queue",
    "retry_queue": "$retry_queue",
    "redis_host": "$redis_host",
    "redis_port": $redis_port,
    "max_retries": 3,
    "retry_delay_ms": 1000,
    "job_ttl_seconds": 3600,
    "result_ttl_seconds": 86400,
    "worker_concurrency": 4,
    "visibility_timeout": 300,
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSONEOF
            count=$((count + 1))

            # Enqueue scan jobs
            local job_types=("subdomain_enumeration" "port_scan" "web_analysis" "vulnerability_scan")
            local jobs_enqueued=0

            for job_type in "${job_types[@]}"; do
                local job_payload
                job_payload=$(cat <<JOBEOF
{"domain":"$domain","type":"$job_type","priority":"normal","created_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
JOBEOF
)
                redis-cli -h "$redis_host" -p "$redis_port" \
                    LPUSH "$queue_name" "$job_payload" >/dev/null 2>&1 && \
                    jobs_enqueued=$((jobs_enqueued + 1)) || true
            done

            log "INFO" "Enqueued $jobs_enqueued scan jobs to Redis"

            # Write finding
            write_finding "{\"type\":\"redis_queue_configured\",\"domain\":\"$domain\",\"queue\":\"$queue_name\",\"jobs_enqueued\":$jobs_enqueued,\"redis_endpoint\":\"$redis_host:$redis_port\"}" "$phase_dir/finding_queue.json" 2>/dev/null || true

            # Check queue status
            local pending_jobs
            pending_jobs=$(redis-cli -h "$redis_host" -p "$redis_port" LLEN "$queue_name" 2>/dev/null || echo "0")

            cat > "$queue_status" <<STATUSEOF
Redis Queue Status
==================
Domain: $domain
Queue: $queue_name
Result Queue: $result_queue
Retry Queue: $retry_queue
Pending Jobs: $pending_jobs
Jobs Enqueued: $jobs_enqueued
Redis: $redis_host:$redis_port
Status: active
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
STATUSEOF
            count=$((count + 1))
        else
            log "WARN" "Redis server not reachable at $redis_host:$redis_port"
            _redis_queue_fallback_config "$domain" "$phase_dir"
        fi
    else
        log "WARN" "redis-cli not available, generating offline queue config"
        _redis_queue_fallback_config "$domain" "$phase_dir"
    fi

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Redis queue phase complete: $count results"
    py_log "INFO" "redis_queue_phase_complete" --phase "redis_queue" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}

_redis_queue_fallback_config() {
    local domain="$1"
    local phase_dir="$2"

    cat > "$phase_dir/queue_config.json" <<JSONEOF
{
    "queue_name": "darkrecon:$domain:jobs",
    "result_queue": "darkrecon:$domain:results",
    "retry_queue": "darkrecon:$domain:retries",
    "redis_host": "127.0.0.1",
    "redis_port": 6379,
    "max_retries": 3,
    "retry_delay_ms": 1000,
    "job_ttl_seconds": 3600,
    "result_ttl_seconds": 86400,
    "worker_concurrency": 4,
    "visibility_timeout": 300,
    "mode": "file_based_fallback",
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSONEOF

    cat > "$phase_dir/queue_status.txt" <<STATUSEOF
Redis Queue Status (Fallback Mode)
===================================
Domain: $domain
Mode: File-based fallback (Redis unavailable)
Queue: darkrecon:$domain:jobs
Status: configured_offline
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
STATUSEOF
}

export -f redis_queue_phase _redis_queue_fallback_config
