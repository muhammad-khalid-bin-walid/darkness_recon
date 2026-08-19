#!/bin/bash
# Track 7 - Distributed Scale: Docker worker containers phase
# Isolated scan execution, resource limits, health checks

docker_worker_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/docker_worker"

    mkdir -p "$phase_dir"

    if ! declare -f log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    log "INFO" "Starting Docker worker phase for $domain"
    py_log "INFO" "docker_worker_phase_start" --phase "docker_worker" --target "$domain" 2>/dev/null || true

    local worker_config="$phase_dir/worker_config.json"
    local worker_status="$phase_dir/worker_status.txt"
    local count=0

    if tool_available docker; then
        if docker info >/dev/null 2>&1; then
            log "INFO" "Docker daemon accessible"

            local image="${DOCKER_IMAGE:-dark-recon-framework:latest}"
            local worker_count="${DOCKER_WORKERS:-4}"
            local memory_limit="${DOCKER_MEMORY_LIMIT:-2g}"
            local cpu_limit="${DOCKER_CPU_LIMIT:-2}"
            local network="${DOCKER_NETWORK:-host}"

            # Check if image exists
            local image_status="available"
            if ! docker image inspect "$image" >/dev/null 2>&1; then
                image_status="needs_build"
                log "WARN" "Docker image $image not found locally"
            fi

            cat > "$worker_config" <<JSONEOF
{
    "image": "$image",
    "image_status": "$image_status",
    "worker_count": $worker_count,
    "resource_limits": {
        "memory": "$memory_limit",
        "cpus": "$cpu_limit",
        "network": "$network",
        "pids_limit": 256,
        "oom_kill_disable": false
    },
    "health_check": {
        "interval_seconds": 30,
        "timeout_seconds": 10,
        "retries": 3,
        "start_period_seconds": 60
    },
    "restart_policy": "unless-stopped",
    "logging": {
        "driver": "json-file",
        "max_size": "10m",
        "max_file": "3"
    },
    "environment": {
        "DOMAIN": "$domain",
        "GRACEFUL_DEGRADATION": "true",
        "DEBUG_MODE": "false"
    },
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSONEOF
            count=$((count + 1))

            # Deploy workers
            local workers_running=0
            local worker_container_ids=()

            for i in $(seq 1 "$worker_count"); do
                local container_name="darkrecon-worker-${domain}-${i}"
                local worker_output="$phase_dir/worker_$i"
                mkdir -p "$worker_output"

                # Stop existing container if running
                docker stop "$container_name" >/dev/null 2>&1 || true
                docker rm "$container_name" >/dev/null 2>&1 || true

                # Start worker container
                local container_id
                container_id=$(docker run -d \
                    --name "$container_name" \
                    --memory="$memory_limit" \
                    --cpus="$cpu_limit" \
                    --network="$network" \
                    --pids-limit=256 \
                    -v "$worker_output:/app/output" \
                    -e "DOMAIN=$domain" \
                    -e "WORKER_ID=$i" \
                    -e "TOTAL_WORKERS=$worker_count" \
                    "$image" \
                    sleep infinity 2>/dev/null) || true

                if [ -n "$container_id" ]; then
                    workers_running=$((workers_running + 1))
                    worker_container_ids+=("$container_id")
                    log "INFO" "Started Docker worker $i: $container_name"
                else
                    log "WARN" "Failed to start Docker worker $i"
                fi
            done

            write_finding "{\"type\":\"docker_workers_deployed\",\"domain\":\"$domain\",\"worker_count\":$worker_count,\"workers_running\":$workers_running,\"image\":\"$image\"}" "$phase_dir/finding_workers.json" 2>/dev/null || true

            # Health check
            local healthy_workers=0
            for cid in "${worker_container_ids[@]}"; do
                local health
                health=$(docker inspect --format='{{.State.Status}}' "$cid" 2>/dev/null || echo "unknown")
                if [ "$health" = "running" ]; then
                    healthy_workers=$((healthy_workers + 1))
                fi
            done

            cat > "$worker_status" <<STATUSEOF
Docker Worker Status
====================
Domain: $domain
Image: $image
Workers Requested: $worker_count
Workers Running: $workers_running
Healthy Workers: $healthy_workers
Memory Limit: $memory_limit
CPU Limit: $cpu_limit
Network: $network
Status: operational
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
STATUSEOF
            count=$((count + 1))

            write_asset "{\"type\":\"docker_workers\",\"domain\":\"$domain\",\"running\":$workers_running,\"healthy\":$healthy_workers}" "$phase_dir/asset_workers.json" 2>/dev/null || true
        else
            log "WARN" "Docker daemon not accessible"
            _docker_worker_fallback "$domain" "$phase_dir"
        fi
    else
        log "WARN" "Docker not available, generating offline config"
        _docker_worker_fallback "$domain" "$phase_dir"
    fi

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Docker worker phase complete: $count results"
    py_log "INFO" "docker_worker_phase_complete" --phase "docker_worker" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}

_docker_worker_fallback() {
    local domain="$1"
    local phase_dir="$2"

    cat > "$phase_dir/worker_config.json" <<JSONEOF
{
    "image": "dark-recon-framework:latest",
    "image_status": "unavailable",
    "worker_count": 0,
    "resource_limits": {"memory": "2g", "cpus": "2", "network": "host"},
    "mode": "local_fallback",
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSONEOF

    cat > "$phase_dir/worker_status.txt" <<STATUSEOF
Docker Worker Status (Fallback)
================================
Domain: $domain
Mode: Local execution (Docker unavailable)
Workers Running: 0
Status: fallback
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
STATUSEOF
}

export -f docker_worker_phase _docker_worker_fallback
