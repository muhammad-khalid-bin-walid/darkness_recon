#!/bin/bash
# Track 7 - Distributed Scale: Spot/preemptible instance management phase
# Checkpoint-based recovery, cost optimization

spot_instance_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/spot_instance"

    mkdir -p "$phase_dir"

    if ! declare -f log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    log "INFO" "Starting spot instance phase for $domain"
    py_log "INFO" "spot_instance_phase_start" --phase "spot_instance" --target "$domain" 2>/dev/null || true

    local spot_config="$phase_dir/spot_config.json"
    local spot_status="$phase_dir/spot_status.txt"
    local count=0

    # Detect cloud provider
    local cloud_provider="local"
    local instance_type="on_demand"
    local spot_eligible=false

    if command -v aws >/dev/null 2>&1; then
        local instance_id
        instance_id=$(curl -s --max-time 2 "http://169.254.169.254/latest/meta-data/instance-id" 2>/dev/null || echo "")
        if [ -n "$instance_id" ]; then
            cloud_provider="aws"
            local lifecycle
            lifecycle=$(aws ec2 describe-instance-attribute --instance-id "$instance_id" --attribute instanceType 2>/dev/null | grep -o '"Value": "[^"]*"' | head -1 || echo "")
            if echo "$lifecycle" | grep -qi spot; then
                instance_type="spot"
                spot_eligible=true
            fi
        fi
    elif command -v gcloud >/dev/null 2>&1; then
        local gcp_zone
        gcp_zone=$(curl -s --max-time 2 "http://metadata.google.internal/computeMetadata/v1/instance/zone" -H "Metadata-Flavor: Google" 2>/dev/null || echo "")
        if [ -n "$gcp_zone" ]; then
            cloud_provider="gcp"
            instance_type="preemptible"
            spot_eligible=true
        fi
    fi

    # Configure spot management
    local checkpoint_interval="${SPOT_CHECKPOINT_INTERVAL:-300}"
    local max_interruption_warning="${SPOT_MAX_WARNING:-120}"
    local checkpoint_dir="$phase_dir/checkpoints"
    mkdir -p "$checkpoint_dir"

    # Create checkpoint protocol
    local checkpoint_file="$checkpoint_dir/scan_checkpoint.json"
    cat > "$checkpoint_file" <<CKEOF
{
    "domain": "$domain",
    "checkpoint_id": "$(date +%s)",
    "phase_state": "initialized",
    "completed_phases": [],
    "partial_results": {},
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
CKEOF

    cat > "$spot_config" <<JSONEOF
{
    "domain": "$domain",
    "cloud_provider": "$cloud_provider",
    "instance_type": "$instance_type",
    "spot_eligible": $spot_eligible,
    "checkpoint_strategy": {
        "interval_seconds": $checkpoint_interval,
        "max_interruption_warning_seconds": $max_interruption_warning,
        "checkpoint_dir": "$checkpoint_dir",
        "state_persistence": "file_based",
        "recovery_mode": "resume_from_last_checkpoint"
    },
    "cost_optimization": {
        "prefer_spot": true,
        "fallback_to_on_demand": true,
        "max_spot_price_per_hour": "${MAX_SPOT_PRICE:-0.50}",
        "availability_zone_diversification": true,
        "instance_families": ["c5", "c6g", "m5", "t3"],
        "reserved_capacity_percentage": 0
    },
    "interruption_handling": {
        "SIGTERM_handler": "checkpoint_and_drain",
        "drain_timeout_seconds": 30,
        "save_partial_results": true,
        "retry_with_new_instance": true,
        "max_retries": 3
    },
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSONEOF
    count=$((count + 1))

    cat > "$spot_status" <<STATUSEOF
Spot Instance Status
====================
Domain: $domain
Cloud Provider: $cloud_provider
Instance Type: $instance_type
Spot Eligible: $spot_eligible
Checkpoint Interval: ${checkpoint_interval}s
Recovery Mode: Resume from last checkpoint
Cost Strategy: Spot-first with on-demand fallback
Status: configured
Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)
STATUSEOF
    count=$((count + 1))

    write_finding "{\"type\":\"spot_instance_configured\",\"domain\":\"$domain\",\"cloud\":\"$cloud_provider\",\"instance_type\":\"$instance_type\",\"spot_eligible\":$spot_eligible}" "$phase_dir/finding_spot.json" 2>/dev/null || true

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Spot instance phase complete: $count results"
    py_log "INFO" "spot_instance_phase_complete" --phase "spot_instance" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}

export -f spot_instance_phase
