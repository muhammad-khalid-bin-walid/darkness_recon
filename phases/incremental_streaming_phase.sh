#!/bin/bash
# Track 7 - Distributed Scale: Incremental streaming results phase
# Partial output delivery, resumable scans, checkpoint support

incremental_streaming_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/incremental_streaming"

    mkdir -p "$phase_dir"

    if ! declare -f log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    log "INFO" "Starting incremental streaming phase for $domain"
    py_log "INFO" "incremental_streaming_phase_start" --phase "incremental_streaming" --target "$domain" 2>/dev/null || true

    local stream_config="$phase_dir/stream_config.json"
    local incremental_results="$phase_dir/incremental_results.json"
    local count=0

    # Detect existing scan state for resume
    local resume_available=false
    local checkpoint_file="$output_dir/.checkpoint"
    local last_phase="none"
    local completed_phases=0
    local total_phases=15

    if [ -f "$checkpoint_file" ]; then
        resume_available=true
        last_phase=$(grep -oP 'last_phase=\K.*' "$checkpoint_file" 2>/dev/null || echo "unknown")
        completed_phases=$(grep -oP 'completed=\K[0-9]+' "$checkpoint_file" 2>/dev/null || echo 0)
        log "INFO" "Resume available from phase: $last_phase ($completed_phases/$total_phases completed)"
    fi

    # Configure streaming
    local stream_mode="${STREAM_MODE:-chunked}"
    local chunk_size="${STREAM_CHUNK_SIZE:-1000}"
    local flush_interval="${STREAM_FLUSH_INTERVAL:-5}"
    local compression="${STREAM_COMPRESSION:-gzip}"

    cat > "$stream_config" <<JSONEOF
{
    "domain": "$domain",
    "stream_mode": "$stream_mode",
    "chunk_size": $chunk_size,
    "flush_interval_seconds": $flush_interval,
    "compression": "$compression",
    "resume": {
        "available": $resume_available,
        "last_phase": "$last_phase",
        "completed_phases": $completed_phases,
        "total_phases": $total_phases,
        "checkpoint_file": "$checkpoint_file"
    },
    "delivery": {
        "partial_results": true,
        "real_time_streaming": true,
        "webhook_callback": "${STREAM_WEBHOOK:-}",
        "output_format": "jsonl"
    },
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSONEOF
    count=$((count + 1))

    # Collect incremental results from existing phases
    local result_files=0
    local partial_data="[]"

    if [ -d "$output_dir" ]; then
        # Find all finding files from completed phases
        local finding_files
        finding_files=$(find "$output_dir" -name "finding_*.json" -type f 2>/dev/null | head -100)

        if [ -n "$finding_files" ]; then
            result_files=$(echo "$finding_files" | wc -l)
            log "INFO" "Found $result_files partial result files for streaming"

            # Build incremental results manifest
            echo "$finding_files" | while read -r ffile; do
                local phase_name
                phase_name=$(basename "$(dirname "$ffile")")
                echo "{\"phase\":\"$phase_name\",\"file\":\"$ffile\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" 2>/dev/null || true
            done > "$phase_dir/results_manifest.jsonl"
        fi
    fi

    # Create checkpoint for resumability
    cat > "$checkpoint_file" <<CHECKEOF
domain=$domain
last_phase=incremental_streaming
completed=$completed_phases
total=$total_phases
timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CHECKEOF

    cat > "$incremental_results" <<JSONEOF
{
    "domain": "$domain",
    "result_files_found": $result_files,
    "resume_checkpoint": "$checkpoint_file",
    "stream_mode": "$stream_mode",
    "status": "streaming_ready",
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSONEOF
    count=$((count + 1))

    write_finding "{\"type\":\"incremental_streaming_configured\",\"domain\":\"$domain\",\"resume_available\":$resume_available,\"result_files\":$result_files,\"stream_mode\":\"$stream_mode\"}" "$phase_dir/finding_stream.json" 2>/dev/null || true

    echo "$count" > "$phase_dir/count.txt"
    log "INFO" "Incremental streaming phase complete: $count results"
    py_log "INFO" "incremental_streaming_phase_complete" --phase "incremental_streaming" --target "$domain" --extra "{\"count\":$count}" 2>/dev/null || true
}

export -f incremental_streaming_phase
