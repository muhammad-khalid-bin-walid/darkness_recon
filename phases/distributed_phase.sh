#!/bin/bash
# Distributed/cloud scaling phase - Production Ready
# Supports Kubernetes, Docker, and cloud-native distributed scanning

distributed_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local distributed_dir="$output_dir/distributed"
    local scan_mode="${DISTRIBUTED_MODE:-docker}"

    mkdir -p "$distributed_dir"

    log "INFO" "Starting distributed scanning for $domain (mode: $scan_mode)"

    # Pre-flight checks
    if ! _distributed_preflight_checks "$scan_mode"; then
        log "WARN" "Distributed pre-flight checks failed, falling back to local scanning"
        _distributed_local_fallback "$domain" "$distributed_dir"
        return 0
    fi

    case "$scan_mode" in
        kubernetes|k8s)
            _distributed_kubernetes_scan "$domain" "$distributed_dir"
            ;;
        docker)
            _distributed_docker_scan "$domain" "$distributed_dir"
            ;;
        local)
            _distributed_local_fallback "$domain" "$distributed_dir"
            ;;
        *)
            log "WARN" "Unknown distributed mode: $scan_mode, using local fallback"
            _distributed_local_fallback "$domain" "$distributed_dir"
            ;;
    esac

    # Aggregate results
    _distributed_aggregate_results "$distributed_dir"

    local dist_count
    dist_count=$(find "$distributed_dir" -name "*.txt" -o -name "*.json" 2>/dev/null | wc -l)
    
    phase_log "INFO" "Distributed scanning complete: $dist_count result files" "distributed" "$domain"

    # Write findings for distributed scan completion
    write_finding "{\"type\":\"distributed_scan_complete\",\"severity\":\"info\",\"mode\":\"$scan_mode\",\"result_files\":$dist_count,\"phase\":\"distributed\"}" \
        "$distributed_dir/findings.jsonl" 2>/dev/null || true

    echo "$dist_count" > "$distributed_dir/count.txt"
}

# Pre-flight checks for distributed scanning
_distributed_preflight_checks() {
    local mode="$1"

    # Check disk space (require at least 500MB)
    if ! check_disk_space 500; then
        log "ERROR" "Insufficient disk space for distributed scanning"
        return 1
    fi

    case "$mode" in
        kubernetes|k8s)
            if ! command -v kubectl >/dev/null 2>&1; then
                log "ERROR" "kubectl not found, cannot use Kubernetes mode"
                return 1
            fi
            if ! kubectl cluster-info >/dev/null 2>&1; then
                log "ERROR" "Kubernetes cluster not accessible"
                return 1
            fi
            ;;
        docker)
            if ! command -v docker >/dev/null 2>&1; then
                log "ERROR" "docker not found, cannot use Docker mode"
                return 1
            fi
            if ! docker info >/dev/null 2>&1; then
                log "ERROR" "Docker daemon not accessible"
                return 1
            fi
            ;;
    esac

    return 0
}

# Kubernetes distributed scan
_distributed_kubernetes_scan() {
    local domain="$1"
    local distributed_dir="$2"
    local namespace="${KUBERNETES_NAMESPACE:-dark-recon-framework}"
    local replicas="${DISTRIBUTED_WORKERS:-4}"

    log "INFO" "Running distributed scan via Kubernetes ($replicas workers)..."

    # Create namespace
    kubectl create namespace "$namespace" 2>/dev/null || true

    # Create configmap with scan configuration
    kubectl create configmap dark-recon-framework-config \
        --from-literal=domain="$domain" \
        --from-literal=timestamp="$TIMESTAMP" \
        --from-literal=threads="$THREADS" \
        --from-literal=rate_limit="$RATE_LIMIT" \
        --from-literal=output_path="/app/output" \
        --dry-run=client -o yaml | kubectl apply -n "$namespace" -f - 2>>"$LOGS_DIR/distributed.log" || true

    # Create persistent volume claim for results
    cat <<EOF | kubectl apply -n "$namespace" -f - 2>>"$LOGS_DIR/distributed.log" || true
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: dark-recon-framework-results
  namespace: $namespace
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 5Gi
EOF

    # Create worker jobs
    local job_failed=false
    for i in $(seq 1 "$replicas"); do
        log "INFO" "Creating Kubernetes worker job $i/$replicas..."

        cat <<JOBEOF | kubectl apply -n "$namespace" -f - 2>>"$LOGS_DIR/distributed.log" || { job_failed=true; break; }
apiVersion: batch/v1
kind: Job
metadata:
  name: dark-recon-worker-$i
  namespace: $namespace
spec:
  backoffLimit: 2
  template:
    spec:
      restartPolicy: Never
      containers:
      - name: worker
        image: ${DOCKER_IMAGE:-dark-recon-framework:latest}
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        env:
        - name: DOMAIN
          value: "$domain"
        - name: WORKER_ID
          value: "$i"
        - name: TOTAL_WORKERS
          value: "$replicas"
        - name: THREADS
          value: "$THREADS"
        - name: RATE_LIMIT
          value: "$RATE_LIMIT"
        volumeMounts:
        - name: output
          mountPath: /app/output
        - name: config
          mountPath: /app/config
      volumes:
      - name: output
        persistentVolumeClaim:
          claimName: dark-recon-framework-results
      - name: config
        configMap:
          name: dark-recon-framework-config
JOBEOF
    done

    if [ "$job_failed" = true ]; then
        log "ERROR" "Failed to create Kubernetes worker jobs"
        _distributed_local_fallback "$domain" "$distributed_dir"
        return 1
    fi

    # Wait for jobs to complete (with timeout)
    log "INFO" "Waiting for Kubernetes jobs to complete..."
    local timeout="${KUBERNETES_TIMEOUT:-600}"
    local completed=0

    for i in $(seq 1 "$replicas"); do
        if kubectl wait --for=condition=complete job/"dark-recon-worker-$i" -n "$namespace" --timeout="${timeout}s" 2>/dev/null; then
            completed=$((completed + 1))
        else
            log "WARN" "Worker $i did not complete within timeout"
        fi
    done

    log "INFO" "$completed/$replicas workers completed successfully"

    # Copy results from PVC
    log "INFO" "Collecting results from Kubernetes..."
    local collector_pod="dark-recon-collector-$(date +%s)"

    kubectl run "$collector_pod" --image=busybox --restart=Never -n "$namespace" \
        --overrides='{"spec":{"containers":[{"name":"collector","image":"busybox","command":["sleep","300"],"volumeMounts":[{"name":"output","mountPath":"/app/output"]}],"volumes":[{"name":"output","persistentVolumeClaim":{"claimName":"dark-recon-framework-results"}}]}}' \
        2>>"$LOGS_DIR/distributed.log" || true

    sleep 5
    kubectl cp "$namespace/$collector_pod:/app/output" "$distributed_dir/results" 2>>"$LOGS_DIR/distributed.log" || true

    # Cleanup
    kubectl delete job -l "app=dark-recon-worker" -n "$namespace" 2>/dev/null || true
    kubectl delete pod "$collector_pod" -n "$namespace" 2>/dev/null || true

    log "INFO" "Kubernetes distributed scan completed"
}

# Docker distributed scan
_distributed_docker_scan() {
    local domain="$1"
    local distributed_dir="$2"
    local replicas="${DISTRIBUTED_WORKERS:-4}"

    log "INFO" "Running distributed scan via Docker ($replicas workers)..."

    # Check if Docker image exists, build if needed
    if ! docker image inspect "${DOCKER_IMAGE:-dark-recon-framework:latest}" >/dev/null 2>&1; then
        log "WARN" "Docker image not found, attempting to build..."
        if [ -f "$SCRIPT_DIR/../Dockerfile" ]; then
            docker build -t "${DOCKER_IMAGE:-dark-recon-framework:latest}" "$SCRIPT_DIR/.." 2>>"$LOGS_DIR/docker_build.log" || {
                log "ERROR" "Failed to build Docker image, using local fallback"
                _distributed_local_fallback "$domain" "$distributed_dir"
                return 1
            }
        else
            log "WARN" "No Dockerfile found, using local fallback"
            _distributed_local_fallback "$domain" "$distributed_dir"
            return 0
        fi
    fi

    # Run parallel Docker containers
    local container_ids=()
    local docker_failed=false

    for i in $(seq 1 "$replicas"); do
        local worker_output="$distributed_dir/worker_$i"
        mkdir -p "$worker_output"

        log "INFO" "Starting Docker worker $i/$replicas..."

        docker run --rm \
            -v "$worker_output:/app/output" \
            -e "DOMAIN=$domain" \
            -e "WORKER_ID=$i" \
            -e "TOTAL_WORKERS=$replicas" \
            -e "THREADS=$THREADS" \
            -e "RATE_LIMIT=$RATE_LIMIT" \
            -e "TIMEOUT=$TIMEOUT" \
            --memory="2g" \
            --cpus="2" \
            --network=host \
            "${DOCKER_IMAGE:-dark-recon-framework:latest}" \
            /bin/bash -c "./dark_recon_framework.sh $domain --fast --quiet" \
            2>>"$LOGS_DIR/docker_worker_$i.log" &

        container_ids+=($!)

        # Limit concurrent container starts
        if [ $((i % 4)) -eq 0 ]; then
            sleep 2
        fi
    done

    # Wait for all containers to complete
    log "INFO" "Waiting for $replicas Docker workers to complete..."
    local completed=0
    for pid in "${container_ids[@]}"; do
        if wait "$pid" 2>/dev/null; then
            completed=$((completed + 1))
        fi
    done

    log "INFO" "$completed/$replicas Docker workers completed"

    # Merge results from all workers
    for i in $(seq 1 "$replicas"); do
        local worker_output="$distributed_dir/worker_$i"
        if [ -d "$worker_output" ]; then
            cp -r "$worker_output"/* "$distributed_dir/results/" 2>/dev/null || true
        fi
    done

    log "INFO" "Docker distributed scan completed"
}

# Local fallback when distributed infrastructure is unavailable
_distributed_local_fallback() {
    local domain="$1"
    local distributed_dir="$2"

    log "INFO" "Running local fallback scan for $domain"

    local fallback_output="$distributed_dir/local_fallback"
    mkdir -p "$fallback_output"

    # Run essential phases locally
    if [ -f "$(dirname "$0")/subdomain_phase.sh" ]; then
        source "$(dirname "$0")/subdomain_phase.sh"
        subdomain_phase "$domain"
    fi

    if [ -f "$(dirname "$0")/live_phase.sh" ]; then
        source "$(dirname "$0")/live_phase.sh"
        live_phase "$domain"
    fi

    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$fallback_output/completed.txt"
    log "INFO" "Local fallback scan completed"
}

# Aggregate results from all distributed workers
_distributed_aggregate_results() {
    local distributed_dir="$1"
    local results_dir="$distributed_dir/results"
    local aggregated="$distributed_dir/aggregated"

    mkdir -p "$aggregated"

    log "INFO" "Aggregating distributed scan results..."

    # Find and merge all text files
    find "$distributed_dir" -name "*.txt" -type f 2>/dev/null | while read -r txt_file; do
        local basename
        basename=$(basename "$txt_file")
        cat "$txt_file" >> "$aggregated/$basename.merged" 2>/dev/null || true
    done

    # Deduplicate merged files
    for merged_file in "$aggregated"/*.merged; do
        [ -f "$merged_file" ] || continue
        local deduped_file="${merged_file%.merged}.deduped"
        sort -u "$merged_file" > "$deduped_file" 2>/dev/null || true
    done

    # Aggregate JSON results
    local json_results=()
    find "$distributed_dir" -name "*.json" -type f 2>/dev/null | while read -r json_file; do
        json_results+=("$json_file")
    done

    if [ ${#json_results[@]} -gt 0 ]; then
        log "INFO" "Found ${#json_results[@]} JSON result files to aggregate"
    fi

    log "INFO" "Results aggregation completed"

    py_log "INFO" "distributed_phase" "Completed for $domain"
}

# Export distributed phase functions
export -f distributed_phase _distributed_preflight_checks _distributed_kubernetes_scan _distributed_docker_scan _distributed_local_fallback _distributed_aggregate_results
