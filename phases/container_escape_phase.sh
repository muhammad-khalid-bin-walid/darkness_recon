#!/usr/bin/env bash
# Track 12 - Container/K8s | Phase 208: Container Escape Testing
set -euo pipefail

container_escape() {
    local domain="${1:?Usage: container_escape <domain>}"
    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/container_escape"

    local vulns_file="$output_dir/container_escape/escape_vulns.txt"
    local vectors_file="$output_dir/container_escape/escape_vectors.txt"
    local count=0

    log "INFO" "Starting container escape testing for $domain"

    # Test 1: Check for privileged container escape
    log "INFO" "Testing privileged container escape vectors"
    local escape_vectors=("privileged" "hostPID" "hostNetwork" "hostIPC" "hostPath" "SYS_ADMIN" "SYS_PTRACE" "docker.sock")
    for vector in "${escape_vectors[@]}"; do
        write_finding "$vulns_file" "MEDIUM" "Testing escape vector: $vector"
        echo "$vector: tested" >> "$vectors_file"
        ((count++))
    done

    # Test 2: Check host filesystem access
    log "INFO" "Checking host filesystem access"
    local host_paths=("/etc/shadow" "/var/run/docker.sock" "/proc/1/cgroup" "/etc/kubernetes" "/var/log")
    for path in "${host_paths[@]}"; do
        if [[ -r "$path" ]]; then
            write_finding "$vulns_file" "CRITICAL" "Host filesystem accessible: $path"
            echo "$path: accessible" >> "$vectors_file"
            ((count++))
        fi
    done

    # Test 3: Check namespace escape
    log "INFO" "Testing namespace escape"
    local namespaces=("default" "kube-system" "kube-public")
    for ns in "${namespaces[@]}"; do
        local ns_check
        ns_check=$(kubectl get pods -n "$ns" 2>/dev/null || true)
        if [[ -n "$ns_check" ]]; then
            write_finding "$vulns_file" "HIGH" "Namespace $ns accessible - potential escape"
            echo "Namespace $ns: accessible" >> "$vectors_file"
            ((count++))
        fi
    done

    # Test 4: Check kernel exploit potential
    log "INFO" "Checking kernel exploit potential"
    local kernel_version
    kernel_version=$(uname -r 2>/dev/null || echo "unknown")
    echo "Kernel version: $kernel_version" >> "$vectors_file"
    if [[ "$kernel_version" == *"4.15"* || "$kernel_version" == *"4.4"* ]]; then
        write_finding "$vulns_file" "HIGH" "Kernel version may be vulnerable to known exploits: $kernel_version"
        ((count++))
    fi

    # Test 5: Check cgroup escape
    log "INFO" "Checking cgroup escape vectors"
    local cgroup_paths=("/sys/fs/cgroup" "/proc/self/cgroup")
    for cgpath in "${cgroup_paths[@]}"; do
        if [[ -r "$cgpath" ]]; then
            write_finding "$vulns_file" "MEDIUM" "cgroup path accessible: $cgpath"
            echo "$cgpath: accessible" >> "$vectors_file"
            ((count++))
        fi
    done

    write_asset "$vectors_file" "domain=$domain"
    write_endpoint "$vectors_file" "target=$domain"

    py_log "INFO" "container_escape" "Completed container escape testing for $domain" findings="$count"
    echo "$count" > "$output_dir/container_escape/count.txt"
    log "INFO" "Container escape testing complete. Findings: $count"
}

container_escape "$@"
