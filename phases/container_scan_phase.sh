#!/usr/bin/env bash
# container_scan_phase.sh - Container/image exposure checks, Docker registry
# misconfiguration, image vulnerabilities.

container_scan_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "container_scan_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/container_scan"

    local results=0
    local vulns_file="$output_dir/container_scan/container_vulns.txt"
    local images_file="$output_dir/container_scan/exposed_images.txt"
    local findings_file="$output_dir/container_scan/findings.json"

    log "INFO" "Starting container scan phase for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # --- Discover Docker Registry endpoints ---
    local registry_paths=(
        "/v2/"
        "/v2/_catalog"
        "/v2/_catalog?n=100"
        "/registry/"
        "/docker/"
        "/_catalog"
    )

    local registry_hosts=(
        "${domain}"
        "registry.${domain}"
        "docker.${domain}"
        "hub.${domain}"
        "containers.${domain}"
        "${domain}:5000"
        "${domain}:443"
    )

    for reg_host in "${registry_hosts[@]}"; do
        for rpath in "${registry_paths[@]}"; do
            local reg_url="https://${reg_host}${rpath}"
            local reg_status reg_body
            reg_body=$(curl -s -m 10 -w "\n%{http_code}" "$reg_url" 2>/dev/null || true)
            reg_status=$(echo "$reg_body" | tail -1)

            if [[ "$reg_status" == "200" ]]; then
                local content
                content=$(echo "$reg_body" | head -n -1)
                log "INFO" "Docker registry found: $reg_url"

                echo "[REGISTRY-ENDPOINT] $reg_url - Docker registry accessible (HTTP 200)" >> "$vulns_file"
                ((results++)) || true

                write_endpoint "{\"url\":\"$reg_url\",\"method\":\"GET\",\"status\":200,\"phase\":\"container_scan\"}" \
                    "$findings_file" 2>/dev/null || true

                # Parse catalog
                if echo "$content" | grep -q 'repositories' 2>/dev/null; then
                    local repos
                    repos=$(echo "$content" | grep -oE '"[^"]*"' | tr -d '"' | grep -v 'repositories' | head -20 || true)

                    while IFS= read -r repo; do
                        [[ -z "$repo" ]] && continue
                        echo "[REGISTRY-REPO] $reg_url - Repository: $repo" >> "$images_file"
                        ((results++)) || true

                        # Check tags for each repository
                        local tags_url="https://${reg_host}/v2/${repo}/tags/list"
                        local tags_status tags_body
                        tags_body=$(curl -s -m 10 -w "\n%{http_code}" "$tags_url" 2>/dev/null || true)
                        tags_status=$(echo "$tags_body" | tail -1)

                        if [[ "$tags_status" == "200" ]]; then
                            local tags
                            tags=$(echo "$tags_body" | head -n -1 | grep -oE '"[a-zA-Z0-9._\-:]+"' | tr -d '"' | head -10 || true)
                            while IFS= read -r tag; do
                                [[ -z "$tag" ]] && continue
                                echo "[REGISTRY-TAG] $reg_url/$repo:$tag" >> "$images_file"

                                # Check image manifest for vulnerabilities
                                local manifest_url="https://${reg_host}/v2/${repo}/manifests/${tag}"
                                local manifest_body
                                manifest_body=$(curl -s -m 10 -H "Accept: application/vnd.docker.distribution.manifest.v2+json" "$manifest_url" 2>/dev/null || true)

                                if [[ -n "$manifest_body" ]]; then
                                    # Check for 'latest' tag usage
                                    [[ "$tag" == "latest" ]] && {
                                        echo "[LATEST-TAG] $reg_url/$repo:latest - Uses 'latest' tag" >> "$vulns_file"
                                        ((results++)) || true

                                        write_finding "{\"type\":\"container_latest_tag\",\"image\":\"${repo}:${tag}\",\"severity\":\"LOW\",\"evidence\":\"Image uses 'latest' tag\"}" \
                                            "$findings_file" 2>/dev/null || true
                                    } || true

                                    # Check for large layer count (potential bloat)
                                    local layer_count
                                    layer_count=$(echo "$manifest_body" | grep -c 'mediaType' 2>/dev/null || echo "0")
                                    if [[ "$layer_count" -gt 30 ]]; then
                                        echo "[LAYER-BLOAT] $reg_url/$repo:$tag - High layer count: $layer_count" >> "$vulns_file"
                                        ((results++)) || true
                                    fi
                                fi
                            done <<< "$tags"
                        fi
                    done <<< "$repos"
                fi

                # Check for unauthenticated catalog access
                echo "[REGISTRY-NO-AUTH] $reg_url - Registry accessible without authentication" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"registry_no_auth\",\"url\":\"$reg_url\",\"severity\":\"HIGH\",\"evidence\":\"Docker registry accessible without authentication\"}" \
                    "$findings_file" 2>/dev/null || true
            fi
        done
    done

    # --- Check for exposed Dockerfiles ---
    local dockerfile_paths=(
        "/Dockerfile"
        "/docker/Dockerfile"
        "/.docker/Dockerfile"
        "/build/Dockerfile"
        "/deploy/Dockerfile"
        "/Dockerfile.dev"
        "/Dockerfile.prod"
        "/Dockerfile.staging"
        "/docker-compose.yml"
        "/docker-compose.yaml"
        "/docker-compose.override.yml"
        "/.dockerignore"
    )

    for dpath in "${dockerfile_paths[@]}"; do
        local df_status
        df_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://${domain}${dpath}" 2>/dev/null || echo "000")

        if [[ "$df_status" == "200" ]]; then
            echo "[DOCKERFILE-EXPOSED] https://${domain}${dpath} - Dockerfile accessible" >> "$vulns_file"
            ((results++)) || true

            local df_body
            df_body=$(curl -s -m 5 "https://${domain}${dpath}" 2>/dev/null || true)

            # Check for secrets in Dockerfile
            echo "$df_body" | grep -qiE '(ENV.*PASSWORD|ENV.*SECRET|ENV.*KEY|COPY.*\.env|COPY.*credentials)' 2>/dev/null && {
                echo "[DOCKERFILE-SECRET] https://${domain}${dpath} - Secret found in Dockerfile" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"dockerfile_secret\",\"url\":\"https://${domain}${dpath}\",\"severity\":\"HIGH\",\"evidence\":\"Secret found in Dockerfile\"}" \
                    "$findings_file" 2>/dev/null || true
            } || true

            # Check for root user
            echo "$df_body" | grep -qiE '(USER root|RUN.*sudo|FROM.*root)' 2>/dev/null && {
                echo "[DOCKERFILE-ROOT] https://${domain}${dpath} - Running as root" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"dockerfile_root_user\",\"url\":\"https://${domain}${dpath}\",\"severity\":\"MEDIUM\",\"evidence\":\"Container configured to run as root\"}" \
                    "$findings_file" 2>/dev/null || true
            } || true
        fi
    done

    # --- Check for Kubernetes container registries ---
    local k8s_reg_paths=(
        "/api/v1/namespaces/default/pods"
        "/api/v1/namespaces/kube-system/pods"
        "/apis/apps/v1/namespaces/default/deployments"
    )

    for kpath in "${k8s_reg_paths[@]}"; do
        local k8s_status
        k8s_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://${domain}${kpath}" 2>/dev/null || echo "000")

        if [[ "$k8s_status" == "200" ]]; then
            echo "[K8S-API-EXPOSED] https://${domain}${kpath} - Kubernetes API accessible" >> "$vulns_file"
            ((results++)) || true

            write_finding "{\"type\":\"k8s_api_exposed\",\"url\":\"https://${domain}${kpath}\",\"severity\":\"CRITICAL\",\"evidence\":\"Kubernetes API server accessible without auth\"}" \
                "$findings_file" 2>/dev/null || true
        fi
    done

    # Write count
    echo "$results" > "$output_dir/container_scan/count.txt"

    py_log "INFO" "container_scan_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Container scan phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    container_scan_phase "$@"
fi
