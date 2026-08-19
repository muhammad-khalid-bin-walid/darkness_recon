#!/bin/bash
# Track 16 - Secrets Deep | Phase 248: CI/CD Secret Detection
# Pipeline credential exposure, build log leaks

secrets_cicd_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "secrets_cicd_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/secrets_cicd"
    mkdir -p "$phase_dir"

    log "INFO" "Starting secrets_cicd_phase for $domain"

    local cicd_file="$phase_dir/cicd_secrets.txt"
    local pipeline_file="$phase_dir/pipeline_leaks.txt"
    local count=0

    # --- CI/CD configuration file paths ---
    log "INFO" "Scanning for exposed CI/CD configuration files..."
    local cicd_paths=(
        "/.github/workflows"
        "/.github/workflows/main.yml"
        "/.github/workflows/ci.yml"
        "/.github/workflows/deploy.yml"
        "/.gitlab-ci.yml"
        "/.gitlab-ci.yaml"
        "/Jenkinsfile"
        "/jenkins"
        "/.travis.yml"
        "/.circleci/config.yml"
        "/azure-pipelines.yml"
        "/azure-pipelines.yaml"
        "/bitbucket-pipelines.yml"
        "/.drone.yml"
        "/cloudbuild.yaml"
        "/cloudbuild.yml"
        "/buildkite.yml"
        "/codebuild.yml"
        "/appveyor.yml"
        "/.github/actions"
        "/Dockerfile"
        "/docker-compose.yml"
        "/docker-compose.yaml"
        "/.dockerignore"
        "/Procfile"
        "/appveyor.yml"
        "/buildspec.yml"
        "/taskdef.json"
        "/buildspec.json"
        "/Makefile"
        "/build.gradle"
        "/pom.xml"
        "/Gemfile"
        "/Rakefile"
    )

    for path in "${cicd_paths[@]}"; do
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$http_code" == "200" ]]; then
            local content
            content=$(curl -s -m 5 "https://$domain$path" 2>/dev/null) || true
            if echo "$content" | grep -qiE '(secret|password|token|key|credential|env|aws|docker)'; then
                echo "[CICD_EXPOSED] https://$domain$path contains potential secrets" >> "$cicd_file"
                ((count++)) || true
            fi
        fi
    done

    # --- Scan GitHub Actions for secrets ---
    log "INFO" "Scanning GitHub Actions workflows..."
    local repos_file="$phase_dir/discovered_repos.txt"
    curl -s "https://api.github.com/search/repositories?q=domain:$domain+org:$domain" 2>/dev/null | \
        jq -r '.items[]? | .full_name' 2>/dev/null > "$repos_file" || true

    while IFS= read -r repo_name; do
        [[ -z "$repo_name" ]] && continue

        # Fetch workflow files
        local workflows_resp
        workflows_resp=$(curl -s "https://api.github.com/repos/$repo_name/contents/.github/workflows" 2>/dev/null) || true
        echo "$workflows_resp" | jq -r '.[]? | .download_url' 2>/dev/null | while IFS= read -r wf_url; do
            [[ -z "$wf_url" ]] && continue
            local wf_content
            wf_content=$(curl -s -m 10 "$wf_url" 2>/dev/null) || true

            # Check for hardcoded secrets
            if echo "$wf_content" | grep -qiE 'secrets\.[A-Z_]+|password:|api_key:|token:|AWS_ACCESS_KEY|AWS_SECRET'; then
                echo "[GH_ACTIONS_SECRET] repo=$repo_name workflow=$wf_url" >> "$pipeline_file"
                ((count++)) || true
            fi

            # Check for dangerous secret handling
            if echo "$wf_content" | grep -qiE 'echo.*secret|print.*secret|printf.*secret|logging.*secret'; then
                echo "[SECRET_IN_LOGS] repo=$repo_name workflow=$wf_url (secret echoed in logs)" >> "$cicd_file"
                ((count++)) || true
            fi

            # Check for secrets passed to child workflows
            if echo "$wf_content" | grep -qiE 'uses:.*secret|input.*secret.*\$\{\{'; then
                echo "[SECRET_PROPAGATION] repo=$repo_name workflow=$wf_url" >> "$pipeline_file"
                ((count++)) || true
            fi
        done

        # Check for exposed build logs
        local actions_resp
        actions_resp=$(curl -s "https://api.github.com/repos/$repo_name/actions/runs?per_page=5" 2>/dev/null) || true
        echo "$actions_resp" | jq -r '.workflow_runs[]? | .logs_url // empty' 2>/dev/null | while IFS= read -r log_url; do
            echo "[BUILD_LOG_AVAILABLE] repo=$repo_name log_url=$log_url" >> "$pipeline_file"
            ((count++)) || true
        done
    done < "$repos_file"

    # --- Check for exposed GitLab CI ---
    log "INFO" "Checking for exposed GitLab CI configurations..."
    curl -s "https://api.github.com/search/code?q=$domain+filename:.gitlab-ci.yml" 2>/dev/null | \
        jq -r '.items[]? | .repository.full_name + " " + .html_url' 2>/dev/null | while IFS= read -r result; do
            echo "[GITLAB_CI_EXPOSED] $result" >> "$cicd_file"
            ((count++)) || true
        done

    # --- Check for Terraform/cloud deployment configs ---
    log "INFO" "Checking for cloud deployment configuration exposure..."
    local deploy_paths=(
        "/terraform.tfvars"
        "/terraform.tfstate"
        "/.terraform"
        "/terraform"
        "/infrastructure"
        "/deploy"
        "/deployment"
        "/k8s"
        "/kubernetes"
        "/helm"
        "/charts"
    )

    for path in "${deploy_paths[@]}"; do
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://$domain$path" 2>/dev/null) || true
        if [[ "$code" == "200" ]]; then
            echo "[DEPLOY_CONFIG_EXPOSED] https://$domain$path" >> "$cicd_file"
            ((count++)) || true
        fi
    done

    # --- Write structured findings ---
    if [[ -f "$cicd_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "cicd_secret" "" "" "" || true
        done < "$cicd_file"
    fi

    if [[ -f "$pipeline_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "pipeline_leak" "" "" "" || true
        done < "$pipeline_file"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "secrets_cicd_phase" "domain=$domain findings=$count"
    log "INFO" "secrets_cicd_phase complete: $count findings"
    return 0
}

secrets_cicd_phase "$@"
