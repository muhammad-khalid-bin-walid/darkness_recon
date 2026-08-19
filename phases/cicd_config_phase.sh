#!/usr/bin/env bash
# cicd_config_phase.sh - CI/CD pipeline config pull, GitHub Actions/GitLab CI
# secrets, exposed build artifacts.

cicd_config_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "cicd_config_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/cicd_config"

    local results=0
    local vulns_file="$output_dir/cicd_config/cicd_vulns.txt"
    local configs_file="$output_dir/cicd_config/pipeline_configs.txt"
    local findings_file="$output_dir/cicd_config/findings.json"

    log "INFO" "Starting CI/CD config phase for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # --- GitHub Actions / GitLab CI file discovery ---
    local ci_paths=(
        "/.github/workflows/"
        "/.github/workflows/main.yml"
        "/.github/workflows/ci.yml"
        "/.github/workflows/deploy.yml"
        "/.github/workflows/build.yml"
        "/.gitlab-ci.yml"
        "/.gitlab-ci.yml/"
        "/Jenkinsfile"
        "/Jenkinsfile/"
        "/.circleci/config.yml"
        "/.circleci/"
        "/.travis.yml"
        "/azure-pipelines.yml"
        "/azure-pipelines.yml/"
        "/bitbucket-pipelines.yml"
        "/cloudbuild.yaml"
        "/cloudbuild.json"
        "/buildspec.yml"
        "/taskcat.yml"
    )

    for cipath in "${ci_paths[@]}"; do
        local ci_url="https://${domain}${cipath}"
        local ci_status ci_body
        ci_body=$(curl -s -m 10 -w "\n%{http_code}" "$ci_url" 2>/dev/null || true)
        ci_status=$(echo "$ci_body" | tail -1)

        if [[ "$ci_status" == "200" ]]; then
            local content
            content=$(echo "$ci_body" | head -n -1)
            log "INFO" "CI config found: $ci_url"

            echo "[CI-CONFIG] $ci_url - Accessible (HTTP 200)" >> "$configs_file"
            ((results++)) || true

            write_endpoint "{\"url\":\"$ci_url\",\"method\":\"GET\",\"status\":200,\"phase\":\"cicd_config\"}" \
                "$findings_file" 2>/dev/null || true

            # --- Scan for secrets in CI configs ---
            local secret_patterns=(
                'password\s*[:=]\s*["\x27][^"\x27]+["\x27]'
                'secret\s*[:=]\s*["\x27][^"\x27]+["\x27]'
                'token\s*[:=]\s*["\x27][^"\x27]+["\x27]'
                'api_key\s*[:=]\s*["\x27][^"\x27]+["\x27]'
                'access_key\s*[:=]\s*["\x27][^"\x27]+["\x27]'
                'AWS_ACCESS_KEY_ID\s*[:=]\s*["\x27][^"\x27]+["\x27]'
                'AWS_SECRET_ACCESS_KEY\s*[:=]\s*["\x27][^"\x27]+["\x27]'
                'PRIVATE_KEY\s*[:=]\s*["\x27][^"\x27]+["\x27]'
                'NPM_TOKEN\s*[:=]\s*["\x27][^"\x27]+["\x27]'
                'DOCKER_PASSWORD\s*[:=]\s*["\x27][^"\x27]+["\x27]'
                'ghp_[A-Za-z0-9]{36}'
                'sk-[A-Za-z0-9]{32,}'
                'AKIA[0-9A-Z]{16}'
            )

            for pattern in "${secret_patterns[@]}"; do
                local matches
                matches=$(echo "$content" | grep -oiE "$pattern" 2>/dev/null || true)
                if [[ -n "$matches" ]]; then
                    echo "[CI-SECRET] $ci_url - Secret found: $matches" >> "$vulns_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"cicd_secret_exposed\",\"url\":\"$ci_url\",\"severity\":\"CRITICAL\",\"evidence\":\"Secret found in CI/CD configuration\"}" \
                        "$findings_file" 2>/dev/null || true
                fi
            done

            # --- Check for exposed environment variables ---
            local env_patterns=(
                'secrets\.'
                'env\.'
                '\$\{secrets\.'
                '\$\{\{ secrets\.'
                'environment:'
            )

            for epat in "${env_patterns[@]}"; do
                local env_matches
                env_matches=$(echo "$content" | grep -c "$epat" 2>/dev/null || echo "0")
                if [[ "$env_matches" -gt 0 ]]; then
                    echo "[CI-ENV-REFERENCE] $ci_url - Environment/secrets references found ($env_matches)" >> "$configs_file"
                fi
            done

            # --- Check for unsafe CI practices ---
            echo "$content" | grep -qiE '(curl.*\|.*bash|wget.*\|.*sh|eval\s|sudo\s)' 2>/dev/null && {
                echo "[CI-UNSAFE] $ci_url - Unsafe CI practice (curl|bash or eval)" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"cicd_unsafe_practice\",\"url\":\"$ci_url\",\"severity\":\"HIGH\",\"evidence\":\"Unsafe practice: curl|bash or eval in pipeline\"}" \
                    "$findings_file" 2>/dev/null || true
            } || true
        fi
    done

    # --- Check for exposed build artifacts ---
    local artifact_paths=(
        "/build/"
        "/dist/"
        "/target/"
        "/out/"
        "/output/"
        "/release/"
        "/deploy/"
        "/.buildkite/"
        "/artifacts/"
        "/packages/"
    )

    for apath in "${artifact_paths[@]}"; do
        local art_url="https://${domain}${apath}"
        local art_status
        art_status=$(curl -s -o /dev/null -w "%{http_code}" -m 10 "$art_url" 2>/dev/null || echo "000")

        if [[ "$art_status" == "200" ]]; then
            local art_body
            art_body=$(curl -s -m 10 "$art_url" 2>/dev/null || true)

            # Check for directory listing
            echo "$art_body" | grep -qiE '(index of|directory listing|parent directory|\[DIR\])' 2>/dev/null && {
                echo "[ARTIFACT-DIR-LISTING] $art_url - Directory listing enabled on build artifacts" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"cicd_artifact_listing\",\"url\":\"$art_url\",\"severity\":\"HIGH\",\"evidence\":\"Directory listing enabled on build artifacts\"}" \
                    "$findings_file" 2>/dev/null || true
            } || true

            # Check for common artifact files
            local art_files=("build.log" "output.log" "deploy.log" ".env" "config.json" "settings.json" "credentials.json")
            for afile in "${art_files[@]}"; do
                local af_status
                af_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "${art_url}${afile}" 2>/dev/null || echo "000")
                if [[ "$af_status" == "200" ]]; then
                    echo "[ARTIFACT-EXPOSED] ${art_url}${afile} - Build artifact accessible" >> "$vulns_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"cicd_artifact_exposed\",\"url\":\"${art_url}${afile}\",\"severity\":\"MEDIUM\",\"evidence\":\"Build artifact file publicly accessible\"}" \
                        "$findings_file" 2>/dev/null || true
                fi
            done
        fi
    done

    # --- Check common CI/CD dashboard endpoints ---
    local dash_paths=(
        "/jenkins/"
        "/jenkins/login"
        "/ci/"
        "/pipeline/"
        "/builds/"
        "/deployments/"
        "/actions/"
        "/runs/"
    )

    for dpath in "${dash_paths[@]}"; do
        local d_status
        d_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://${domain}${dpath}" 2>/dev/null || echo "000")

        if [[ "$d_status" == "200" || "$d_status" == "302" ]]; then
            echo "[CI-DASHBOARD] https://${domain}${dpath} - CI dashboard accessible (HTTP $d_status)" >> "$configs_file"
            ((results++)) || true
        fi
    done

    # Write count
    echo "$results" > "$output_dir/cicd_config/count.txt"

    py_log "INFO" "cicd_config_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "CI/CD config phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    cicd_config_phase "$@"
fi
