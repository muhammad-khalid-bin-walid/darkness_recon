#!/usr/bin/env bash
# serverless_phase.sh - Serverless function exposure, Lambda/Azure Functions/
# GCP Functions security.

serverless_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "serverless_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/serverless"

    local results=0
    local vulns_file="$output_dir/serverless/serverless_vulns.txt"
    local functions_file="$output_dir/serverless/exposed_functions.txt"
    local findings_file="$output_dir/serverless/findings.json"

    log "INFO" "Starting serverless phase for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # --- AWS Lambda function discovery ---
    local lambda_paths=(
        "/api/"
        "/api/v1/"
        "/api/v2/"
        "/rest/"
        "/function/"
        "/lambda/"
        "/prod/"
        "/dev/"
        "/stage/"
        "/production/"
        "/execute/"
        "/invoke/"
    )

    for lpath in "${lambda_paths[@]}"; do
        local l_url="https://${domain}${lpath}"
        local l_status l_body
        l_body=$(curl -s -m 10 -w "\n%{http_code}" "$l_url" 2>/dev/null || true)
        l_status=$(echo "$l_body" | tail -1)

        if [[ "$l_status" != "000" && "$l_status" != "404" ]]; then
            local content
            content=$(echo "$l_body" | head -n -1)

            echo "[FUNCTION-ENDPOINT] $l_url - HTTP $l_status" >> "$functions_file"
            ((results++)) || true

            write_endpoint "{\"url\":\"$l_url\",\"method\":\"GET\",\"status\":$l_status,\"phase\":\"serverless\"}" \
                "$findings_file" 2>/dev/null || true

            # Check for Lambda execution error messages
            echo "$content" | grep -qiE '(arn:aws:lambda|Function.*not found|RequestId|lambda-runtime|X-Amz-Function-Error)' 2>/dev/null && {
                echo "[LAMBDA-EXPOSED] $l_url - AWS Lambda function details exposed" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"lambda_details_exposed\",\"url\":\"$l_url\",\"severity\":\"MEDIUM\",\"evidence\":\"AWS Lambda execution details exposed in error response\"}" \
                    "$findings_file" 2>/dev/null || true
            } || true

            # Check for environment variable leakage
            echo "$content" | grep -qiE '(ENV_|DATABASE_URL|AWS_|API_KEY|SECRET)' 2>/dev/null && {
                echo "[LAMBDA-ENV-LEAK] $l_url - Environment variables leaked" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"lambda_env_leak\",\"url\":\"$l_url\",\"severity\":\"CRITICAL\",\"evidence\":\"Lambda environment variables exposed in response\"}" \
                    "$findings_file" 2>/dev/null || true
            } || true
        fi
    done

    # --- Azure Functions discovery ---
    local azure_func_paths=(
        "/api/"
        "/api/v1/"
        "/admin/functions/"
        "/runtime/webhooks/"
        "/host.json"
    )

    for afpath in "${azure_func_paths[@]}"; do
        local af_url="https://${domain}${afpath}"
        local af_status af_body
        af_body=$(curl -s -m 10 -w "\n%{http_code}" "$af_url" 2>/dev/null || true)
        af_status=$(echo "$af_body" | tail -1)

        if [[ "$af_status" == "200" ]]; then
            local af_content
            af_content=$(echo "$af_body" | head -n -1)

            echo "$af_content" | grep -qiE '(azure-functions|functionKeys|systemKeys|masterKey)' 2>/dev/null && {
                echo "[AZURE-FUNC-EXPOSED] $af_url - Azure Functions endpoint exposed" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"azure_function_exposed\",\"url\":\"$af_url\",\"severity\":\"HIGH\",\"evidence\":\"Azure Functions endpoint accessible\"}" \
                    "$findings_file" 2>/dev/null || true

                echo "$af_content" | grep -qiE '(masterKey|adminKey|functionKey)' 2>/dev/null && {
                    echo "[AZURE-FUNC-KEY] $af_url - Azure Function admin keys exposed" >> "$vulns_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"azure_function_key_exposed\",\"url\":\"$af_url\",\"severity\":\"CRITICAL\",\"evidence\":\"Azure Function admin/master keys exposed\"}" \
                        "$findings_file" 2>/dev/null || true
                } || true
            } || true
        fi
    done

    # --- GCP Cloud Functions discovery ---
    local gcf_paths=(
        "/function/"
        "/api/"
        "/_ah/"
        "/_ah/warmup"
    )

    for gpath in "${gcf_paths[@]}"; do
        local g_url="https://${domain}${gpath}"
        local g_status g_body
        g_body=$(curl -s -m 10 -w "\n%{http_code}" "$g_url" 2>/dev/null || true)
        g_status=$(echo "$g_body" | tail -1)

        if [[ "$g_status" == "200" ]]; then
            local g_content
            g_content=$(echo "$g_body" | head -n -1)

            echo "$g_content" | grep -qiE '(cloud-functions|X-Cloud-Trace-Context|Function-Status)' 2>/dev/null && {
                echo "[GCF-EXPOSED] $g_url - GCP Cloud Function exposed" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"gcp_function_exposed\",\"url\":\"$g_url\",\"severity\":\"MEDIUM\",\"evidence\":\"GCP Cloud Function accessible\"}" \
                    "$findings_file" 2>/dev/null || true
            } || true
        fi
    done

    # --- Test serverless function parameters for injection ---
    local inject_params=(
        "?debug=true"
        "?test=true"
        "?admin=true"
        "?internal=true"
        "?dev=true"
        "?env=production"
        "?config=../../etc/passwd"
        "?file=/etc/passwd"
        "?exec=id"
        "?cmd=whoami"
    )

    for lpath in "${lambda_paths[@]:0:5}"; do
        for param in "${inject_params[@]}"; do
            local test_url="https://${domain}${lpath}${param}"
            local t_status t_body
            t_body=$(curl -s -m 10 -w "\n%{http_code}" "$test_url" 2>/dev/null || true)
            t_status=$(echo "$t_body" | tail -1)

            if [[ "$t_status" == "200" ]]; then
                local t_content
                t_content=$(echo "$t_body" | head -n -1)

                echo "$t_content" | grep -qiE '(root:x:0:0|bin/bash|lambda:/var/task)' 2>/dev/null && {
                    echo "[FUNC-FILE-INCLUDE] $test_url - File inclusion via function parameter" >> "$vulns_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"serverless_file_inclusion\",\"url\":\"$test_url\",\"severity\":\"CRITICAL\",\"evidence\":\"Serverless function allows file inclusion\"}" \
                        "$findings_file" 2>/dev/null || true
                } || true

                echo "$t_content" | grep -qiE '(uid=|gid=|www-data|root)' 2>/dev/null && {
                    echo "[FUNC-COMMAND-INJECT] $test_url - Command injection via function parameter" >> "$vulns_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"serverless_command_injection\",\"url\":\"$test_url\",\"severity\":\"CRITICAL\",\"evidence\":\"Serverless function allows command injection\"}" \
                        "$findings_file" 2>/dev/null || true
                } || true
            fi
        done
    done

    # --- Check for exposed serverless configurations ---
    local config_paths=(
        "/serverless.yml"
        "/serverless.yaml"
        "/.env"
        "/.env.local"
        "/.env.production"
        "/host.json"
        "/local.settings.json"
        "/function.json"
    )

    for cpath in "${config_paths[@]}"; do
        local c_status
        c_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://${domain}${cpath}" 2>/dev/null || echo "000")

        if [[ "$c_status" == "200" ]]; then
            echo "[SERVERLESS-CONFIG] https://${domain}${cpath} - Serverless config accessible" >> "$vulns_file"
            ((results++)) || true

            local c_body
            c_body=$(curl -s -m 5 "https://${domain}${cpath}" 2>/dev/null || true)

            echo "$c_body" | grep -qiE '(password|secret|token|api_key|access_key)' 2>/dev/null && {
                echo "[SERVERLESS-CONFIG-SECRET] https://${domain}${cpath} - Secrets in serverless config" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"serverless_config_secret\",\"url\":\"https://${domain}${cpath}\",\"severity\":\"CRITICAL\",\"evidence\":\"Secrets found in serverless configuration file\"}" \
                    "$findings_file" 2>/dev/null || true
            } || true
        fi
    done

    # Write count
    echo "$results" > "$output_dir/serverless/count.txt"

    py_log "INFO" "serverless_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Serverless phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    serverless_phase "$@"
fi
