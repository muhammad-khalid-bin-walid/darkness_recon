#!/usr/bin/env bash
# iac_scan_phase.sh - Infrastructure-as-code artifact scanning,
# Terraform/CloudFormation misconfigurations.

iac_scan_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "iac_scan_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/iac_scan"

    local results=0
    local vulns_file="$output_dir/iac_scan/iac_vulns.txt"
    local artifacts_file="$output_dir/iac_scan/iac_artifacts.txt"
    local findings_file="$output_dir/iac_scan/findings.json"

    log "INFO" "Starting IaC scan phase for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # --- Discover IaC artifact endpoints ---
    local iac_paths=(
        "/terraform.tfstate"
        "/terraform.tfstate.backup"
        "/.terraform/terraform.tfstate"
        "/tfstate"
        "/infra/terraform.tfstate"
        "/infra/terraform.tfstate.backup"
        "/deploy/terraform.tfstate"
        "/terraform.tfvars"
        "/terraform.tfvars.json"
        "/.env"
        "/terraform/"
        "/cloudformation.yml"
        "/cloudformation.yaml"
        "/cloudformation.json"
        "/cfn.yml"
        "/cfn.yaml"
        "/template.yml"
        "/template.yaml"
        "/infrastructure.yml"
        "/infrastructure.yaml"
        "/stack.yml"
        "/stacks.yml"
        "/pulumi.yaml"
        "/pulumi.yml"
        "/serverless.yml"
        "/serverless.yaml"
        "/sam.yml"
        "/sam.yaml"
        "/template.json"
        "/arm.json"
        "/bicep/main.bicep"
        "/cdktf.out/"
        "/.pulumi/"
        "/.terraform.d/"
        "/.terraform.lock.hcl"
        "/terraform.plan"
        "/tfplan"
        "/tf.plan"
    )

    for iacpath in "${iac_paths[@]}"; do
        local iac_url="https://${domain}${iacpath}"
        local iac_status iac_body
        iac_body=$(curl -s -m 10 -w "\n%{http_code}" "$iac_url" 2>/dev/null || true)
        iac_status=$(echo "$iac_body" | tail -1)

        if [[ "$iac_status" == "200" ]]; then
            local content
            content=$(echo "$iac_body" | head -n -1)
            log "INFO" "IaC artifact found: $iac_url"

            echo "[IAC-ARTIFACT] $iac_url - Accessible (HTTP 200)" >> "$artifacts_file"
            ((results++)) || true

            write_endpoint "{\"url\":\"$iac_url\",\"method\":\"GET\",\"status\":200,\"phase\":\"iac_scan\"}" \
                "$findings_file" 2>/dev/null || true

            # --- Terraform state file analysis ---
            if echo "$iacpath" | grep -qiE '(\.tfstate|terraform)'; then
                # Check for sensitive data in state
                echo "$content" | grep -qiE '(password|secret|access_key|private_key|token|api_key)' 2>/dev/null && {
                    echo "[TFSTATE-SECRETS] $iac_url - Secrets found in Terraform state" >> "$vulns_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"terraform_state_secrets\",\"url\":\"$iac_url\",\"severity\":\"CRITICAL\",\"evidence\":\"Secrets found in Terraform state file\"}" \
                        "$findings_file" 2>/dev/null || true
                } || true

                # Check for public resources
                echo "$content" | grep -qiE '(public|0\.0\.0\.0/0|::/0|acl.*public)' 2>/dev/null && {
                    echo "[TFSTATE-PUBLIC] $iac_url - Public resources in Terraform state" >> "$vulns_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"terraform_public_resources\",\"url\":\"$iac_url\",\"severity\":\"HIGH\",\"evidence\":\"Public resources found in Terraform state\"}" \
                        "$findings_file" 2>/dev/null || true
                } || true

                # Check state encryption
                echo "$content" | grep -q '"encrypted":false' 2>/dev/null && {
                    echo "[TFSTATE-UNENCRYPTED] $iac_url - Terraform state unencrypted" >> "$vulns_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"terraform_state_unencrypted\",\"url\":\"$iac_url\",\"severity\":\"HIGH\",\"evidence\":\"Terraform state file is not encrypted\"}" \
                        "$findings_file" 2>/dev/null || true
                } || true
            fi

            # --- CloudFormation template analysis ---
            if echo "$iacpath" | grep -qiE '(cloudformation|cfn|template)'; then
                # Check for hardcoded secrets
                echo "$content" | grep -qiE '(Password|Secret|ApiKey|Token|AccessKey)' 2>/dev/null && {
                    echo "[CFN-SECRETS] $iac_url - Hardcoded secrets in CloudFormation template" >> "$vulns_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"cloudformation_secrets\",\"url\":\"$iac_url\",\"severity\":\"CRITICAL\",\"evidence\":\"Hardcoded secrets in CloudFormation template\"}" \
                        "$findings_file" 2>/dev/null || true
                } || true

                # Check for public access
                echo "$content" | grep -qiE '(PubliclyAccessible|0\.0\.0\.0/0|public.*true|PublicAccess)' 2>/dev/null && {
                    echo "[CFN-PUBLIC] $iac_url - Publicly accessible resources in template" >> "$vulns_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"cloudformation_public\",\"url\":\"$iac_url\",\"severity\":\"HIGH\",\"evidence\":\"Publicly accessible resources in CloudFormation template\"}" \
                        "$findings_file" 2>/dev/null || true
                } || true

                # Check for unencrypted storage
                echo "$content" | grep -qiE '(Encrypted.*false|SSEAlgorithm.*NONE|encryption.*disabled)' 2>/dev/null && {
                    echo "[CFN-UNENCRYPTED] $iac_url - Unencrypted resources in template" >> "$vulns_file"
                    ((results++)) || true

                    write_finding "{\"type\":\"cloudformation_unencrypted\",\"url\":\"$iac_url\",\"severity\":\"MEDIUM\",\"evidence\":\"Unencrypted resources in CloudFormation template\"}" \
                        "$findings_file" 2>/dev/null || true
                } || true
            fi

            # --- Serverless framework analysis ---
            if echo "$iacpath" | grep -qiE '(serverless|sam)'; then
                echo "$content" | grep -qiE '(environment.*variables|env:)' 2>/dev/null && {
                    echo "[SERVERLESS-ENV] $iac_url - Environment variables in serverless config" >> "$vulns_file"
                    ((results++)) || true
                } || true
            fi
        fi
    done

    # --- Check for exposed .git directories containing IaC ---
    local git_paths=(
        "/.git/config"
        "/.git/HEAD"
        "/.gitignore"
    )

    for gpath in "${git_paths[@]}"; do
        local g_status
        g_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://${domain}${gpath}" 2>/dev/null || echo "000")

        if [[ "$g_status" == "200" ]]; then
            local g_body
            g_body=$(curl -s -m 5 "https://${domain}${gpath}" 2>/dev/null || true)

            # Check if git repo contains IaC files
            echo "$g_body" | grep -qiE '(terraform|cloudformation|pulumi|serverless)' 2>/dev/null && {
                echo "[GIT-IAC-EXPOSED] https://${domain}${gpath} - IaC files in exposed git repo" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"git_iac_exposed\",\"url\":\"https://${domain}${gpath}\",\"severity\":\"HIGH\",\"evidence\":\"Infrastructure-as-code found in exposed git repository\"}" \
                    "$findings_file" 2>/dev/null || true
            } || true
        fi
    done

    # --- Check for exposed plan files ---
    local plan_paths=(
        "/terraform.plan"
        "/tfplan"
        "/tf.plan"
        "/plan.json"
        "/plan.binary"
        "/cfn-execution-history.json"
        "/change-set.json"
    )

    for ppath in "${plan_paths[@]}"; do
        local p_status
        p_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "https://${domain}${ppath}" 2>/dev/null || echo "000")

        if [[ "$p_status" == "200" ]]; then
            echo "[IAC-PLAN-EXPOSED] https://${domain}${ppath} - Infrastructure plan file accessible" >> "$vulns_file"
            ((results++)) || true

            write_finding "{\"type\":\"iac_plan_exposed\",\"url\":\"https://${domain}${ppath}\",\"severity\":\"MEDIUM\",\"evidence\":\"Infrastructure plan file publicly accessible\"}" \
                "$findings_file" 2>/dev/null || true
        fi
    done

    # Write count
    echo "$results" > "$output_dir/iac_scan/count.txt"

    py_log "INFO" "iac_scan_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "IaC scan phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    iac_scan_phase "$@"
fi
