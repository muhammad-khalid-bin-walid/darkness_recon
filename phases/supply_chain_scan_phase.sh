#!/usr/bin/env bash
# supply_chain_scan_phase.sh - Supply-chain dependency risk scan, dependency
# confusion, malicious package detection.

supply_chain_scan_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "supply_chain_scan_phase: No domain provided"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/supply_chain_scan"

    local results=0
    local vulns_file="$output_dir/supply_chain_scan/supply_chain_vulns.txt"
    local deps_file="$output_dir/supply_chain_scan/risky_deps.txt"
    local findings_file="$output_dir/supply_chain_scan/findings.json"

    log "INFO" "Starting supply chain scan phase for $domain"

    tool_available curl || { log "WARN" "curl not found - skipping"; return 0; }

    # --- Discover package manifest endpoints ---
    local manifest_paths=(
        "/package.json"
        "/package-lock.json"
        "/yarn.lock"
        "/pnpm-lock.yaml"
        "/Gemfile"
        "/Gemfile.lock"
        "/requirements.txt"
        "/Pipfile"
        "/Pipfile.lock"
        "/poetry.lock"
        "/pyproject.toml"
        "/go.sum"
        "/go.mod"
        "/Cargo.lock"
        "/Cargo.toml"
        "/composer.json"
        "/composer.lock"
        "/pom.xml"
        "/build.gradle"
        "/build.gradle.kts"
        "/mix.lock"
        "/pubspec.lock"
        "/Package.resolved"
        "/Package.swift"
        "/package.resolved"
    )

    for mpath in "${manifest_paths[@]}"; do
        local m_url="https://${domain}${mpath}"
        local m_status m_body
        m_body=$(curl -s -m 10 -w "\n%{http_code}" "$m_url" 2>/dev/null || true)
        m_status=$(echo "$m_body" | tail -1)

        if [[ "$m_status" == "200" ]]; then
            local content
            content=$(echo "$m_body" | head -n -1)
            log "INFO" "Package manifest found: $m_url"

            echo "[MANIFEST-EXPOSED] $m_url - Package manifest accessible" >> "$deps_file"
            ((results++)) || true

            write_endpoint "{\"url\":\"$m_url\",\"method\":\"GET\",\"status\":200,\"phase\":\"supply_chain_scan\"}" \
                "$findings_file" 2>/dev/null || true

            # --- Analyze dependencies for known vulnerabilities ---
            case "$mpath" in
                "/package.json")
                    # Extract npm package names
                    local npm_pkgs
                    npm_pkgs=$(echo "$content" | grep -oE '"[a-z0-9@/\._\-]+"\s*:\s*"[^"]*"' 2>/dev/null | \
                        grep -v '"name"\|"version"\|"description"\|"main"\|"scripts"\|"keywords"\|"author"\|"license"\|"repository"' | \
                        sed 's/"//g' | awk -F: '{print $1}' | sed 's/^ *//' | head -50 || true)

                    if [[ -n "$npm_pkgs" ]]; then
                        while IFS= read -r pkg; do
                            # Check npm registry for typosquatting signals
                            local pkg_clean
                            pkg_clean=$(echo "$pkg" | sed 's/@[^@]*$//' | sed 's|^@||')

                            local registry_url="https://registry.npmjs.org/${pkg_clean}"
                            local reg_status
                            reg_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$registry_url" 2>/dev/null || echo "000")

                            if [[ "$reg_status" == "404" ]]; then
                                echo "[DEP-NOT-FOUND] $m_url - npm package not found in registry: $pkg" >> "$vulns_file"
                                ((results++)) || true

                                write_finding "{\"type\":\"dependency_not_found\",\"manifest\":\"$m_url\",\"package\":\"$pkg\",\"severity\":\"HIGH\",\"evidence\":\"Package not found in npm registry (possible typosquatting)\"}" \
                                    "$findings_file" 2>/dev/null || true
                            fi

                            # Check for deprecated packages
                            if [[ "$reg_status" == "200" ]]; then
                                local reg_body
                                reg_body=$(curl -s -m 5 "$registry_url" 2>/dev/null || true)
                                echo "$reg_body" | grep -q '"deprecated"' 2>/dev/null && {
                                    echo "[DEP-DEPRECATED] $m_url - Deprecated npm package: $pkg" >> "$deps_file"
                                    ((results++)) || true

                                    write_finding "{\"type\":\"deprecated_dependency\",\"manifest\":\"$m_url\",\"package\":\"$pkg\",\"severity\":\"LOW\",\"evidence\":\"Package is deprecated\"}" \
                                        "$findings_file" 2>/dev/null || true
                                } || true
                            fi
                        done <<< "$npm_pkgs"
                    fi
                    ;;

                "/requirements.txt" | "/Pipfile" | "/pyproject.toml")
                    local py_pkgs
                    py_pkgs=$(echo "$content" | grep -oE '[a-zA-Z0-9_\-]+' | sort -u | head -50 || true)

                    while IFS= read -r pkg; do
                        [[ -z "$pkg" ]] && continue
                        local pypi_url="https://pypi.org/pypi/${pkg}/json"
                        local pypi_status
                        pypi_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$pypi_url" 2>/dev/null || echo "000")

                        if [[ "$pypi_status" == "404" ]]; then
                            echo "[DEP-NOT-FOUND-PYPI] $m_url - Python package not found: $pkg" >> "$vulns_file"
                            ((results++)) || true

                            write_finding "{\"type\":\"dependency_not_found_pypi\",\"manifest\":\"$m_url\",\"package\":\"$pkg\",\"severity\":\"HIGH\",\"evidence\":\"Package not found in PyPI (possible dependency confusion)\"}" \
                                "$findings_file" 2>/dev/null || true
                        fi
                    done <<< "$py_pkgs"
                    ;;
            esac
        fi
    done

    # --- Check for dependency confusion via DNS ---
    local pkg_prefixes=("internal" "private" "corp" "dev" "staging" "prod")
    local pkg_suffixes=("utils" "auth" "core" "api" "common" "shared" "lib")

    for prefix in "${pkg_prefixes[@]}"; do
        for suffix in "${pkg_suffixes[@]}"; do
            local test_pkg="${prefix}-${suffix}-${base_name:-internal}"
            local npm_check="https://registry.npmjs.org/${test_pkg}"
            local pypi_check="https://pypi.org/pypi/${test_pkg}/json"

            local npm_status pypi_status
            npm_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$npm_check" 2>/dev/null || echo "000")
            pypi_status=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$pypi_check" 2>/dev/null || echo "000")

            if [[ "$npm_status" == "200" ]]; then
                echo "[DEP-CONFUSION-NPM] Potential npm dependency confusion: $test_pkg is registered" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"dependency_confusion_npm\",\"package\":\"$test_pkg\",\"severity\":\"HIGH\",\"evidence\":\"Internal package name registered in public npm registry\"}" \
                    "$findings_file" 2>/dev/null || true
            fi

            if [[ "$pypi_status" == "200" ]]; then
                echo "[DEP-CONFUSION-PYPI] Potential PyPI dependency confusion: $test_pkg is registered" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"dependency_confusion_pypi\",\"package\":\"$test_pkg\",\"severity\":\"HIGH\",\"evidence\":\"Internal package name registered in public PyPI registry\"}" \
                    "$findings_file" 2>/dev/null || true
            fi
        done
    done

    # --- Check for malicious indicators in JS bundles ---
    local js_urls=()
    local main_page
    main_page=$(curl -s -m 15 "https://$domain" 2>/dev/null || true)
    if [[ -n "$main_page" ]]; then
        while IFS= read -r url; do
            js_urls+=("$url")
        done < <(echo "$main_page" | grep -oE '(src|href)="[^"]*\.js[^"]*"' | \
            sed 's/.*="\(.*\)"/\1/' | head -20 2>/dev/null || true)
    fi

    for js_url in "${js_urls[@]}"; do
        if [[ "$js_url" != http* ]]; then
            [[ "$js_url" == /* ]] && js_url="https://${domain}${js_url}" || js_url="https://${domain}/${js_url}"
        fi

        local js_body
        js_body=$(curl -s -m 15 "$js_url" 2>/dev/null || true)
        if [[ -n "$js_body" ]]; then
            # Check for crypto mining patterns
            echo "$js_body" | grep -qiE '(coinhive|coin-hive|cryptoloot|crypto-loot|coinimp|authedmine|stratum\+tcp)' 2>/dev/null && {
                echo "[MALICIOUS-JS] $js_url - Potential crypto miner detected" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"crypto_miner_detected\",\"url\":\"$js_url\",\"severity\":\"CRITICAL\",\"evidence\":\"Cryptocurrency mining code detected in JavaScript\"}" \
                    "$findings_file" 2>/dev/null || true
            } || true

            # Check for data exfiltration patterns
            echo "$js_body" | grep -qiE '(eval\(atob|Function\(.*atob|document\.cookie.*https?://|send\(.*\.cookie)' 2>/dev/null && {
                echo "[MALICIOUS-JS-EXFIL] $js_url - Potential data exfiltration pattern" >> "$vulns_file"
                ((results++)) || true

                write_finding "{\"type\":\"js_data_exfiltration\",\"url\":\"$js_url\",\"severity\":\"CRITICAL\",\"evidence\":\"Potential data exfiltration pattern in JavaScript\"}" \
                    "$findings_file" 2>/dev/null || true
            } || true
        fi
    done

    # Write count
    echo "$results" > "$output_dir/supply_chain_scan/count.txt"

    py_log "INFO" "supply_chain_scan_phase" "Completed for $domain" "results=$results" 2>/dev/null || true
    log "INFO" "Supply chain scan phase complete: $results findings for $domain"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    supply_chain_scan_phase "$@"
fi
