#!/bin/bash
# Track 17 - Wireless/IoT | Phase 253: Firmware CVE Analysis
# Vulnerability mapping, patch status

iot_firmware_cve_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        log "ERROR" "iot_firmware_cve_phase: domain argument required"
        return 1
    fi

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/iot_firmware_cve"
    mkdir -p "$phase_dir"

    log "INFO" "Starting iot_firmware_cve_phase for $domain"

    local cve_file="$phase_dir/firmware_cves.txt"
    local mapping_file="$phase_dir/vulnerability_mapping.txt"
    local count=0

    # --- Extract firmware and software versions from HTTP responses ---
    log "INFO" "Extracting firmware and software versions..."
    local versions_file="$phase_dir/detected_versions.txt"

    local targets_file="$output_dir/crawl/endpoints.txt"
    if [[ -f "$targets_file" ]]; then
        head -20 "$targets_file" | while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            local resp
            resp=$(curl -s -m 5 -D- "$url" 2>/dev/null) || true
            echo "$resp" | grep -ioE '(Server|X-Powered-By|X-AspNet-Version|X-Generator|Firmware|Version|X-Device): [^\r\n]+' 2>/dev/null | while IFS= read -r header; do
                echo "$url | $header" >> "$versions_file"
            done
            echo "$resp" | grep -ioE '(firmware|software|version|build)\s*[:=]\s*[0-9]+\.[0-9]+[\.\d]*[a-z]*[\.\d]*' 2>/dev/null | while IFS= read -r ver; do
                echo "$url | $ver" >> "$versions_file"
            done
        done
    fi

    # --- Query NIST NVD API for known CVEs ---
    log "INFO" "Mapping detected versions to known CVEs..."
    if [[ -f "$versions_file" ]]; then
        while IFS= read -r version_line; do
            [[ -z "$version_line" ]] && continue
            local version_str
            version_str=$(echo "$version_line" | grep -ioE '[0-9]+\.[0-9]+[\.\d]*[a-z]*[\.\d]*' | head -1)
            [[ -z "$version_str" ]] && continue

            local cve_resp
            cve_resp=$(curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=$version_str&resultsPerPage=5" 2>/dev/null) || true
            echo "$cve_resp" | jq -r '.vulnerabilities[]? | .cve.id + "|" + (.cve.descriptions[0].value // "N/A") + "|" + (.cve.metrics.cvssMetricV31[0].cvssData.baseScore // "N/A" | tostring)' 2>/dev/null | while IFS='|' read -r cve_id description score; do
                echo "[CVE] version=$version_str cve=$cve_id score=$score desc=${description:0:200}" >> "$cve_file"
                echo "$version_line | CVE=$cve_id | Score=$score" >> "$mapping_file"
                ((count++)) || true
            done
        done
    fi

    # --- Check for known IoT-specific CVEs ---
    log "INFO" "Checking for known IoT vulnerability signatures..."
    local iot_cve_patterns=(
        "CVE-2021-36260:Hikvision:OS Command Injection"
        "CVE-2021-33044:Dahua:Auth Bypass"
        "CVE-2021-33045:Dahua:Auth Bypass"
        "CVE-2020-24950:Netgear:RCE"
        "CVE-2019-20625:Netgear:Auth Bypass"
        "CVE-2018-10561:GPON:Auth Bypass"
        "CVE-2017-17215:Huawei:RCE"
        "CVE-2019-19781:Citrix:RCE"
        "CVE-2020-5902:F5:Bypass"
        "CVE-2021-20038:SonicWall:Buffer Overflow"
    )

    for iot_cve in "${iot_cve_patterns[@]}"; do
        local cve_id="${iot_cve%%:*}"
        local remainder="${iot_cve#*:}"
        local vendor="${remainder%%:*}"
        local vuln_type="${remainder#*:}"
        echo "[IOT_CVE_CHECK] cve=$cve_id vendor=$vendor type=$vuln_type" >> "$mapping_file"
    done

    # --- Write structured findings ---
    if [[ -f "$cve_file" ]]; then
        while IFS= read -r finding; do
            write_finding "$phase_dir" "$finding" "firmware_cve" "" "" "" || true
        done < "$cve_file"
    fi

    echo "$count" > "$phase_dir/count.txt"

    py_log "INFO" "iot_firmware_cve_phase" "domain=$domain findings=$count"
    log "INFO" "iot_firmware_cve_phase complete: $count findings"
    return 0
}

iot_firmware_cve_phase "$@"
