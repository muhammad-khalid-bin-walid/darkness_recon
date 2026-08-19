#!/bin/bash
# fuzz_phase.sh — Directory and parameter fuzzing with baseline response diffing
# Dark Recon Framework v4 — Authorized pentesting only (requires signed ROE)
# Phase 4 of plan.md

fuzz_phase() {
    local domain="$1"
    local output_dir="${OUTPUT_DIR}/${domain}/recon_${TIMESTAMP}"
    local fuzz_dir="${output_dir}/fuzz"
    local live_file="${output_dir}/live/live_subdomains.txt"
    local state_file="${CACHE_DIR}/state/${domain}/fuzz.done"

    # Idempotency: skip if already completed
    if [ -f "${fuzz_dir}/fuzz_results.json" ] && [ -s "${fuzz_dir}/fuzz_results.json" ]; then
        log "INFO" "[fuzz] Results already exist, skipping (idempotent)"
        return 0
    fi

    mkdir -p "${fuzz_dir}/baselines" "${fuzz_dir}/diffs" "${fuzz_dir}/params"

    # Prerequisite checks
    local wordlist="${WORDLIST:-${CACHE_DIR}/wordlists/common.txt}"
    if [ ! -f "${wordlist}" ]; then
        log "WARN" "[fuzz] Wordlist not found at ${wordlist}, skipping fuzz phase"
        echo "0" > "${fuzz_dir}/count.txt"
        return 0
    fi

    if [ ! -f "${live_file}" ]; then
        log "WARN" "[fuzz] No live subdomains file at ${live_file}, skipping fuzz phase"
        echo "0" > "${fuzz_dir}/count.txt"
        return 0
    fi

    log "INFO" "[fuzz] Starting fuzzing for ${domain}"

    local threads="${THREADS:-50}"
    local timeout="${TIMEOUT:-300}"
    local fuzz_count=0
    local processed=0

    # Process up to 20 live subdomains
    while IFS= read -r target && [ "${processed}" -lt 20 ]; do
        [ -z "${target}" ] && continue
        processed=$((processed + 1))

        # Sanitize target name for use in filenames
        local safe
        safe=$(echo "${target}" | sed 's|https\?://||g' | sed 's|/.*||g' | tr '/:?*@' '_' | sed 's/[^a-zA-Z0-9._-]/_/g')

        log "INFO" "[fuzz] Processing target: ${target} (${processed}/20)"

        # ----------------------------------------------------------------
        # 1. Baseline capture
        # ----------------------------------------------------------------
        local baseline_file="${fuzz_dir}/baselines/${safe}.json"
        if command -v curl >/dev/null 2>&1; then
            local status_code content_length body_hash
            status_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
                -H "User-Agent: Mozilla/5.0" "${target}" 2>/dev/null || echo "000")
            content_length=$(curl -s -I --max-time 10 \
                -H "User-Agent: Mozilla/5.0" "${target}" 2>/dev/null \
                | grep -i "content-length" | awk '{print $2}' | tr -d '\r' || echo "0")
            body_hash=$(curl -s --max-time 10 \
                -H "User-Agent: Mozilla/5.0" "${target}" 2>/dev/null \
                | sha256sum | awk '{print $1}' || echo "unknown")

            cat > "${baseline_file}" <<EOF
{"url":"${target}","status":${status_code:-0},"content_length":${content_length:-0},"body_hash":"${body_hash:-unknown}"}
EOF
            log "INFO" "[fuzz] Baseline captured for ${target}: status=${status_code}"
        fi

        # ----------------------------------------------------------------
        # 2. Directory fuzzing
        # ----------------------------------------------------------------
        local ffuf_out="${fuzz_dir}/ffuf_${safe}.json"

        if tool_available "ffuf"; then
            log "INFO" "[fuzz] Running ffuf on ${target}"
            ffuf -u "${target}/FUZZ" \
                -w "${wordlist}" \
                -t "${threads}" \
                -mc 200,201,204,301,302,307,401,403,405 \
                -timeout 10 \
                -silent \
                -ac \
                -o "${ffuf_out}" \
                -of json \
                -H "User-Agent: Mozilla/5.0 (compatible; DarkRecon/1.0.2)" \
                2>>"${LOGS_DIR}/ffuf_${safe}.log" || true

        elif tool_available "gobuster"; then
            log "INFO" "[fuzz] ffuf not found, falling back to gobuster on ${target}"
            local gb_out="${fuzz_dir}/gobuster_${safe}.txt"
            gobuster dir \
                -u "${target}" \
                -w "${wordlist}" \
                -t "${threads}" \
                -o "${gb_out}" \
                -q \
                2>>"${LOGS_DIR}/gobuster_${safe}.log" || true

            # Convert gobuster output to minimal JSON for unified processing
            if [ -f "${gb_out}" ]; then
                python3 - "${gb_out}" "${target}" <<'PYEOF' > "${ffuf_out}" 2>/dev/null || true
import sys, json, re
gb_file, base_url = sys.argv[1], sys.argv[2]
results = []
with open(gb_file) as f:
    for line in f:
        m = re.match(r'(/\S+)\s+\(Status:\s*(\d+)\)', line.strip())
        if m:
            results.append({"url": base_url.rstrip('/') + m.group(1), "status": int(m.group(2)), "length": 0})
print(json.dumps({"results": results}))
PYEOF
            fi
        else
            log "WARN" "[fuzz] Neither ffuf nor gobuster available for ${target}"
        fi

        # ----------------------------------------------------------------
        # 3. Response diffing
        # ----------------------------------------------------------------
        if [ -f "${ffuf_out}" ] && [ -f "${baseline_file}" ] && command -v python3 >/dev/null 2>&1; then
            local diff_out="${fuzz_dir}/diffs/${safe}_anomalies.json"
            python3 - "${ffuf_out}" "${baseline_file}" "${diff_out}" <<'PYEOF' 2>/dev/null || true
import sys, json

ffuf_file, baseline_file, diff_out = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    baseline = json.loads(open(baseline_file).read())
    ffuf_data = json.loads(open(ffuf_file).read())
    results = ffuf_data.get("results", [])
    baseline_len = int(baseline.get("content_length", 0) or 0)
    baseline_status = int(baseline.get("status", 0) or 0)

    anomalies = []
    for r in results:
        r_status = int(r.get("status", 0) or 0)
        r_length = int(r.get("length", 0) or 0)
        is_anomaly = False
        reason = []
        if baseline_status > 0 and r_status != baseline_status:
            reason.append(f"status_changed:{baseline_status}->{r_status}")
            is_anomaly = True
        if baseline_len > 0:
            diff_pct = abs(r_length - baseline_len) / baseline_len
            if diff_pct > 0.20:
                reason.append(f"length_diff:{diff_pct:.0%}")
                is_anomaly = True
        if is_anomaly:
            anomalies.append({"url": r.get("url", ""), "status": r_status,
                               "length": r_length, "reasons": reason})

    with open(diff_out, "w") as f:
        json.dump({"baseline": baseline, "anomalies": anomalies, "total": len(anomalies)}, f, indent=2)
except Exception as e:
    with open(diff_out, "w") as f:
        json.dump({"error": str(e), "anomalies": [], "total": 0}, f)
PYEOF
        fi

    done < <(head -20 "${live_file}")

    # ----------------------------------------------------------------
    # 4. Parameter fuzzing (if arjun available)
    # ----------------------------------------------------------------
    if tool_available "arjun"; then
        log "INFO" "[fuzz] Running arjun parameter discovery on top endpoints"
        local crawl_urls="${output_dir}/crawl/all_urls.txt"
        if [ -f "${crawl_urls}" ]; then
            head -10 "${crawl_urls}" | while IFS= read -r ep_url; do
                [ -z "${ep_url}" ] && continue
                local ep_safe
                ep_safe=$(echo "${ep_url}" | md5sum | awk '{print $1}')
                arjun -u "${ep_url}" -oJ "${fuzz_dir}/params/arjun_${ep_safe}.json" \
                    --stable --rate-limit 10 \
                    2>>"${LOGS_DIR}/arjun.log" || true
            done
        fi
    fi

    # ----------------------------------------------------------------
    # 5. Result aggregation
    # ----------------------------------------------------------------
    log "INFO" "[fuzz] Aggregating results"

    if command -v jq >/dev/null 2>&1; then
        # Merge all ffuf JSON outputs into one results file
        local all_json_files
        all_json_files=$(find "${fuzz_dir}" -maxdepth 1 -name "ffuf_*.json" -size +2c 2>/dev/null || true)

        if [ -n "${all_json_files}" ]; then
            # Combine results arrays from all ffuf outputs
            echo "${all_json_files}" | xargs jq -s '[.[].results // [] | .[]]' 2>/dev/null \
                > "${fuzz_dir}/fuzz_results.json" || echo "[]" > "${fuzz_dir}/fuzz_results.json"

            # Human-readable txt
            jq -r '.[] | "\(.url) [\(.status)] length=\(.length)"' \
                "${fuzz_dir}/fuzz_results.json" 2>/dev/null \
                | sort -u > "${fuzz_dir}/fuzz_results.txt" || true
        else
            echo "[]" > "${fuzz_dir}/fuzz_results.json"
            touch "${fuzz_dir}/fuzz_results.txt"
        fi
    else
        # Fallback: cat all gobuster outputs
        cat "${fuzz_dir}"/*.txt 2>/dev/null | sort -u > "${fuzz_dir}/fuzz_results.txt" || true
        echo "[]" > "${fuzz_dir}/fuzz_results.json"
    fi

    fuzz_count=$(wc -l < "${fuzz_dir}/fuzz_results.txt" 2>/dev/null || echo 0)
    fuzz_count=$(echo "${fuzz_count}" | tr -d '[:space:]')
    echo "${fuzz_count}" > "${fuzz_dir}/count.txt"
    
    phase_log "INFO" "[fuzz] Complete: ${fuzz_count} results found for ${domain}" "fuzz" "$domain"

    # Write findings for interesting results (non-404)
    if [ -f "${fuzz_dir}/fuzz_results.json" ]; then
        while IFS= read -r result; do
            [ -z "$result" ] && continue
            local url=$(echo "$result" | jq -r '.url // empty' 2>/dev/null)
            local status=$(echo "$result" | jq -r '.status // 0' 2>/dev/null)
            
            if [ -n "$url" ] && [ "$status" != "404" ] && [ "$status" != "0" ]; then
                write_finding "{\"type\":\"directory_discovered\",\"severity\":\"info\",\"url\":\"$url\",\"status\":$status,\"phase\":\"fuzz\"}" \
                    "${fuzz_dir}/findings.jsonl" 2>/dev/null || true
            fi
        done < <(jq -c '.[]' "${fuzz_dir}/fuzz_results.json" 2>/dev/null)
    fi

    # Write findings for anomaly detections
    for diff_file in "${fuzz_dir}/diffs/"*_anomalies.json; do
        [ -f "$diff_file" ] || continue
        local anomaly_count=$(jq -r '.total // 0' "$diff_file" 2>/dev/null)
        if [ "$anomaly_count" -gt 0 ]; then
            write_finding "{\"type\":\"response_anomaly\",\"severity\":\"medium\",\"count\":$anomaly_count,\"file\":\"$(basename "$diff_file")\",\"phase\":\"fuzz\"}" \
                "${fuzz_dir}/findings.jsonl" 2>/dev/null || true
        fi
    done

    # ----------------------------------------------------------------
    # 6. Checkpoint
    # ----------------------------------------------------------------
    mkdir -p "$(dirname "${state_file}")"
    echo "$(date -u +%s)" > "${state_file}"

    py_log "INFO" "fuzz_phase" "Completed for $domain"
}
