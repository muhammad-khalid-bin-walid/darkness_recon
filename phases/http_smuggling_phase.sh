#!/bin/bash
# HTTP request smuggling/desync detection, CL.TE and TE.CL testing, header normalization

http_smuggling_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local smuggle_dir="$output_dir/http_smuggling"
    local live_file="$output_dir/live/live_subdomains.txt"

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    mkdir -p "$smuggle_dir"

    log "INFO" "Starting HTTP smuggling testing for $domain"
    py_log "INFO" "http_smuggling_phase started" --phase "http_smuggling" --target "$domain" || true

    local smuggling_vulns="$smuggle_dir/smuggling_vulns.txt"
    local desync_vectors="$smuggle_dir/desync_vectors.txt"
    touch "$smuggling_vulns" "$desync_vectors"

    if [ ! -f "$live_file" ]; then
        log "WARN" "No live hosts file found, skipping HTTP smuggling testing"
        echo "0" > "$smuggle_dir/count.txt"
        return 0
    fi

    # ------------------------------------------------------------------
    # 1. CL.TE (Content-Length vs Transfer-Encoding) detection
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing CL.TE smuggling vectors..."

        # CL.TE payload: front server uses Content-Length, back server uses Transfer-Encoding
        local clte_payload
        clte_payload="POST / HTTP/1.1\r\nHost: TARGET\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED"

        while IFS= read -r host; do
            [ -z "$host" ] && continue
            local response
            response=$(curl -s -D - --max-time 15 \
                -H $'Transfer-Encoding: chunked\r\nContent-Length: 3' \
                -d "1\r\nZ\r\n0\r\n\r\n" \
                "$host" 2>/dev/null) || true

            if echo "$response" | grep -qiE "transfer-encoding.*chunked"; then
                echo "CLTE_CANDIDATE: $host | Server accepts both CL and TE" >> "$desync_vectors"
                write_finding "{\"type\":\"http_smuggling_clte\",\"url\":\"$host\",\"severity\":\"critical\",\"domain\":\"$domain\"}" "$smuggle_dir/findings.json" || true
            fi
        done < <(head -30 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 2. TE.CL detection
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing TE.CL smuggling vectors..."

        while IFS= read -r host; do
            [ -z "$host" ] && continue
            # Send TE header with obfuscation
            for te_variant in "Transfer-Encoding: chunked" "Transfer-Encoding: cow" "Transfer-Encoding : chunked" "Transfer-Encoding: chunked, identity" "Transfer-Encoding: identity, chunked"; do
                local response
                response=$(curl -s -D - --max-time 15 \
                    -H "$te_variant" \
                    -H "Content-Length: 5" \
                    -d "0\r\n\r\n" \
                    "$host" 2>/dev/null) || true

                if echo "$response" | grep -qiE "transfer-encoding"; then
                    echo "TECL_CANDIDATE: $host | Variant: $te_variant" >> "$desync_vectors"
                    write_finding "{\"type\":\"http_smuggling_tecl\",\"url\":\"$host\",\"variant\":\"$te_variant\",\"severity\":\"critical\",\"domain\":\"$domain\"}" "$smuggle_dir/findings.json" || true
                    break
                fi
            done
        done < <(head -30 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 3. TE.TE obfuscation testing
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing TE.TE obfuscation smuggling..."

        while IFS= read -r host; do
            [ -z "$host" ] && continue
            for obfuscation in \
                "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity" \
                "Transfer-Encoding: chunked, identity" \
                "Transfer-Encoding : chunked" \
                "Transfer-Encoding: chunked\t" \
                "Transfer-Encoding:\tchunked" \
                "Transfer-Encoding: chunked\r\nX: ignored"; do
                local code
                code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
                    -H "$obfuscation" \
                    -d "0\r\n\r\n" \
                    "$host" 2>/dev/null) || true
                if echo "$code" | grep -qE "^(200|400|403|404|500|502)$"; then
                    echo "TETE_OBFUSCATION: $host | Obfuscation: $obfuscation" >> "$desync_vectors"
                fi
            done
        done < <(head -20 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 4. Header normalization issues
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing header normalization discrepancies..."

        while IFS= read -r host; do
            [ -z "$host" ] && continue
            # Test case sensitivity in header names
            for variant in "X-Custom-Header" "x-custom-header" "X-CUSTOM-HEADER"; do
                local code
                code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
                    -H "${variant}: test" \
                    "$host" 2>/dev/null) || true
                if echo "$code" | grep -qE "^(200|201)$"; then
                    echo "HEADER_NORMALIZATION: $host | Variant accepted: $variant" >> "$desync_vectors"
                fi
            done
            # Test duplicate headers
            local dup_code
            dup_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
                -H "Host: target.com" \
                -H "Host: evil.com" \
                "$host" 2>/dev/null) || true
            if echo "$dup_code" | grep -qE "^(200|201)$"; then
                echo "DUPLICATE_HOST_HEADER: $host | Both Host headers accepted" >> "$desync_vectors"
                write_finding "{\"type\":\"http_smuggling_duplicate_host\",\"url\":\"$host\",\"severity\":\"high\",\"domain\":\"$domain\"}" "$smuggle_dir/findings.json" || true
            fi
        done < <(head -20 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 5. H2C smuggling (HTTP/2 to cleartext HTTP)
    # ------------------------------------------------------------------
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Testing H2C smuggling potential..."

        while IFS= read -r host; do
            [ -z "$host" ] && continue
            # Check for Upgrade: h2c support
            local code
            code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
                -H "Connection: Upgrade" \
                -H "Upgrade: h2c" \
                --http2 \
                "$host" 2>/dev/null) || true
            if echo "$code" | grep -qE "^(101|200)$"; then
                echo "H2C_UPGRADE_SUPPORTED: $host | H2C upgrade accepted" >> "$desync_vectors"
                write_finding "{\"type\":\"h2c_smuggling_possible\",\"url\":\"$host\",\"severity\":\"high\",\"domain\":\"$domain\"}" "$smuggle_dir/findings.json" || true
            fi
        done < <(head -20 "$live_file")
    fi

    # ------------------------------------------------------------------
    # 6. Summary count
    # ------------------------------------------------------------------
    local vuln_count
    vuln_count=$(wc -l < "$desync_vectors" 2>/dev/null || echo 0)
    log "INFO" "HTTP smuggling testing complete: $vuln_count potential vectors found"

    py_log "INFO" "http_smuggling_phase complete" --phase "http_smuggling" --target "$domain" --extra "{\"vectors\":$vuln_count}" || true
    echo "$vuln_count" > "$smuggle_dir/count.txt"
}

export -f http_smuggling_phase
