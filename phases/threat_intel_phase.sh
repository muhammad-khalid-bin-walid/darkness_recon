#!/bin/bash
# Combined Phase 16: Threat Intelligence & IOC Correlation
# Encompasses: OTX, AbuseIPDB, VirusTotal, URLhaus, ThreatFox, IOC correlation phases
# Sources Python bridge for phase_log, write_asset, write_finding functions

[[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

threat_intel_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local intel_dir="$output_dir/threat_intel"

    mkdir -p "$intel_dir"

    log "INFO" "Starting threat intelligence & IOC correlation for $domain"

    # AlienVault OTX integration
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Querying AlienVault OTX..."
        curl -s "https://otx.alienvault.com/indicator/domain/$domain/puzzlepieces" 2>>"$LOGS_DIR/threat_intel.log" >> "$intel_dir/otx.txt" || true
        curl -s "https://otx.alienvault.com/indicator/domain/$domain/analyses" 2>>"$LOGS_DIR/threat_intel.log" >> "$intel_dir/otx_analyses.txt" || true
    fi

    # AbuseIPDB integration
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Querying AbuseIPDB..."
        curl -s "https://api.abuseipdb.com/api/v2/blacklist/$domain" -H "Key: $ABUSEIPDB_KEY" 2>>"$LOGS_DIR/threat_intel.log" >> "$intel_dir/abuseipdb.txt" || true
    fi

    # VirusTotal integration
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Querying VirusTotal..."
        # Note: Would need VT API key
        curl -s "https://www.virustotal.com/api/v3/domain/$domain" -H "x-apikey: $VT_KEY" 2>>"$LOGS_DIR/threat_intel.log" >> "$intel_dir/virustotal.txt" || true
    fi

    # URLhaus integration
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Querying URLhaus..."
        curl -s "https://urlhaus.abuse.ch/api/v2/indicator/$domain/" 2>>"$LOGS_DIR/threat_intel.log" >> "$intel_dir/urlhaus.txt" || true
    fi

    # ThreatFox integration
    if command -v curl >/dev/null 2>&1; then
        log "INFO" "Querying ThreatFox..."
        curl -s "https://api.threatfox.eu/v1/indicators/domain/$domain" 2>>"$LOGS_DIR/threat_intel.log" >> "$intel_dir/threatfox.txt" || true
    fi

    # IOC correlation - merge all findings
    cat "$intel_dir"/*.txt 2>/dev/null | grep -v "^$" | sort -u > "$intel_dir/merged_iocs.txt"

    local ti_count
    ti_count=$(wc -l < "$intel_dir/merged_iocs.txt" 2>/dev/null || echo 0)

    phase_log "INFO" "Threat intelligence & IOC correlation complete: $ti_count IOCs found" "threat_intel" "$domain"

    # Write assets
    while IFS= read -r ioc; do
        [ -z "$ioc" ] && continue
        write_asset "{\"type\":\"threat_ioc\",\"value\":\"$ioc\",\"source\":\"threat_intel_correlation\",\"phase\":\"threat_intel_ioc_correlation\"}" \
            "$intel_dir/assets.jsonl" 2>/dev/null || true
    done < "$intel_dir/merged_iocs.txt"

    echo "$ti_count" > "$intel_dir/count.txt"

    write_finding "{\"type\":\"threat_intelligence\",\"severity\":\"info\",\"count\":$ti_count,\"phase\":\"threat_intel_ioc_correlation\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true

    py_log "INFO" "threat_intel_phase" "Completed for $domain"
}