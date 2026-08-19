#!/usr/bin/env bash
# Phase 191: Database Port Testing
set -euo pipefail

net_database() {
    local domain="$1"
    [[ -z "$domain" ]] && { log "ERROR" "Domain argument required"; return 1; }

    source "$(dirname "$0")/../core/core.sh" 2>/dev/null || true
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/net_database"

    log "INFO" "Starting database port testing for $domain"

    local db_vulns="$output_dir/net_database/db_vulns.txt"
    local db_exposed="$output_dir/net_database/db_exposed.txt"
    local count=0

    {
        echo "=== Database Vulnerabilities ==="
        echo "Domain: $domain"
        echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "Database security checks:"
        echo "  1. Default credentials"
        echo "  2. Authentication bypass"
        echo "  3. SQL injection vectors"
        echo "  4. Privilege escalation"
        echo "  5. Data exfiltration"
        echo "  6. Backup exposure"
        echo "  7. Replication configuration"
        echo "  8. Encryption at rest"
    } > "$db_vulns"

    {
        echo "=== Exposed Databases ==="
        echo "Domain: $domain"
        echo ""
        echo "Database ports to check:"
        echo "  MySQL:      3306"
        echo "  PostgreSQL:  5432"
        echo "  MongoDB:     27017"
        echo "  Redis:       6379"
        echo "  Memcached:   11211"
        echo "  MSSQL:       1433"
        echo "  Oracle:      1521"
        echo "  Cassandra:   9042"
        echo "  Elasticsearch: 9200"
        echo ""
        echo "Exposed database risks:"
        echo "  - Direct internet access"
        echo "  - No authentication"
        echo "  - Default credentials"
        echo "  - Information leakage"
        echo "  - Denial of service"
    } > "$db_exposed"

    # Test database ports
    local db_ports=(
        "3306:MySQL"
        "5432:PostgreSQL"
        "27017:MongoDB"
        "6379:Redis"
        "11211:Memcached"
        "1433:MSSQL"
        "9200:Elasticsearch"
    )

    for entry in "${db_ports[@]}"; do
        local port="${entry%%:*}"
        local name="${entry##*:}"
        local db_test
        db_test=$(nc -w 5 "$domain" "$port" < /dev/null 2>&1 | head -1 || echo "")
        if [[ $? -eq 0 ]] || [[ -n "$db_test" ]]; then
            echo "[DB] $name (port $port) responding" >> "$db_exposed"
            ((count++)) || true
        fi
    done

    echo "$count" > "$output_dir/net_database/count.txt"
    log "INFO" "Database port testing complete: $count findings"
    write_finding "{\"type\":\"net_database\",\"severity\":\"info\",\"count\":$count,\"phase\":\"net_database\"}" \
        "$output_dir/findings.jsonl" 2>/dev/null || true
    py_log "INFO" "phase=net_database domain=$domain findings=$count"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    net_database "${1:-}"
fi
