#!/bin/bash
# Social media OSINT phase - platform discovery, employee enumeration, credential leaks

social_media_osint_phase() {
    local domain="$1"
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local social_dir="$output_dir/social_media_osint"

    [[ "$(type -t log 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../core/core.sh"
    [[ "$(type -t write_finding 2>/dev/null)" != "function" ]] && source "$(dirname "$0")/../lib/phase_bridge.sh"

    mkdir -p "$social_dir"

    log "INFO" "Starting social media OSINT for $domain"
    py_log "INFO" "social_media_osint_phase" --phase "social_media_osint" --target "$domain"

    # ===== SOCIAL MEDIA PLATFORM DISCOVERY =====
    log "INFO" "Discovering social media profiles..."
    if tool_available "curl"; then
        local company_name
        company_name=$(echo "$domain" | sed 's/\..*//' | sed 's/-/ /g')

        # Check major platforms
        local platforms=(
            "https://twitter.com/$company_name"
            "https://x.com/$company_name"
            "https://www.linkedin.com/company/$company_name"
            "https://www.facebook.com/$company_name"
            "https://www.instagram.com/$company_name"
            "https://github.com/$company_name"
            "https://www.youtube.com/@$company_name"
            "https://www.tiktok.com/@$company_name"
            "https://www.reddit.com/r/$company_name"
            "https://medium.com/@$company_name"
        )

        > "$social_dir/platforms_found.txt"
        local profile_count=0

        for platform_url in "${platforms[@]}"; do
            local http_code
            http_code=$(curl -s -o /dev/null -w "%{http_code}" -L --max-time 10 \
                -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
                "$platform_url" 2>/dev/null || echo "000")

            if [ "$http_code" = "200" ] || [ "$http_code" = "301" ] || [ "$http_code" = "302" ]; then
                echo "$platform_url (HTTP $http_code)" >> "$social_dir/platforms_found.txt"
                profile_count=$((profile_count + 1))
                write_endpoint "{\"type\":\"social_profile\",\"url\":\"$platform_url\",\"status_code\":$http_code,\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$social_dir/profile_${profile_count}.json" || true
            fi
        done

        log "INFO" "Found $profile_count social media profiles"
    fi

    # ===== EMPLOYEE ENUMERATION =====
    log "INFO" "Enumerating employees via LinkedIn and GitHub..."
    if tool_available "curl"; then
        # LinkedIn employee search (public)
        curl -s "https://www.google.com/search?q=site:linkedin.com/in+%22$domain%22&num=50" \
            -H "User-Agent: Mozilla/5.0" 2>/dev/null \
            | grep -oiP 'https?://[a-z]{2,3}\.linkedin\.com/in/[^"&]+' 2>/dev/null \
            | sort -u > "$social_dir/linkedin_employees.txt" || true

        # GitHub organization members
        if tool_available "curl"; then
            local company_name
            company_name=$(echo "$domain" | sed 's/\..*//' | sed 's/-//g')
            curl -s "https://api.github.com/orgs/$company_name/members?per_page=100" \
                -H "Accept: application/vnd.github.v3+json" 2>/dev/null \
                | jq -r '.[].login' 2>/dev/null > "$social_dir/github_members.txt" || true
        fi

        # Hunter.io email enumeration (if API key available)
        if [ -n "${HUNTER_API_KEY:-}" ]; then
            curl -s "https://api.hunter.io/v2/domain-search?domain=$domain&api_key=$HUNTER_API_KEY&limit=50" \
                -o "$social_dir/hunter_results.json" 2>/dev/null || true

            python3 -c "
import json, sys
try:
    with open('$social_dir/hunter_results.json') as f:
        data = json.load(f)
    emails = []
    for e in data.get('data', {}).get('emails', []):
        emails.append({
            'email': e.get('value', ''),
            'name': f\"{e.get('first_name', '')} {e.get('last_name', '')}\",
            'position': e.get('position', ''),
            'confidence': e.get('confidence', 0),
            'linkedin': e.get('linkedin', '')
        })
    with open('$social_dir/hunter_employees.json', 'w') as f:
        json.dump(emails, f, indent=2)
    with open('$social_dir/hunter_employees.txt', 'w') as f:
        for e in emails:
            f.write(f\"{e['email']} - {e['name']} ({e['position']}) [confidence:{e['confidence']}]\n\")
except Exception as e:
    pass
" 2>/dev/null || true
        fi
    fi

    # ===== SHERLOCK USERNAME ENUMERATION =====
    log "INFO" "Running Sherlock for username enumeration..."
    if tool_available "sherlock"; then
        local company_name
        company_name=$(echo "$domain" | sed 's/\..*//' | sed 's/-//g')
        sherlock --no-color "$company_name" \
            --output "$social_dir/sherlock_results.txt" \
            2>>"$LOGS_DIR/sherlock.log" || true
    fi

    # ===== COMPILE EMPLOYEE LIST =====
    log "INFO" "Compiling employee list..."
    {
        echo "=== EMPLOYEE ENUMERATION FOR $domain ==="
        echo ""
        echo "--- LinkedIn Profiles ---"
        cat "$social_dir/linkedin_employees.txt" 2>/dev/null || echo "Not found"
        echo ""
        echo "--- GitHub Members ---"
        cat "$social_dir/github_members.txt" 2>/dev/null || echo "Not found"
        echo ""
        echo "--- Hunter.io Employees ---"
        cat "$social_dir/hunter_employees.txt" 2>/dev/null || echo "Not found"
    } > "$social_dir/employee_list.txt" 2>/dev/null || true

    # ===== CREDENTIAL LEAK CORRELATION =====
    log "INFO" "Checking for credential leaks..."
    if tool_available "curl"; then
        # Have I Been Pwned - domain search
        if [ -n "${HIBP_API_KEY:-}" ]; then
            curl -s "https://haveibeenpwned.com/api/v3/breacheddomain/$domain" \
                -H "hibp-api-key: $HIBP_API_KEY" \
                -H "User-Agent: DarkRecon-Framework" \
                2>/dev/null > "$social_dir/hibp_domain.json" || true
        fi

        # Breach directory check
        if [ -n "${BD_API_KEY:-}" ]; then
            curl -s "https://breachdirectory.p.rapidapi.com/?domain=$domain" \
                -H "X-RapidAPI-Key: $BD_API_KEY" \
                2>/dev/null > "$social_dir/breach_directory.json" || true
        fi

        # DeHashed (if API available)
        if [ -n "${DEHASHED_API_KEY:-}" ]; then
            curl -s -u "$DEHASHED_API_KEY:" \
                "https://api.dehashed.com/search?query=domain:$domain" \
                2>/dev/null > "$social_dir/dehashed.json" || true
        fi

        # GitLeaks via truffleHog
        local repo_url
        repo_url=$(curl -s "https://api.github.com/repos/$(echo "$domain" | sed 's/\..*//')" 2>/dev/null | jq -r '.html_url // empty' 2>/dev/null)
        if [ -n "$repo_url" ] && tool_available "trufflehog"; then
            trufflehog git "$repo_url" --json 2>/dev/null > "$social_dir/trufflehog_results.json" || true
        fi
    fi

    # ===== COMPILE CREDENTIAL LEAK REPORT =====
    log "INFO" "Compiling credential leak report..."
    {
        echo "=== CREDENTIAL LEAK REPORT FOR $domain ==="
        echo ""
        echo "--- HIBP Domain Breaches ---"
        if [ -s "$social_dir/hibp_domain.json" ]; then
            python3 -c "
import json
with open('$social_dir/hibp_domain.json') as f:
    data = json.load(f)
if isinstance(data, list):
    for b in data:
        print(f\"- {b.get('Name', 'Unknown')}: {b.get('BreachDate', 'Unknown date')}, {b.get('PwnCount', 0)} accounts\")
elif isinstance(data, dict) and data.get('message'):
    print(f'Status: {data[\"message\"]}')
" 2>/dev/null || echo "Query failed"
        else
            echo "Not queried or no results"
        fi
        echo ""
        echo "--- GitLeak/TruffleHog Results ---"
        if [ -s "$social_dir/trufflehog_results.json" ]; then
            python3 -c "
import json
with open('$social_dir/trufflehog_results.json') as f:
    for line in f:
        entry = json.loads(line)
        print(f\"Found: {entry.get('DetectorName', 'Unknown')} at {entry.get('SourceMetadata', {}).get('Data', {}).get('Git', {}).get('file', 'unknown')}\")
" 2>/dev/null || echo "Parse failed"
        else
            echo "Not queried or no results"
        fi
    } > "$social_dir/credential_leaks.txt" 2>/dev/null || true

    local social_count
    social_count=$(wc -l < "$social_dir/platforms_found.txt" 2>/dev/null || echo 0)
    local employee_count
    employee_count=$(wc -l < "$social_dir/employee_list.txt" 2>/dev/null || echo 0)

    write_finding "{\"type\":\"social_media_osint\",\"target\":\"$domain\",\"profiles\":$social_count,\"employees\":$employee_count,\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" "$social_dir/social_finding.json" || true

    log "INFO" "Social media OSINT complete: $social_count profiles, $employee_count employee entries"
    local total_count=$((social_count + employee_count))
    echo "$total_count" > "$social_dir/count.txt"
}
