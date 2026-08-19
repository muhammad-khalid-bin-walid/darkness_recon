#!/usr/bin/env bash
# Track 8: Reporting & Integration - Program Profiles Phase
# Program-specific profiles, scope rules, methodology templates

program_profiles_phase() {
    local domain="$1"
    if [[ -z "$domain" ]]; then
        echo "Usage: program_profiles_phase <domain>"
        return 1
    fi

    # Source core.sh if not already sourced
    if ! declare -F log >/dev/null 2>&1; then
        source "$(dirname "$0")/../core/core.sh"
    fi

    # Set up output directory
    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    mkdir -p "$output_dir/program_profiles"

    log "INFO" "Starting program profiles phase for $domain"

    # Check for required tools
    if ! tool_available "python3"; then
        log "ERROR" "python3 is required for program profiles phase"
        return 1
    fi

    # Initialize outputs
    local program_profiles="$output_dir/program_profiles/program_profiles.json"
    local active_profile="$output_dir/program_profiles/active_profile.txt"

    # Create program profiles
    cat > "$program_profiles" <<EOF
{
  "domain": "$domain",
  "timestamp": "$TIMESTAMP",
  "profiles": {
    "hackerone_standard": {
      "name": "HackerOne Standard",
      "platform": "hackerone",
      "scope": {
        "in_scope": ["*.${domain}", "api.${domain}", "app.${domain}"],
        "out_scope": ["*.${domain}/admin", "*.${domain}/internal"],
        "wildcard_allowed": true,
        "subdomains_allowed": true
      },
      "methodology": {
        "reconnaissance": true,
        "enumeration": true,
        "vulnerability_scanning": true,
        "manual_testing": true,
        "exploitation": true,
        "reporting": true
      },
      "rules": {
        "dos_allowed": false,
        "social_engineering": false,
        "physical_testing": false,
        "third_party_services": false,
        "data_destruction": false
      },
      "disclosure": {
        "response_time": "30 days",
        "fix_time": "90 days",
        "bounty_timeline": "30 days after fix"
      }
    },
    "bugcrowd_preset": {
      "name": "Bugcrowd Preset",
      "platform": "bugcrowd",
      "scope": {
        "in_scope": ["${domain}", "*.${domain}"],
        "out_scope": ["*.${domain}/admin/*"],
        "wildcard_allowed": true,
        "subdomains_allowed": true
      },
      "methodology": {
        "reconnaissance": true,
        "enumeration": true,
        "vulnerability_scanning": true,
        "manual_testing": true,
        "exploitation": true,
        "reporting": true
      },
      "rules": {
        "dos_allowed": false,
        "social_engineering": false,
        "physical_testing": false,
        "third_party_services": false,
        "data_destruction": false
      },
      "vrt_mapping": {
        "critical": "P1",
        "high": "P2",
        "medium": "P3",
        "low": "P4",
        "info": "P5"
      }
    },
    "custom_profile": {
      "name": "Custom Profile",
      "platform": "custom",
      "scope": {
        "in_scope": ["${domain}"],
        "out_scope": [],
        "wildcard_allowed": false,
        "subdomains_allowed": false
      },
      "methodology": {
        "reconnaissance": true,
        "enumeration": true,
        "vulnerability_scanning": true,
        "manual_testing": true,
        "exploitation": false,
        "reporting": true
      },
      "rules": {
        "dos_allowed": false,
        "social_engineering": false,
        "physical_testing": false,
        "third_party_services": false,
        "data_destruction": false
      }
    }
  },
  "active_profile": "hackerone_standard"
}
EOF

    # Create active profile file
    cat > "$active_profile" <<EOF
Active Program Profile for $domain
====================================
Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

Active Profile: hackerone_standard
Platform: HackerOne
Status: CONFIGURED

Scope Configuration:
- In-Scope: *.${domain}, api.${domain}, app.${domain}
- Out-of-Scope: *.${domain}/admin, *.${domain}/internal
- Wildcards: ALLOWED
- Subdomains: ALLOWED

Methodology:
- Reconnaissance: ENABLED
- Enumeration: ENABLED
- Vulnerability Scanning: ENABLED
- Manual Testing: ENABLED
- Exploitation: ENABLED
- Reporting: ENABLED

Rules:
- DoS Testing: NOT ALLOWED
- Social Engineering: NOT ALLOWED
- Physical Testing: NOT ALLOWED
- Third-Party Services: NOT ALLOWED
- Data Destruction: NOT ALLOWED

Disclosure Policy:
- Response Time: 30 days
- Fix Time: 90 days
- Bounty Timeline: 30 days after fix

Available Profiles:
1. hackerone_standard (ACTIVE)
2. bugcrowd_preset
3. custom_profile
EOF

    # Validate outputs
    if [[ -f "$program_profiles" ]]; then
        log "INFO" "Program profiles created successfully"
        write_finding "$domain" "PROGRAM_PROFILES" "Program profiles configured" "info" "$output_dir/program_profiles"
    else
        log "ERROR" "Failed to create program profiles"
    fi

    if [[ -f "$active_profile" ]]; then
        log "INFO" "Active profile file created"
        write_asset "$domain" "ACTIVE_PROFILE" "Active program profile documentation" "$output_dir/program_profiles"
    fi

    # Structured logging
    py_log "INFO" "program_profiles" "Phase completed" \
        "domain=$domain" \
        "output_dir=$output_dir/program_profiles" \
        "program_profiles=$program_profiles" \
        "active_profile=$active_profile"

    # Count results
    local result_count=2
    echo "$result_count" > "$output_dir/program_profiles/count.txt"

    log "INFO" "Program profiles phase completed for $domain"
    return 0
}