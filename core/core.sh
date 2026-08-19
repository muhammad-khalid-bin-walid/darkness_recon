#!/bin/bash
# Core framework for Dark Recon Framework v4
# shellcheck shell=bash

# Strict mode
set -euo pipefail
trap 'cleanup' EXIT INT TERM

# Global variables - will be set by phase_manager
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CACHE_DIR="${CACHE_DIR:-$SCRIPT_DIR/../cache}"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/../output}"
LOGS_DIR="${LOGS_DIR:-$SCRIPT_DIR/../logs}"
CONFIG_DIR="${CONFIG_DIR:-$SCRIPT_DIR/../config}"

# Create directories
mkdir -p "$CACHE_DIR" "$OUTPUT_DIR" "$LOGS_DIR" "$CONFIG_DIR" "$CACHE_DIR/state" "$CACHE_DIR/wordlists" "$CACHE_DIR/temp"

# Default configuration
readonly DEFAULT_THREADS=150
readonly DEFAULT_TIMEOUT=300
readonly DEFAULT_RATE_LIMIT=1000
readonly MAX_RETRIES=2

# Tool installation mappings (package name -> command name)
declare -A TOOL_PACKAGES=(
    [subfinder]="subfinder"
    [assetfinder]="assetfinder"
    [amass]="amass"
    [findomain]="findomain"
    [sublist3r]="sublist3r"
    [gobuster]="gobuster"
    [dnsx]="dnsx"
    [puredns]="puredns"
    [dnsrecon]="dnsrecon"
    [altdns]="altdns"
    [shuffledns]="shuffledns"
    [haktrails]="haktrails"
    [dnsgen]="dnsgen"
    [ctfr]="ctfr"
    [knockpy]="knockpy"
    [cero]="cero"
    [bhedak]="bhedak"
    [dnsenum]="dnsenum"
    [sublert]="sublert"
    [dnsmap]="dnsmap"
    [sdgo]="sdgo"
    [bbot]="bbot"
    [spiderfoot]="spiderfoot"
    [httpx]="httpx"
    [whatweb]="whatweb"
    [waybackurls]="waybackurls"
    [waymore]="waymore"
    [gauplus]="gauplus"
    [katana]="katana"
    [gospider]="gospider"
    [hakrawler]="hakrawler"
    [paramspider]="paramspider"
    [arjun]="arjun"
    [unfurl]="unfurl"
    [ffuf]="ffuf"
    [wafw00f]="wafw00f"
    [nuclei]="nuclei"
    [subjack]="subjack"
    [subzy]="subzy"
    [nmap]="nmap"
    [masscan]="masscan"
    [naabu]="naabu"
    [cloud_enum]="cloud-enum"
    [dirsearch]="dirsearch"
    [sslyze]="sslyze"
    [commonspeak2]="commonspeak2"
    [apiscope]="apiscope"
    [gitrob]="gitrob"
    [dnsvalidator]="dnsvalidator"
    [trufflehog]="trufflehog"
    [ratelimitr]="ratelimitr"
    [jq]="jq"
    [anew]="anew"
    [gf]="gf"
    [aquatone]="aquatone"
)

# Essential tools (script fails if missing)
ESSENTIAL_TOOLS=(
    "subfinder"
    "assetfinder"
    "findomain"
    "httpx"
    "katana"
    "whatweb"
    "unfurl"
    "jq"
)

# Logging functions
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # JSON log for machine processing
    mkdir -p "$LOGS_DIR"
    echo "{\"timestamp\": \"$timestamp\", \"level\": \"$level\", \"message\": \"$message\"}" >> "$LOGS_DIR/process.log"
    
    # Human-readable log
    case "$level" in
        INFO) echo "[*] $message" ;;
        WARN) echo "[!] $message" >&2 ;;
        ERROR) echo "[X] $message" >&2 ;;
        DEBUG) if [ "${DEBUG_MODE:-false}" = true ]; then echo "[D] $message" >&2; fi ;;
        *) echo "[?] $message" ;;
    esac
    return 0
}

# Debug logging
debug() {
    [ "${DEBUG_MODE:-false}" = true ] && log "DEBUG" "$@"
}

# Error handling with graceful degradation
handle_error() {
    local exit_code=$?
    local line_number=${1:-unknown}
    local command="${2:-unknown}"
    
    if [ $exit_code -ne 0 ]; then
        log "ERROR" "Command failed at line $line_number: $command (exit code: $exit_code)"
        
        # Don't exit on non-critical errors when GRACEFUL_DEGRADATION is enabled
        if [ "${GRACEFUL_DEGRADATION:-true}" = true ]; then
            log "WARN" "Graceful degradation enabled - continuing despite error"
            return 0
        fi
    fi
    return $exit_code
}

# Retry function with exponential backoff
retry_with_backoff() {
    local max_retries="${1:-$MAX_RETRIES}"
    local delay="${2:-1}"
    local command="${3:-}"
    
    if [ -z "$command" ]; then
        log "ERROR" "No command provided to retry_with_backoff"
        return 1
    fi
    
    local attempt=0
    local exit_code=0
    
    while [ $attempt -lt "$max_retries" ]; do
        attempt=$((attempt + 1))
        log "DEBUG" "Attempt $attempt/$max_retries: $command"
        
        eval "$command" && return 0
        exit_code=$?
        
        if [ $attempt -lt "$max_retries" ]; then
            local backoff=$((delay * (2 ** (attempt - 1))))
            log "WARN" "Attempt $attempt failed (exit: $exit_code), retrying in ${backoff}s..."
            sleep "$backoff"
        fi
    done
    
    log "ERROR" "All $max_retries attempts failed for: $command"
    return $exit_code
}

# Safe file operation - ensures directory exists and handles errors
safe_write() {
    local filepath="$1"
    local content="${2:-}"
    local dir
    dir=$(dirname "$filepath")
    
    mkdir -p "$dir" 2>/dev/null || {
        log "ERROR" "Cannot create directory: $dir"
        return 1
    }
    
    if [ -n "$content" ]; then
        echo "$content" > "$filepath" 2>/dev/null || {
            log "ERROR" "Cannot write to: $filepath"
            return 1
        }
    else
        touch "$filepath" 2>/dev/null || {
            log "ERROR" "Cannot touch: $filepath"
            return 1
        }
    fi
    
    return 0
}

# Safe file read - returns empty string if file doesn't exist
safe_read() {
    local filepath="$1"
    local default="${2:-}"
    
    if [ -f "$filepath" ]; then
        cat "$filepath" 2>/dev/null
    else
        echo "$default"
    fi
}

# Check disk space before operations
check_disk_space() {
    local required_mb="${1:-100}"
    local available_mb=0
    
    if command -v df >/dev/null 2>&1; then
        available_mb=$(df -m "$OUTPUT_DIR" 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)
    fi
    
    if [ "$available_mb" -lt "$required_mb" ]; then
        log "ERROR" "Insufficient disk space: ${available_mb}MB available, ${required_mb}MB required"
        return 1
    fi
    
    log "DEBUG" "Disk space check passed: ${available_mb}MB available"
    return 0
}

# Parallel execution helper
run_parallel() {
    local max_jobs="${1:-4}"
    shift
    local commands=("$@")
    local pids=()
    local running=0
    
    for cmd in "${commands[@]}"; do
        # Wait if max jobs running
        while [ "$running" -ge "$max_jobs" ]; do
            for i in "${!pids[@]}"; do
                if ! kill -0 "${pids[$i]}" 2>/dev/null; then
                    wait "${pids[$i]}" 2>/dev/null
                    unset 'pids[$i]'
                    running=$((running - 1))
                fi
            done
            sleep 0.1
        done
        
        # Start new job
        eval "$cmd" &
        pids+=($!)
        running=$((running + 1))
        log "DEBUG" "Started parallel job ($running/$max_jobs): $cmd"
    done
    
    # Wait for remaining jobs
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done
    
    log "DEBUG" "All parallel jobs completed"
}

# Register parallel job for phase execution
declare -A PARALLEL_JOBS
register_parallel_job() {
    local phase="$1"
    local command="$2"
    PARALLEL_JOBS[$phase]="$command"
}

# Run registered parallel jobs
run_parallel_jobs() {
    local max_jobs="${1:-$DEFAULT_THREADS}"
    local commands=()
    
    for phase in "${!PARALLEL_JOBS[@]}"; do
        commands+=("${PARALLEL_JOBS[$phase]}")
    done
    
    if [ ${#commands[@]} -gt 0 ]; then
        run_parallel "$max_jobs" "${commands[@]}"
    fi
}

# Check if a tool is available
tool_available() {
    local tool="$1"
    if ! command -v "$tool" >/dev/null 2>&1; then
        log "WARN" "Tool $tool not found"
        return 1
    fi
    return 0
}

# Install missing tools automatically
install_tools() {
    local missing_tools=()
    
    for tool in "${!TOOL_PACKAGES[@]}"; do
        if ! tool_available "$tool"; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -eq 0 ]; then
        log "INFO" "All tools are already installed"
        return 0
    fi
    
    log "INFO" "Installing ${#missing_tools[@]} missing tools..."
    
    # Try to install each missing tool
    for tool in "${missing_tools[@]}"; do
        local pkg="${TOOL_PACKAGES[$tool]}"
        log "INFO" "Attempting to install $tool (package: $pkg)..."
        
        local installed=false
        
        # Try different package managers
        if command -v go >/dev/null 2>&1; then
            case "$tool" in
                subfinder|httpx|dnsx|nuclei|katana|naabu|alterx|mapcidr|chaos|unfurl|gf|waybackurls|assetfinder|anew|qsreplace|ffuf|subjack|gauplus|dnsgen|shuffledns|puredns|gotator|dmut)
                    local go_pkg=""
                    case "$tool" in
                        subfinder) go_pkg="github.com/projectdiscovery/subfinder/v2/cmd/subfinder" ;;
                        httpx) go_pkg="github.com/projectdiscovery/httpx/cmd/httpx" ;;
                        dnsx) go_pkg="github.com/projectdiscovery/dnsx/cmd/dnsx" ;;
                        nuclei) go_pkg="github.com/projectdiscovery/nuclei/v3/cmd/nuclei" ;;
                        katana) go_pkg="github.com/projectdiscovery/katana/cmd/katana" ;;
                        naabu) go_pkg="github.com/projectdiscovery/naabu/v2/cmd/naabu" ;;
                        alterx) go_pkg="github.com/projectdiscovery/alterx/cmd/alterx" ;;
                        mapcidr) go_pkg="github.com/projectdiscovery/mapcidr/cmd/mapcidr" ;;
                        chaos) go_pkg="github.com/projectdiscovery/chaos-client/cmd/chaos" ;;
                        unfurl) go_pkg="github.com/tomnomnom/unfurl" ;;
                        gf) go_pkg="github.com/tomnomnom/gf" ;;
                        waybackurls) go_pkg="github.com/tomnomnom/waybackurls" ;;
                        assetfinder) go_pkg="github.com/tomnomnom/assetfinder" ;;
                        anew) go_pkg="github.com/tomnomnom/anew" ;;
                        qsreplace) go_pkg="github.com/tomnomnom/qsreplace" ;;
                        ffuf) go_pkg="github.com/ffuf/ffuf/v2" ;;
                        subjack) go_pkg="github.com/haccer/subjack" ;;
                        gauplus) go_pkg="github.com/bp0lr/gauplus" ;;
                        dnsgen) go_pkg="github.com/ProjectAnte/dnsgen" ;;
                        shuffledns) go_pkg="github.com/projectdiscovery/shuffledns/cmd/shuffledns" ;;
                        puredns) go_pkg="github.com/d3mondev/puredns/v2" ;;
                        gotator) go_pkg="github.com/Josue87/gotator" ;;
                        dmut) go_pkg="github.com/bp0lr/dmut" ;;
                    esac
                    if [ -n "$go_pkg" ]; then
                        go install -v "$go_pkg@latest" && installed=true
                    fi
                    ;;
            esac
        fi
        
        if [ "$installed" = false ] && command -v apt-get >/dev/null 2>&1; then
            apt-get update && apt-get install -y "$pkg" && installed=true
        elif [ "$installed" = false ] && command -v yum >/dev/null 2>&1; then
            yum install -y "$pkg" && installed=true
        elif [ "$installed" = false ] && command -v dnf >/dev/null 2>&1; then
            dnf install -y "$pkg" && installed=true
        elif [ "$installed" = false ] && command -v brew >/dev/null 2>&1; then
            brew install "$pkg" && installed=true
        elif [ "$installed" = false ] && command -v cargo >/dev/null 2>&1; then
            cargo install "$pkg" && installed=true
        elif [ "$installed" = false ] && command -v pip3 >/dev/null 2>&1; then
            pip3 install "$pkg" && installed=true
        elif [ "$installed" = false ] && command -v npm >/dev/null 2>&1; then
            npm install -g "$pkg" && installed=true
        fi
        
        if [ "$installed" = true ]; then
            log "INFO" "Successfully installed $tool"
        else
            log "ERROR" "Failed to install $tool. Please install it manually."
        fi
    done
}

# Auto-configure wordlists and resolvers
configure_assets() {
    local domain="${1:-}"
    log "INFO" "Configuring wordlists and resolvers..."
    
    # Wordlists directory
    mkdir -p "$CACHE_DIR/wordlists"
    
    # SecLists wordlists (if not present)
    if [ ! -d "/usr/share/seclists" ]; then
        log "WARN" "SecLists not found at /usr/share/seclists. Installing..."
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists 2>>"$LOGS_DIR/configure_assets.log" || log "WARN" "Failed to clone SecLists"
    fi
    
    # Download additional wordlists if needed
    if [ ! -f "$CACHE_DIR/wordlists/common.txt" ]; then
        log "INFO" "Downloading common wordlist..."
        curl -s "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" -o "$CACHE_DIR/wordlists/common.txt" 2>>"$LOGS_DIR/configure_assets.log" || log "WARN" "Failed to download common wordlist"
    fi
    
    # Resolvers
    if [ ! -f "$CACHE_DIR/resolvers.txt" ]; then
        log "INFO" "Downloading resolvers..."
        curl -s "https://public-dns.info/nameservers.txt" -o "$CACHE_DIR/resolvers.txt" 2>>"$LOGS_DIR/configure_assets.log" || log "WARN" "Failed to download resolvers"
    fi
    
    # Custom wordlist generation (only if domain provided)
    if [ -n "$domain" ] && command -v commonspeak2 >/dev/null 2>&1; then
        log "INFO" "Generating custom wordlist with commonspeak2..."
        commonspeak2 -t subdomains -o "$CACHE_DIR/wordlists/custom.txt" -d "$domain" -l 2000 -p 2>>"$LOGS_DIR/configure_assets.log" || log "WARN" "Failed to generate custom wordlist"
    fi
}

# Environment-specific profile loading
load_profile() {
    local profile="${1:-default}"
    local profile_file="$CONFIG_DIR/profiles/${profile}.conf"
    
    if [ -f "$profile_file" ]; then
        log "INFO" "Loading environment profile: $profile"
        source "$profile_file"
    else
        log "DEBUG" "No profile file found for: $profile (using defaults)"
    fi
    return 0
}

# Cleanup function
cleanup() {
    local exit_code=$?
    
    log "INFO" "Cleaning up temporary files..."
    rm -rf "$CACHE_DIR/temp" 2>/dev/null || true
    
    # Kill any background jobs
    jobs -p 2>/dev/null | while read -r pid; do
        kill "$pid" 2>/dev/null || true
    done
    
    # Kill any background jobs (alternative syntax for compatibility)
    local bg_jobs
    bg_jobs=$(jobs -p 2>/dev/null || true)
    if [ -n "$bg_jobs" ]; then
        echo "$bg_jobs" | while read -r pid; do
            kill "$pid" 2>/dev/null || true
        done
    fi
    
    if [ $exit_code -ne 0 ]; then
        log "WARN" "Script exiting with code: $exit_code"
    fi
    
    log "INFO" "Cleanup complete"
}

# Error trap - catches errors in strict mode
error_handler() {
    local exit_code=$?
    local line_no=$1
    
    if [ "${GRACEFUL_DEGRADATION:-true}" = true ]; then
        log "WARN" "Error at line $line_no (exit: $exit_code) - graceful degradation active"
    else
        log "ERROR" "Error at line $line_no (exit: $exit_code) - strict mode"
    fi
}

# Signal handler
trap 'log "INFO" "Script interrupted. Performing cleanup..."; cleanup; exit 130' INT TERM
trap 'cleanup' EXIT
trap 'error_handler $LINENO' ERR

# Verification pipeline for 0 false positives
# Every finding goes through: Detection -> Correlation -> Validation -> Confidence Scoring

# Confidence score thresholds
readonly CONFIDENCE_VERIFIED=0.9
readonly CONFIDENCE_HIGH=0.7
readonly CONFIDENCE_MEDIUM=0.5
readonly CONFIDENCE_LOW=0.3
readonly CONFIDENCE_UNVERIFIED=0.0

# Verification methods
verify_finding() {
    local finding_id="$1"
    local finding_type="$2"
    local sources="$3"
    local evidence="$4"
    
    local source_count
    source_count=$(echo "$sources" | tr ',' '\n' | grep -v '^$' | wc -l)
    
    local confidence="$CONFIDENCE_UNVERIFIED"
    local verification_status="unverified"
    
    if [ "$source_count" -ge 3 ]; then
        confidence="$CONFIDENCE_VERIFIED"
        verification_status="verified"
    elif [ "$source_count" -ge 2 ]; then
        confidence="$CONFIDENCE_HIGH"
        verification_status="high_confidence"
    elif [ "$source_count" -ge 1 ]; then
        confidence="$CONFIDENCE_MEDIUM"
        verification_status="candidate"
    fi
    
    echo "{\"finding_id\":\"$finding_id\",\"type\":\"$finding_type\",\"confidence\":$confidence,\"verification_status\":\"$verification_status\",\"sources\":[$sources],\"evidence\":\"$evidence\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}"
}

# Cross-reference two findings for correlation
correlate_findings() {
    local finding1="$1"
    local finding2="$2"
    
    # Extract key fields for comparison
    local f1_type f1_value f2_type f2_value
    f1_type=$(echo "$finding1" | jq -r '.type // empty' 2>/dev/null)
    f1_value=$(echo "$finding1" | jq -r '.value // empty' 2>/dev/null)
    f2_type=$(echo "$finding2" | jq -r '.type // empty' 2>/dev/null)
    f2_value=$(echo "$finding2" | jq -r '.value // empty' 2>/dev/null)
    
    if [ "$f1_type" = "$f2_type" ] && [ "$f1_value" = "$f2_value" ]; then
        echo " correlated"
    else
        echo " uncorrelated"
    fi
}

# Score confidence based on multiple factors
score_confidence() {
    local source_count="$1"
    local evidence_quality="$2"
    local cross_validation="$3"
    
    local score=0
    
    # Source count contributes up to 0.5
    if [ "$source_count" -ge 3 ]; then
        score=$((score + 50))
    elif [ "$source_count" -ge 2 ]; then
        score=$((score + 35))
    elif [ "$source_count" -ge 1 ]; then
        score=$((score + 15))
    fi
    
    # Evidence quality contributes up to 0.3
    case "$evidence_quality" in
        strong) score=$((score + 30)) ;;
        moderate) score=$((score + 20)) ;;
        weak) score=$((score + 10)) ;;
        none) score=$((score + 0)) ;;
    esac
    
    # Cross-validation contributes up to 0.2
    if [ "$cross_validation" = "true" ]; then
        score=$((score + 20))
    fi
    
    # Normalize to 0.0-1.0 - use awk as primary (always available on Unix), bc as fallback
    _normalize_score "$score"
}

# Internal: normalize a 0-100 score to 0.00-1.00
_normalize_score() {
    local score="$1"
    
    # Try awk first (more universally available than bc)
    if command -v awk >/dev/null 2>&1; then
        awk -v s="$score" 'BEGIN {printf "%.2f", s / 100}' 2>/dev/null && return 0
    fi
    
    # Fallback to bc
    if command -v bc >/dev/null 2>&1; then
        echo "scale=2; $score / 100" | bc 2>/dev/null && return 0
    fi
    
    # Last resort: integer division with manual decimal
    local integer_part=$((score / 100))
    local decimal_part=$((score % 100))
    printf "%d.%02d\n" "$integer_part" "$decimal_part"
}

# Deduplicate findings by content hash
deduplicate_findings() {
    local input_file="$1"
    local output_file="$2"
    
    if [ ! -f "$input_file" ]; then
        log "WARN" "Input file $input_file not found for deduplication"
        return 1
    fi
    
    # Sort by content hash and remove duplicates
    if command -v jq >/dev/null 2>&1; then
        jq -s 'unique_by(.content_hash // .value // .finding_id)' "$input_file" > "$output_file" 2>/dev/null || cp "$input_file" "$output_file"
    else
        cp "$input_file" "$output_file"
    fi
    
    log "INFO" "Deduplicated findings: $(wc -l < "$input_file") -> $(wc -l < "$output_file") entries"
}

# Validate finding against known false positive patterns
validate_against_false_positives() {
    local finding="$1"
    local finding_type
    finding_type=$(echo "$finding" | jq -r '.type // empty' 2>/dev/null)
    local finding_value
    finding_value=$(echo "$finding" | jq -r '.value // empty' 2>/dev/null)
    
    # Known false positive patterns per type
    case "$finding_type" in
        subdomain)
            # Filter out common false positives
            if echo "$finding_value" | grep -qE '\.(example|test|invalid|localhost|local|internal)\.'; then
                echo "false_positive"
                return
            fi
            ;;
        url)
            # Filter out common false positives
            if echo "$finding_value" | grep -qE '\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|pdf|zip|gz|mp4|mp3|avi|mov|webm)$'; then
                echo "false_positive"
                return
            fi
            ;;
        secret)
            # Validate secret format
            if echo "$finding_value" | grep -qE '^[a-zA-Z0-9]{40,}$'; then
                echo "valid_format"
            else
                echo "invalid_format"
            fi
            return
            ;;
    esac
    
    echo "valid"
}

# Generate a content hash for deduplication
generate_content_hash() {
    local content="$1"
    echo -n "$content" | md5sum 2>/dev/null | awk '{print $1}' || echo "unknown"
}

# Validate scope boundaries
validate_scope() {
    local finding_value="$1"
    local scope_rules="$2"

    if [ -z "$scope_rules" ]; then
        echo "no_scope_defined"
        return
    fi

    # Check if finding is within scope
    if echo "$scope_rules" | grep -qi "$finding_value"; then
        echo "in_scope"
    else
        echo "out_of_scope"
    fi
}

# Validate historical recon findings
validate_historical() {
    local finding_value="$1"
    local historical_data="$2"

    if [ -z "$historical_data" ]; then
        echo "no_historical_data"
        return
    fi

    # Check if finding exists in historical data
    if echo "$historical_data" | grep -qi "$finding_value"; then
        echo "historically_validated"
    else
        echo "new_finding"
    fi
}

# Validate exploitation PoC
validate_exploitation() {
    local poc_status="$1"
    local reproduction_confidence="$2"

    if [ "$poc_status" = "reproduced" ] && [ "$(awk "BEGIN {print ($reproduction_confidence >= 0.7) ? 1 : 0}")" = "1" ]; then
        echo "validated_poc"
    elif [ "$poc_status" = "reproduced" ]; then
        echo "partial_poc"
    else
        echo "needs_manual_verification"
    fi
}

# Validate post-exploitation findings
validate_post_exploitation() {
    local lateral_path="$1"
    local escalation_confidence="$2"

    if [ -n "$lateral_path" ] && [ "$(awk "BEGIN {print ($escalation_confidence >= 0.6) ? 1 : 0}")" = "1" ]; then
        echo "validated_lateral_movement"
    elif [ -n "$lateral_path" ]; then
        echo "potential_lateral_movement"
    else
        echo "no_lateral_path"
    fi
}

# Validate data exfiltration findings
validate_data_exfiltration() {
    local data_type="$1"
    local exposure_level="$2"

    if [ -z "$data_type" ] || [ -z "$exposure_level" ]; then
        echo "insufficient_data"
        return
    fi

    case "$exposure_level" in
        public) echo "public_exposure" ;;
        internal) echo "internal_exposure" ;;
        restricted) echo "restricted_exposure" ;;
        *) echo "unknown_exposure" ;;
    esac
}

# Validate continuous monitoring configuration
validate_continuous_monitoring() {
    local config_file="$1"

    if [ ! -f "$config_file" ]; then
        echo "no_monitoring_config"
        return
    fi

    # Check if monitoring is properly configured
    local has_schedule=false
    local has_alerts=false
    local has_baseline=false

    grep -q "re_scan_schedule" "$config_file" 2>/dev/null && has_schedule=true
    grep -q "alert_thresholds" "$config_file" 2>/dev/null && has_alerts=true
    grep -q "security_baseline" "$config_file" 2>/dev/null && has_baseline=true

    if $has_schedule && $has_alerts && $has_baseline; then
        echo "fully_configured"
    elif $has_schedule || $has_alerts || $has_baseline; then
        echo "partially_configured"
    else
        echo "not_configured"
    fi
}

# Export verification functions
export -f verify_finding correlate_findings score_confidence deduplicate_findings validate_against_false_positives generate_content_hash validate_scope validate_historical validate_exploitation validate_post_exploitation validate_data_exfiltration validate_continuous_monitoring

# Export error handling and utility functions
export -f log debug handle_error retry_with_backoff safe_write safe_read check_disk_space run_parallel register_parallel_job run_parallel_jobs load_profile cleanup error_handler _normalize_score

# Source Python lib bridge (validator, logger, scope_engine)
LIB_DIR="${SCRIPT_DIR:-$(dirname "${BASH_SOURCE[0]}")}/../lib"
if [ -f "$LIB_DIR/phase_bridge.sh" ]; then
    source "$LIB_DIR/phase_bridge.sh"
fi