#!/bin/bash
# run.sh - Dark Recon Framework v4 Runner
# Convenience script to run the framework with common configurations

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRAMEWORK_DIR="${SCRIPT_DIR}"
MAIN_SCRIPT="${FRAMEWORK_DIR}/dark_recon_framework.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Print banner
print_banner() {
    echo -e "${MAGENTA}"
    echo "===================================================================="
    echo "          Dark Recon Framework 1.0.1 - Made by DarkLegende"
    echo "===================================================================="
    echo -e "${NC}"
}

# Usage
usage() {
    print_banner
    echo "Usage: $0 <domain> [options]"
    echo ""
    echo "Options:"
    echo "  --profile <name>    Environment profile (dev|staging|prod) [default: staging]"
    echo "  --mode <name>       Quick mode (fast|deep) [default: fast]"
    echo "  --parallel          Enable parallel phase execution"
    echo "  --install           Install missing tools before running"
    echo "  --docker            Run inside Docker container"
    echo "  --compose <svc>     Run via docker-compose (scan|dev|staging|prod|worker)"
    echo "  --help              Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 example.com                           # Fast scan with staging profile"
    echo "  $0 example.com --profile prod --parallel # Full production scan with parallel execution"
    echo "  $0 example.com --mode deep               # Deep scan (all phases)"
    echo "  $0 example.com --docker                  # Run in Docker"
    echo "  $0 example.com --compose prod            # Run via docker-compose (production)"
    echo "  $0 --install                             # Install tools only"
    echo ""
    echo "Environment variables:"
    echo "  SHODAN_API_KEY       Shodan API key for OSINT"
    echo "  CENSYS_API_ID        Censys API ID"
    echo "  CENSYS_API_SECRET    Censys API secret"
    echo "  SECURITYTRAILS_API_KEY SecurityTrails API key"
    echo "  WEBHOOK_URL          Webhook URL for notifications"
    echo "  DOMAIN               Target domain (alternative to positional arg)"
    echo ""
}

# Run with profile and mode
run_local() {
    local domain="$1"
    local profile="${2:-staging}"
    local mode="${3:-fast}"
    local parallel="${4:-false}"

    local args=("$domain" "--profile" "$profile")

    case "$mode" in
        deep)
            args+=("--deep")
            ;;
        fast|*)
            args+=("--fast")
            ;;
    esac

    if [ "$parallel" = "true" ]; then
        args+=("--parallel")
    fi

    echo -e "${GREEN}[*] Running Dark Recon Framework locally${NC}"
    echo -e "${CYAN}[*] Domain: $domain${NC}"
    echo -e "${CYAN}[*] Profile: $profile${NC}"
    echo -e "${CYAN}[*] Mode: $mode${NC}"
    echo -e "${CYAN}[*] Parallel: $parallel${NC}"
    echo ""

    cd "$FRAMEWORK_DIR" && exec ./dark_recon_framework.sh "${args[@]}"
}

# Run with Docker
run_docker() {
    local domain="$1"
    local profile="${2:-staging}"

    echo -e "${GREEN}[*] Running Dark Recon Framework in Docker${NC}"
    echo -e "${CYAN}[*] Domain: $domain${NC}"
    echo -e "${CYAN}[*] Profile: $profile${NC}"
    echo ""

    cd "$FRAMEWORK_DIR" && docker run --rm \
        -v "$(pwd)/output:/app/output" \
        -v "$(pwd)/cache:/app/cache" \
        -v "$(pwd)/logs:/app/logs" \
        -v "$(pwd)/config:/app/config:ro" \
        -e DOMAIN="$domain" \
        -e ENV_PROFILE="$profile" \
        -e SHODAN_API_KEY="${SHODAN_API_KEY:-}" \
        -e CENSYS_API_ID="${CENSYS_API_ID:-}" \
        -e CENSYS_API_SECRET="${CENSYS_API_SECRET:-}" \
        -e SECURITYTRAILS_API_KEY="${SECURITYTRAILS_API_KEY:-}" \
        -e WEBHOOK_URL="${WEBHOOK_URL:-}" \
        --cap-add=NET_ADMIN \
        --cap-add=NET_RAW \
        --security-opt=no-new-privileges:true \
        dark-recon-framework:latest \
        "$domain" --profile "$profile"
}

# Run with docker-compose
run_compose() {
    local domain="$1"
    local service="${2:-scan}"

    echo -e "${GREEN}[*] Running Dark Recon Framework via docker-compose${NC}"
    echo -e "${CYAN}[*] Domain: $domain${NC}"
    echo -e "${CYAN}[*] Service: $service${NC}"
    echo ""

    cd "$FRAMEWORK_DIR" && DOMAIN="$domain" ENV_PROFILE="$service" docker compose up --build "$service"
}

# Install tools
install_tools() {
    echo -e "${GREEN}[*] Installing tools...${NC}"
    cd "$FRAMEWORK_DIR" && exec ./dark_recon_framework.sh --install
}

# Check prerequisites
check_prerequisites() {
    if [ ! -f "$MAIN_SCRIPT" ]; then
        echo -e "${RED}[X] Framework not found at $MAIN_SCRIPT${NC}"
        exit 1
    fi

    if [ ! -x "$MAIN_SCRIPT" ]; then
        chmod +x "$MAIN_SCRIPT"
    fi
}

# Main
main() {
    check_prerequisites

    if [ $# -eq 0 ]; then
        usage
        exit 0
    fi

    local domain=""
    local profile="staging"
    local mode="fast"
    local parallel="false"
    local use_docker="false"
    local use_compose=""
    local do_install="false"

    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --help|-h)
                usage
                exit 0
                ;;
            --version)
                echo "Dark Recon Framework 1.0.1"
                exit 0
                ;;
            --profile)
                profile="$2"
                shift 2
                ;;
            --mode)
                mode="$2"
                shift 2
                ;;
            --parallel)
                parallel="true"
                shift
                ;;
            --install)
                do_install="true"
                shift
                ;;
            --docker)
                use_docker="true"
                shift
                ;;
            --compose)
                use_compose="$2"
                shift 2
                ;;
            -*)
                echo -e "${RED}[X] Unknown option: $1${NC}"
                usage
                exit 1
                ;;
            *)
                if [ -z "$domain" ]; then
                    domain="$1"
                else
                    echo -e "${RED}[X] Multiple domains specified${NC}"
                    usage
                    exit 1
                fi
                shift
                ;;
        esac
    done

    # Handle install-only
    if [ "$do_install" = "true" ]; then
        install_tools
        exit 0
    fi

    # Validate domain
    if [ -z "$domain" ]; then
        if [ -n "${DOMAIN:-}" ]; then
            domain="$DOMAIN"
        else
            echo -e "${RED}[X] Domain is required${NC}"
            usage
            exit 1
        fi
    fi

    # Validate profile
    case "$profile" in
        dev|staging|prod) ;;
        *)
            echo -e "${RED}[X] Invalid profile: $profile (must be dev|staging|prod)${NC}"
            exit 1
            ;;
    esac

    # Run
    if [ -n "$use_compose" ]; then
        run_compose "$domain" "$use_compose"
    elif [ "$use_docker" = "true" ]; then
        run_docker "$domain" "$profile"
    else
        run_local "$domain" "$profile" "$mode" "$parallel"
    fi
}

main "$@"