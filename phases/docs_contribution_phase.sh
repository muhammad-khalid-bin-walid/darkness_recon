#!/usr/bin/env bash
# Phase 296: Contribution Guidelines, Development Setup, Coding Standards
# Track 21 - Documentation

docs_contribution() {
    local domain="${1:?Usage: docs_contribution <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/docs_contribution"
    mkdir -p "$phase_dir"

    log "INFO" "[CONTRIB] Generating contribution guidelines for $domain"

    local contribution_guide="$phase_dir/contribution_guide.md"
    local dev_setup="$phase_dir/dev_setup.txt"

    local count=0

    cat > "$contribution_guide" <<'CGEOF'
# Contribution Guidelines

## Getting Started

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Development Setup

```bash
# Clone the repository
git clone <repo-url>
cd dark_recon_framework

# Verify tools
tool_available "bash"
tool_available "curl"
tool_available "nmap"

# Set output directory
export OUTPUT_DIR="./output"
```

## Coding Standards

### Phase Scripts
- Name: `<category>_<name>_phase.sh`
- Function: `<category>_<name>()`
- Accept domain as first argument
- Source core.sh at start
- Use log "INFO" for logging
- Use tool_available for checks
- Write count.txt at end
- Handle errors with `|| true`

### Output Functions
- write_finding: Document security findings
- write_asset: Document discovered assets
- write_endpoint: Document endpoints

### Testing
- Test with --dry-run first
- Verify count.txt accuracy
- Check output directory structure

## Pull Request Process

1. Ensure all phases pass
2. Update documentation
3. Add changelog entry
4. Request review
5. Address feedback
6. Merge

## Code Review Checklist

- [ ] Phase follows naming convention
- [ ] Error handling is graceful
- [ ] Output uses phase_bridge functions
- [ ] count.txt is accurate
- [ ] Documentation is updated
CGEOF
    count=$((count + 1))

    log "INFO" "[CONTRIB] Generating dev setup guide"
    {
        echo "=== Development Setup ==="
        echo "Domain: $domain"
        echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "Prerequisites:"
        echo "  - bash 4.0+"
        echo "  - curl"
        echo "  - nmap (optional)"
        echo "  - openssl (optional)"
        echo "  - python3 (optional)"
        echo ""
        echo "Setup Steps:"
        echo "  1. Clone repository"
        echo "  2. Verify tool availability"
        echo "  3. Set OUTPUT_DIR"
        echo "  4. Run test scan"
        echo ""
        echo "Environment Variables:"
        echo "  OUTPUT_DIR: Output directory path"
        echo "  TIMESTAMP: Scan identifier"
        echo ""
        echo "Testing:"
        echo "  - Use --dry-run for preview"
        echo "  - Verify count.txt in each phase"
        echo "  - Check output directory structure"
    } > "$dev_setup"
    count=$((count + 1))

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_finding "$phase_dir" "CONTRIB" "Contribution guidelines generated" "info" "info"

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "contribution_complete" "Contribution guidelines complete: $count items"
    log "INFO" "[CONTRIB] Completed: $count items generated"

    return 0
}
