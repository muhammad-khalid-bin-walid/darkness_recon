#!/usr/bin/env bash
# Phase 290: Man Page Generation, Documentation Formatting, Help System
# Track 20 - UX/CLI

ux_man_page() {
    local domain="${1:?Usage: ux_man_page <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/ux_man_page"
    mkdir -p "$phase_dir/man_pages"

    log "INFO" "[MAN_PAGE] Generating man pages for $domain"

    local help_index="$phase_dir/help_index.txt"

    local count=0

    cat > "$phase_dir/man_pages/darkrecon.1" <<'MANEOF'
.TH DARKRECON 1 "2026-08-06" "DarkRecon" "User Commands"
.SH NAME
darkrecon \- automated security reconnaissance framework
.SH SYNOPSIS
.B darkrecon
.RI [ options ]
.I domain
.SH DESCRIPTION
.B DarkRecon
is a comprehensive security reconnaissance framework organized into phases.
It performs automated scanning, analysis, and reporting for target domains.
.SH OPTIONS
.TP
.BI \-\-domain " domain"
Target domain to scan.
.TP
.BI \-\-output " dir"
Output directory for results.
.TP
.B \-\-verbose
Enable verbose output.
.TP
.B \-\-debug
Enable debug mode with detailed logging.
.TP
.B \-\-dry-run
Preview execution without actual scanning.
.TP
.BI \-\-profile " name"
Scan profile: quick, standard, thorough, custom.
.TP
.B \-\-help
Show help message.
.SH PHASES
DarkRecon organizes work into tracks:
.TP
.B Track 1 (1-50)
Reconnaissance phases.
.TP
.B Track 2 (51-100)
Scanning phases.
.TP
.B Track 3 (101-150)
Analysis phases.
.TP
.B Track 4 (151-200)
Reporting phases.
.TP
.B Track 18 (261-270)
Compliance phases.
.TP
.B Track 19 (271-280)
Collaboration phases.
.TP
.B Track 20 (281-290)
UX/CLI phases.
.TP
.B Track 21 (291-300)
Documentation phases.
.SH EXIT STATUS
.TP
.B 0
Success.
.TP
.B 1
General error.
.TP
.B 2
Usage error.
.SH EXAMPLES
.TP
.B darkrecon example.com
Run full scan on example.com.
.TP
.B darkrecon \-\-dry\-run example.com
Preview scan without execution.
.SH AUTHOR
DarkRecon Team
MANEOF
    count=$((count + 1))

    cat > "$phase_dir/man_pages/darkrecon-compliance.1" <<'MANEOF'
.TH DARKRECON-COMPLIANCE 1 "2026-08-06" "DarkRecon" "User Commands"
.SH NAME
darkrecon-compliance \- compliance checking commands
.SH SYNOPSIS
.B darkrecon compliance
.RI { pci | gdpr | soc2 | asvs | audit-export | policy-as-code }
.SH DESCRIPTION
Compliance-related phases for regulatory verification.
.SH COMMANDS
.TP
.B pci
PCI-DSS compliance checking.
.TP
.B gdpr
GDPR compliance verification.
.TP
.B soc2
SOC2 control mapping.
.TP
.B asvs
ASVS requirement mapping.
.TP
.B audit-export
Generate audit evidence package.
.TP
.B policy-as-code
Automated compliance checks.
MANEOF
    count=$((count + 1))

    log "INFO" "[MAN_PAGE] Generating help index"
    {
        echo "=== Help Index ==="
        echo "Domain: $domain"
        echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "Man Pages Generated:"
        echo "  [OK] darkrecon.1 - Main command reference"
        echo "  [OK] darkrecon-compliance.1 - Compliance commands"
        echo ""
        echo "Quick Reference:"
        echo "  darkrecon --help              Show main help"
        echo "  darkrecon --version           Show version"
        echo "  darkrecon <domain>            Run full scan"
        echo "  darkrecon --dry-run <domain>  Preview scan"
        echo ""
        echo "Installation:"
        echo "  man ./man_pages/darkrecon.1"
        echo "  or copy to /usr/local/share/man/man1/"
        echo ""
        echo "Documentation Sections:"
        echo "  NAME, SYNOPSIS, DESCRIPTION, OPTIONS,"
        echo "  PHASES, EXIT STATUS, EXAMPLES, AUTHOR"
    } > "$help_index"
    count=$((count + 1))

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_finding "$phase_dir" "MAN" "Man pages generated" "info" "info"

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "man_page_complete" "Man page generation complete: $count items"
    log "INFO" "[MAN_PAGE] Completed: $count items generated"

    return 0
}
