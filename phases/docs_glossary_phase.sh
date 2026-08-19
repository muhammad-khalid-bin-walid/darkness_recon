#!/usr/bin/env bash
# Phase 298: Glossary of Terms, Terminology Standardization, Reference Guide
# Track 21 - Documentation

docs_glossary() {
    local domain="${1:?Usage: docs_glossary <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/docs_glossary"
    mkdir -p "$phase_dir"

    log "INFO" "[GLOSSARY] Generating glossary for $domain"

    local glossary="$phase_dir/glossary.md"
    local terminology="$phase_dir/terminology.txt"

    local count=0

    cat > "$glossary" <<'GLEOF'
# DarkRecon Glossary

## A

**ASVS** - Application Security Verification Standard. OWASP standard for verifying web application security.

**Asset** - A discovered resource (domain, IP, service) found during reconnaissance.

## C

**Compliance** - Adherence to regulatory requirements (PCI-DSS, GDPR, SOC2).

**Core** - The core.sh module providing logging, tool checks, and utilities.

## D

**DarkRecon** - The security reconnaissance framework organized into phases and tracks.

**Dry Run** - Preview execution without performing actual scanning.

## E

**Endpoint** - A discovered URL or API endpoint.

**Evidence** - Collected data supporting a finding or compliance status.

## F

**Finding** - A security observation or vulnerability discovered during scanning.

## G

**GDPR** - General Data Protection Regulation. EU data privacy law.

## H

**Handoff** - Documentation and context transfer between operators.

## I

**Interactive Mode** - Guided scanning with user prompts.

## L

**Log** - Structured output from phase execution.

## M

**Methodology** - Documented approach for performing specific scan types.

## O

**OSINT** - Open Source Intelligence. Information gathered from public sources.

## P

**PCI-DSS** - Payment Card Industry Data Security Standard.

**Phase** - A single unit of work within a track.

**Plugin** - An extension module for DarkRecon.

## R

**RBAC** - Role-Based Access Control.

**Recon** - Short for reconnaissance. Initial information gathering.

## S

**SOC2** - Service Organization Control 2. Trust service criteria framework.

**STRIDE** - Threat modeling framework: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.

## T

**Track** - A collection of related phases (e.g., Reconnaissance, Scanning).

**TUI** - Terminal User Interface. Rich terminal-based display.
GLEOF
    count=$((count + 1))

    log "INFO" "[GLOSSARY] Generating terminology reference"
    {
        echo "=== Terminology Reference ==="
        echo "Domain: $domain"
        echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "Core Terms:"
        echo "  Phase: Single unit of work"
        echo "  Track: Collection of related phases"
        echo "  Finding: Security observation"
        echo "  Asset: Discovered resource"
        echo "  Endpoint: Discovered URL"
        echo ""
        echo "Compliance Terms:"
        echo "  ASVS: Application Security Verification Standard"
        echo "  PCI-DSS: Payment Card Industry Data Security Standard"
        echo "  SOC2: Service Organization Control 2"
        echo "  GDPR: General Data Protection Regulation"
        echo ""
        echo "Collaboration Terms:"
        echo "  RBAC: Role-Based Access Control"
        echo "  Handoff: Context transfer between operators"
        echo "  Workload: Task distribution across operators"
        echo ""
        echo "UX/CLI Terms:"
        echo "  TUI: Terminal User Interface"
        echo "  Dry Run: Preview without execution"
        echo "  Interactive Mode: Guided scanning"
        echo ""
        echo "Threat Modeling Terms:"
        echo "  STRIDE: Spoofing, Tampering, Repudiation, Info Disclosure, DoS, EoP"
        echo "  Risk Assessment: Threat impact evaluation"
    } > "$terminology"
    count=$((count + 1))

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_finding "$phase_dir" "GLOSSARY" "Glossary generated" "info" "info"

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "glossary_complete" "Glossary complete: $count items"
    log "INFO" "[GLOSSARY] Completed: $count items generated"

    return 0
}
