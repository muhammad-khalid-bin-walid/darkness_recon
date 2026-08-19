#compdef dark_recon

# zsh completion for dark_recon                              -*- shell-script -*-

_dark_recon() {
    local -a commands phases tracks
    local curcontext="$curcontext" state line

    commands=(
        'scan:Run a reconnaissance scan against a target'
        'report:Generate or view scan reports'
        'config:View or modify framework configuration'
        'status:Show scan status and progress'
        'list-phases:List all available phases and their status'
    )

    tracks=(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21)

    phases=(
        'subdomains:Subdomain enumeration (T0)'
        'dns:DNS record analysis (T0)'
        'live:Live host detection (T0)'
        'tech:Technology fingerprinting (T0)'
        'crawl:URL and endpoint discovery (T0)'
        'params:Parameter discovery (T0)'
        'fuzz:Directory and fuzzing (T0)'
        'takeovers:Subdomain takeover detection (T0)'
        'waf:WAF detection (T1)'
        'nuclei:Template vulnerability scanning (T1)'
        'ports:Port scanning (T1)'
        'ssl:SSL/TLS analysis (T1)'
        'api:API endpoint discovery (T3)'
        'git:Git repository scanning (T1)'
        'secrets:Secret detection (T1)'
        'screenshots:Visual reconnaissance (T1)'
        'patterns:Pattern matching (T1)'
        'asn_pivot:ASN pivot discovery (T2)'
        'cloud_asset:Cloud asset discovery (T2)'
        'origin_ip:Origin IP discovery (T2)'
        'cert_transparency:Certificate transparency (T2)'
        'openapi_ingest:OpenAPI spec ingestion (T3)'
        'graphql_abuse:GraphQL abuse testing (T3)'
        'waf_bypass:WAF bypass techniques (T3)'
        'cloud:Cloud security assessment (T5)'
        'cicd_config:CI/CD config scanning (T5)'
        'vuln:Vulnerability scanning (T6)'
        'service:Service enumeration (T6)'
        'exploitation_validation:PoC validation (T6)'
        'reporting:Report aggregation (T8)'
        'ml_analysis:ML anomaly detection (T9)'
        'compliance:Compliance scanning (T9)'
    )

    _arguments -C \
        '1:command:->command' \
        '*::arg:->args' \
        && return

    case "$state" in
        command)
            _describe 'command' commands
            ;;
        args)
            case $line[1] in
                scan)
                    _arguments \
                        '--target=[Target domain]:domain:' \
                        '--track=[Filter by track]:track:(' $tracks ')' \
                        '--phase=[Run specific phase]:phase:(' $phases ')' \
                        '--output=[Output directory]:directory:_files -/' \
                        '--profile=[Environment profile]:profile:(default dev staging prod)' \
                        '--jobs=[Parallel job count]:count:(1 2 4 8 16)' \
                        '--resume=[Resume from phase]:phase:(' $phases ')' \
                        '--skip=[Skip a phase]:phase:(' $phases ')' \
                        '--fast[Fast mode: skip optional phases]' \
                        '--deep[Deep mode: run all phases]' \
                        '--quiet[Quiet output]' \
                        '--json[JSON output]' \
                        '--parallel[Enable parallel execution]' \
                        '--install[Install missing tools]' \
                        '--help[Show help]' \
                        '--version[Show version]'
                    ;;
                report)
                    _arguments \
                        '--target=[Target domain]:domain:' \
                        '--output=[Output directory]:directory:_files -/' \
                        '--json[JSON output]' \
                        '--help[Show help]'
                    ;;
                config)
                    _arguments \
                        '--show[Show current config]' \
                        '--set=[Set config key]:key:' \
                        '--help[Show help]'
                    ;;
                status)
                    _arguments \
                        '--target=[Target domain]:domain:' \
                        '--help[Show help]'
                    ;;
                list-phases)
                    _arguments \
                        '--track=[Filter by track]:track:(' $tracks ')' \
                        '--all[Show all phases including disabled]' \
                        '--help[Show help]'
                    ;;
            esac
            ;;
    esac
}

_dark_recon "$@"
