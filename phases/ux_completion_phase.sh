#!/usr/bin/env bash
# Phase 286: Shell Completion (bash/zsh/fish), Command Suggestions, Tab Completion
# Track 20 - UX/CLI

ux_completion() {
    local domain="${1:?Usage: ux_completion <domain>}"

    source "$(dirname "$0")/../core/core.sh"

    local output_dir="$OUTPUT_DIR/$domain/recon_$TIMESTAMP"
    local phase_dir="$output_dir/ux_completion"
    mkdir -p "$phase_dir/completion_scripts"

    log "INFO" "[COMPLETION] Generating shell completion scripts for $domain"

    local completion_status="$phase_dir/completion_status.txt"

    local count=0

    cat > "$phase_dir/completion_scripts/darkrecon.bash" <<'BASHEOF'
#!/usr/bin/env bash
# DarkRecon Bash Completion

_darkrecon_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local commands="recon scan analyze report compliance collab ux docs"
    local domains=""
    local flags="--domain --output --verbose --debug --dry-run --profile --help"

    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=($(compgen -W "$commands" -- "$cur"))
    elif [ "$COMP_CWORD" -eq 2 ]; then
        COMPREPLY=($(compgen -W "$domains $flags" -- "$cur"))
    else
        COMPREPLY=($(compgen -W "$flags" -- "$cur"))
    fi
}

complete -F _darkrecon_completions darkrecon
BASHEOF
    count=$((count + 1))

    cat > "$phase_dir/completion_scripts/darkrecon.zsh" <<'ZSHEOF'
# DarkRecon Zsh Completion

_darkrecon() {
    local commands=(recon scan analyze report compliance collab ux docs)
    local flags=(--domain --output --verbose --debug --dry-run --profile --help)

    _arguments \
        '1:command:->command' \
        '*:: :->args'

    case $state in
        command)
            _describe 'command' commands
            ;;
        args)
            _arguments \
                '--domain[Target domain]:domain:_hosts' \
                '--output[Output directory]:directory:_directories' \
                '--verbose[Enable verbose output]' \
                '--debug[Enable debug mode]' \
                '--dry-run[Preview without execution]' \
                '--profile[Scan profile]:profile:(quick standard thorough custom)' \
                '--help[Show help]'
            ;;
    esac
}

_darkrecon "$@"
ZSHEOF
    count=$((count + 1))

    cat > "$phase_dir/completion_scripts/darkrecon.fish" <<'FISHEOF'
# DarkRecon Fish Completion

complete -c darkrecon -f
complete -c darkrecon -n '__fish_use_subcommand' -a 'recon' -d 'Reconnaissance phase'
complete -c darkrecon -n '__fish_use_subcommand' -a 'scan' -d 'Scanning phase'
complete -c darkrecon -n '__fish_use_subcommand' -a 'analyze' -d 'Analysis phase'
complete -c darkrecon -n '__fish_use_subcommand' -a 'report' -d 'Report generation'
complete -c darkrecon -n '__fish_use_subcommand' -a 'compliance' -d 'Compliance checks'
complete -c darkrecon -n '__fish_use_subcommand' -a 'collab' -d 'Collaboration tools'
complete -c darkrecon -n '__fish_use_subcommand' -a 'ux' -d 'UX/CLI features'
complete -c darkrecon -n '__fish_use_subcommand' -a 'docs' -d 'Documentation'

complete -c darkrecon -l domain -d 'Target domain'
complete -c darkrecon -l output -d 'Output directory'
complete -c darkrecon -l verbose -d 'Enable verbose output'
complete -c darkrecon -l debug -d 'Enable debug mode'
complete -c darkrecon -l dry-run -d 'Preview without execution'
complete -c darkrecon -l profile -d 'Scan profile'
complete -c darkrecon -l help -d 'Show help'
FISHEOF
    count=$((count + 1))

    log "INFO" "[COMPLETION] Generating completion status"
    {
        echo "=== Shell Completion Status ==="
        echo "Domain: $domain"
        echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo ""
        echo "Generated Scripts:"
        echo "  [OK] darkrecon.bash - Bash completion"
        echo "  [OK] darkrecon.zsh  - Zsh completion"
        echo "  [OK] darkrecon.fish - Fish completion"
        echo ""
        echo "Installation:"
        echo "  Bash: source completion_scripts/darkrecon.bash"
        echo "  Zsh:  source completion_scripts/darkrecon.zsh"
        echo "  Fish: cp completion_scripts/darkrecon.fish ~/.config/fish/completions/"
        echo ""
        echo "Commands Supported:"
        echo "  recon, scan, analyze, report, compliance, collab, ux, docs"
        echo ""
        echo "Flags Supported:"
        echo "  --domain, --output, --verbose, --debug, --dry-run, --profile, --help"
    } > "$completion_status"
    count=$((count + 1))

    write_asset "$phase_dir" "domain" "$domain" "target"
    write_finding "$phase_dir" "COMPLETION" "Shell completion scripts generated" "info" "info"

    echo "$count" > "$phase_dir/count.txt"
    py_log "INFO" "completion_complete" "Shell completion complete: $count items"
    log "INFO" "[COMPLETION] Completed: $count items generated"

    return 0
}
