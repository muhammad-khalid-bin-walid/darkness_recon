# fish completion for dark_recon                              -*- shell-script -*-

# Helper: list phase names
function __dark_recon_phases
    echo -e "subdomains\tdns\tlive\ttech\tcrawl\tparams\tfuzz\ttakeovers"
    echo -e "waf\tnuclei\tports\tssl\tapi\tgit\tsecrets\tscreenshots\tpatterns"
    echo -e "asn_pivot\tcloud_asset\torigin_ip\tcert_transparency"
    echo -e "openapi_ingest\tgraphql_abuse\twaf_bypass"
    echo -e "cloud\tcicd_config"
    echo -e "vuln\tservice\texploitation_validation"
    echo -e "reporting\tml_analysis\tcompliance"
    echo -e "database\twebhooks\tcicd"
end

# Helper: list track numbers
function __dark_recon_tracks
    echo -e "0\tFoundation"
    echo -e "1\tData Model"
    echo -e "2\tRecon & Discovery"
    echo -e "3\tWeb/API Attack Surface"
    echo -e "4\tBusiness Logic"
    echo -e "5\tCloud/CI/CD"
    echo -e "6\tExploitation/Validation"
    echo -e "7\tDistributed Scale"
    echo -e "8\tReporting/Integration"
    echo -e "9\tML/Triage"
    echo -e "10\tMobile"
    echo -e "11\tNetwork/Protocol"
    echo -e "12\tContainer/K8s"
    echo -e "13\tSupply Chain"
    echo -e "14\tEASM"
    echo -e "15\tThreat Intelligence"
    echo -e "16\tSecrets Deep"
    echo -e "17\tWireless/IoT"
    echo -e "18\tCompliance"
    echo -e "19\tCollaboration"
    echo -e "20\tUX/CLI"
    echo -e "21\tDocumentation"
end

# Helper: list profiles
function __dark_recon_profiles
    echo -e "default\tDefault profile"
    echo -e "dev\tDevelopment"
    echo -e "staging\tStaging"
    echo -e "prod\tProduction"
end

# Main completions
complete -c dark_recon -n '__fish_use_subcommand' -f -a scan -d 'Run a reconnaissance scan'
complete -c dark_recon -n '__fish_use_subcommand' -f -a report -d 'Generate or view reports'
complete -c dark_recon -n '__fish_use_subcommand' -f -a config -d 'View or modify configuration'
complete -c dark_recon -n '__fish_use_subcommand' -f -a status -d 'Show scan status'
complete -c dark_recon -n '__fish_use_subcommand' -f -a list-phases -d 'List all phases'

# --target
complete -c dark_recon -s target -r -d 'Target domain'

# --track
complete -c dark_recon -s track -r -d 'Track number' -a '(__dark_recon_tracks)'

# --phase
complete -c dark_recon -s phase -r -d 'Phase name' -a '(__dark_recon_phases)'

# --output
complete -c dark_recon -s output -r -F -d 'Output directory'

# --profile
complete -c dark_recon -s profile -r -d 'Environment profile' -a '(__dark_recon_profiles)'

# --jobs
complete -c dark_recon -s jobs -r -d 'Parallel job count' -a '1 2 4 8 16'

# --resume / --skip
complete -c dark_recon -s resume -r -d 'Resume from phase' -a '(__dark_recon_phases)'
complete -c dark_recon -s skip -r -d 'Skip a phase' -a '(__dark_recon_phases)'

# Boolean flags
complete -c dark_recon -s fast -d 'Fast mode: skip optional phases'
complete -c dark_recon -s deep -d 'Deep mode: run all phases'
complete -c dark_recon -s quiet -d 'Quiet output'
complete -c dark_recon -s json -d 'JSON output'
complete -c dark_recon -s parallel -d 'Enable parallel execution'
complete -c dark_recon -s install -d 'Install missing tools'
complete -c dark_recon -s help -d 'Show help'
complete -c dark_recon -s version -d 'Show version'

# list-phases flags
complete -c dark_recon -n '__fish_seen_subcommand_from list-phases' -s all -d 'Show all phases'
complete -c dark_recon -n '__fish_seen_subcommand_from list-phases' -s track -r -a '(__dark_recon_tracks)'

# report flags
complete -c dark_recon -n '__fish_seen_subcommand_from report' -s target -r -d 'Target domain'

# config flags
complete -c dark_recon -n '__fish_seen_subcommand_from config' -s show -d 'Show current config'
complete -c dark_recon -n '__fish_seen_subcommand_from config' -s set -r -d 'Set config key'
