# bash completion for dark_recon                              -*- shell-script -*-

_dark_recon_completions()
{
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    commands="scan report config status list-phases"

    phases="subdomains dns live tech crawl params fuzz takeovers waf nuclei ports ssl api git secrets screenshots patterns
            asn_pivot cloud_asset origin_ip osint_correlation dns_checks whois_pivot tls_chain port_fingerprint
            crawl_tuning mirror_detect meta_harvest archive_mine subresource_inventory passive_port email_security
            dns_historical cert_transparency wappalyzer_fingerprint favicon_hash social_media_osint
            openapi_ingest graphql_abuse saml_oauth nosql_injection ssti_xxe http_smuggling waf_bypass
            redirect_injection grpc_endpoint websocket sse_polling file_upload content_type_confusion
            cache_poisoning clickjack cookie_session api_versioning rate_limit_fingerprint input_validation api_key_leakage
            idor_test priv_esc race_condition password_reset mfa_bypass rate_limit_bypass chained_vuln
            business_workflow multi_tenancy session_fixation account_enum referral_abuse workflow_bypass integer_abuse
            cloud cloud_acl cloud_iam cicd_config supply_chain_scan container_scan k8s_scan webhook_discovery
            service_discovery iac_scan serverless metadata load_balancer smtp_relay dns_api backup_exposure
            message_queue cdn_config log_exposure secrets_manager multi_cloud
            vuln service dns_ssl_whois exploitation_gate severity_escalation screenshot response_diff
            manual_review rollback_verify exploitation_validation post_exploitation data_exfiltration
            distributed redis_queue docker_worker adaptive_ratelimit rotating_egress autoscaling
            resource_scheduling incremental_streaming multi_region spot_instance work_stealing
            bandwidth_throttle cost_estimation priority_lanes worker_drain resource_analytics
            reporting live_dashboard cvss_mapping hackerone_template bugcrowd_template asvs_tagging
            slack_webhook jira_linear plugin_manifest public_api sarif_defectdojo program_profiles
            submission_linter bounty_tracking team_leaderboard writeup_library
            database webhooks cicd ml_analysis compliance scan_scheduler ml_classifier anomaly_detection
            nl_summarization self_tuning retrospective predictive_rescan llm_draft llm_fp_filter
            model_drift program_monitoring changelog self_diagnostic ab_testing knowledge_base"

    tracks="0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21"

    # Complete subcommands
    if [ "$COMP_CWORD" -eq 1 ]; then
        COMPREPLY=($(compgen -W "$commands" -- "$cur"))
        return 0
    fi

    # Complete flags based on previous word
    case "$prev" in
        --target)
            COMPREPLY=()
            return 0
            ;;
        --track)
            COMPREPLY=($(compgen -W "$tracks" -- "$cur"))
            return 0
            ;;
        --phase)
            COMPREPLY=($(compgen -W "$phases" -- "$cur"))
            return 0
            ;;
        --output)
            COMPREPLY=($(compgen -f -- "$cur"))
            return 0
            ;;
        --profile)
            COMPREPLY=($(compgen -W "default dev staging prod" -- "$cur"))
            return 0
            ;;
        --jobs)
            COMPREPLY=($(compgen -W "1 2 4 8 16" -- "$cur"))
            return 0
            ;;
        --resume|--skip)
            COMPREPLY=($(compgen -W "$phases" -- "$cur"))
            return 0
            ;;
        --help|--version|--install|--fast|--deep|--quiet|--json|--parallel)
            COMPREPLY=()
            return 0
            ;;
    esac

    # Complete flags
    case "$cur" in
        -*)
            COMPREPLY=($(compgen -W "--target --track --phase --output --profile --jobs --resume --skip --help --version --install --fast --deep --quiet --json --parallel" -- "$cur"))
            return 0
            ;;
    esac

    # Complete phases after --phase or standalone
    COMPREPLY=($(compgen -W "$phases" -- "$cur"))
}

complete -F _dark_recon_completions dark_recon
complete -F _dark_recon_completions ./dark_recon
