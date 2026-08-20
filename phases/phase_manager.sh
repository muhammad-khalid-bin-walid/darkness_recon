#!/bin/bash
# Phase manager for Dark Recon Framework v4

# Source core functions
source "$(dirname "$0")/../core/core.sh"

# Configuration files
SETTINGS_FILE="$(dirname "$0")/../config/settings.conf"
TOOLS_FILE="$(dirname "$0")/../config/tools.conf"

# Load configuration
source "$SETTINGS_FILE"
source "$TOOLS_FILE"

# Load environment profile if specified
load_profile "${ENV_PROFILE:-default}"

# Check essential tools (skip for --help, --version, and --install)
if [[ "$*" != *"--help"* ]] && [[ "$*" != *"--version"* ]] && [[ "$*" != *"--install"* ]]; then
    for tool in "${ESSENTIAL_TOOLS[@]}"; do
        if ! tool_available "$tool"; then
            log "ERROR" "Essential tool $tool is not available. Run with --install to install missing tools."
            exit 1
        fi
    done
fi

# Phase definitions with dependencies (300 phases, 22 tracks)
declare -A PHASE_DEPS
PHASE_DEPS=(
    # Track 0: Foundation
    [subdomains]=""
    [dns]="subdomains"
    [live]="dns"
    [tech]="live"
    [crawl]="live"
    [params]="crawl"
    [fuzz]="live"
    [takeovers]="subdomains live"
    # Track 1: Data Model
    [waf]="live"
    [nuclei]="live"
    [ports]="live"
    [ssl]="live"
    [api]="live"
    [git]="live"
    [secrets]="crawl"
    [screenshots]="live"
    [patterns]="crawl params"
    # Track 2: Recon & Discovery
    [asn_pivot]="subdomains live"
    [cloud_asset]="subdomains live"
    [origin_ip]="live ssl"
    [osint_correlation]="subdomains live"
    [dns_checks]="subdomains dns"
    [whois_pivot]="subdomains"
    [tls_chain]="ssl"
    [port_fingerprint]="ports live"
    [crawl_tuning]="crawl"
    [mirror_detect]="subdomains live"
    [meta_harvest]="crawl"
    [archive_mine]="crawl"
    [subresource_inventory]="crawl"
    [passive_port]="ports"
    [email_security]="dns"
    [dns_historical]="dns"
    [cert_transparency]="subdomains"
    [wappalyzer_fingerprint]="live"
    [favicon_hash]="live"
    [social_media_osint]="subdomains"
    # Track 3: Web/API Attack Surface
    [openapi_ingest]="api crawl"
    [graphql_abuse]="api"
    [saml_oauth]="api"
    [nosql_injection]="api"
    [ssti_xxe]="api"
    [http_smuggling]="live"
    [waf_bypass]="waf live"
    [redirect_injection]="crawl"
    [grpc_endpoint]="api"
    [websocket]="live"
    [sse_polling]="live"
    [file_upload]="api"
    [content_type_confusion]="api"
    [cache_poisoning]="live"
    [clickjack]="live"
    [cookie_session]="live"
    [api_versioning]="api"
    [rate_limit_fingerprint]="api"
    [input_validation]="api"
    [api_key_leakage]="crawl js_analysis"
    # Track 4: Business Logic (THE MOAT)
    [idor_test]="api business_logic"
    [priv_esc]="api business_logic"
    [race_condition]="api business_logic"
    [password_reset]="api"
    [mfa_bypass]="api"
    [rate_limit_bypass]="rate_limit_fingerprint"
    [chained_vuln]="idor_test priv_esc race_condition"
    [business_workflow]="api crawl"
    [multi_tenancy]="api business_logic"
    [session_fixation]="cookie_session"
    [account_enum]="api"
    [referral_abuse]="api business_workflow"
    [workflow_bypass]="business_workflow"
    [integer_abuse]="api input_validation"
    # Track 5: Cloud/CI/CD
    [cloud]="subdomains live crawl"
    [cloud_acl]="cloud_asset"
    [cloud_iam]="cloud_acl"
    [cicd_config]="subdomains live"
    [supply_chain_scan]="crawl api"
    [container_scan]="subdomains live"
    [k8s_scan]="subdomains live"
    [webhook_discovery]="api live"
    [service_discovery]="live ports"
    [iac_scan]="crawl"
    [serverless]="subdomains live"
    [metadata]="serverless cloud_asset"
    [load_balancer]="live"
    [smtp_relay]="dns"
    [dns_api]="dns"
    [backup_exposure]="subdomains live"
    [message_queue]="live ports"
    [cdn_config]="live"
    [log_exposure]="live ports"
    [secrets_manager]="cloud"
    [multi_cloud]="cloud"
    # Track 6: Exploitation/Validation
    [vuln]="live"
    [service]="live"
    [dns_ssl_whois]="subdomains live"
    [exploitation_gate]="vuln"
    [severity_escalation]="vuln exploitation_gate"
    [screenshot]="live"
    [response_diff]="live"
    [manual_review]="vuln severity_escalation"
    [rollback_verify]="exploitation_validation"
    [exploitation_validation]="vuln"
    [post_exploitation]="vuln secrets cloud"
    [data_exfiltration]="crawl api secrets"
    # Track 7: Distributed Scale
    [distributed]="subdomains dns live crawl params fuzz takeovers"
    [redis_queue]="distributed"
    [docker_worker]="distributed redis_queue"
    [adaptive_ratelimit]="distributed"
    [rotating_egress]="distributed"
    [autoscaling]="distributed redis_queue docker_worker"
    [resource_scheduling]="distributed"
    [incremental_streaming]="distributed"
    [multi_region]="distributed"
    [spot_instance]="distributed docker_worker"
    [work_stealing]="distributed docker_worker"
    [bandwidth_throttle]="distributed"
    [cost_estimation]="distributed resource_scheduling"
    [priority_lanes]="distributed resource_scheduling"
    [worker_drain]="distributed docker_worker"
    [resource_analytics]="distributed"
    # Track 8: Reporting/Integration
    [reporting]="subdomains dns live crawl params fuzz takeovers cloud vuln service dns_ssl_whois distributed osint_intel threat_intel business_logic advanced_exploitation"
    [live_dashboard]="reporting"
    [cvss_mapping]="reporting severity_escalation"
    [hackerone_template]="reporting cvss_mapping"
    [bugcrowd_template]="reporting cvss_mapping"
    [asvs_tagging]="reporting"
    [slack_webhook]="reporting"
    [jira_linear]="reporting"
    [plugin_manifest]="reporting"
    [public_api]="reporting"
    [sarif_defectdojo]="reporting"
    [program_profiles]="reporting"
    [submission_linter]="reporting hackerone_template bugcrowd_template"
    [bounty_tracking]="reporting submission_linter"
    [team_leaderboard]="reporting"
    [writeup_library]="reporting"
    # Track 9: ML/Triage
    [database]="reporting"
    [webhooks]="reporting"
    [cicd]="reporting"
    [ml_analysis]="reporting database webhooks cicd"
    [compliance]="reporting ml_analysis"
    [scan_scheduler]="ml_analysis"
    [ml_classifier]="ml_analysis"
    [anomaly_detection]="ml_analysis ml_classifier"
    [nl_summarization]="ml_analysis"
    [self_tuning]="ml_analysis anomaly_detection"
    [retrospective]="ml_analysis self_tuning"
    [predictive_rescan]="retrospective"
    [llm_draft]="ml_analysis nl_summarization"
    [llm_fp_filter]="ml_classifier"
    [model_drift]="ml_classifier anomaly_detection"
    [program_monitoring]="ml_analysis"
    [changelog]="reporting"
    [self_diagnostic]="ml_analysis"
    [ab_testing]="ml_analysis self_tuning"
    [knowledge_base]="ml_analysis retrospective"
    # Track 10: Mobile
    [mobile_apk_extract]="subdomains live"
    [mobile_api_map]="api crawl"
    [mobile_cert_pinning]="ssl"
    [mobile_deeplink]="crawl"
    [mobile_local_storage]="crawl"
    [mobile_sdk_inventory]="crawl"
    [mobile_webview]="crawl"
    [mobile_build_metadata]="crawl"
    [mobile_push]="api"
    [mobile_version_diff]="mobile_apk_extract"
    [mobile_iap]="api"
    [mobile_cicd_artifact]="cicd_config"
    [mobile_cross_platform]="mobile_apk_extract"
    [mobile_appstore]="mobile_apk_extract"
    [mobile_firmware]="mobile_apk_extract"
    # Track 11: Network/Protocol
    [net_smtp]="ports"
    [net_ftp]="ports"
    [net_smb]="ports"
    [net_rdp]="ports"
    [net_snmp]="ports"
    [net_database]="ports"
    [net_vpn]="ports"
    [net_protocol_downgrade]="ssl"
    [net_cert_validity]="ssl"
    [net_segmentation]="ports live"
    [net_doh_dot]="dns"
    [net_legacy]="ports"
    [net_healthcheck]="live"
    [net_port_correlation]="ports"
    [net_firewall_inference]="ports waf"
    # Track 12: Container/K8s
    [container_docker_daemon]="container_scan"
    [container_k8s_api]="k8s_scan"
    [container_etcd]="k8s_scan"
    [container_registry]="container_scan"
    [container_kubelet]="k8s_scan"
    [container_pod_security]="k8s_scan"
    [container_service_mesh]="k8s_scan"
    [container_escape]="container_scan container_docker_daemon"
    [container_helm]="k8s_scan"
    [container_image_cve]="container_scan"
    # Track 13: Supply Chain
    [supply_sbom]="supply_chain_scan"
    [supply_dependency_confusion]="supply_chain_scan"
    [supply_sri]="subresource_inventory"
    [supply_malicious_packages]="supply_chain_scan"
    [supply_provenance]="supply_chain_scan"
    [supply_license]="supply_sbom"
    [supply_abandoned_vendor]="supply_sbom"
    [supply_maintainer_risk]="supply_chain_scan"
    [supply_update_mechanism]="supply_chain_scan"
    [supply_transitive]="supply_sbom"
    # Track 14: EASM
    [easm_asset_inventory]="subdomains dns live"
    [easm_shadow_it]="easm_asset_inventory"
    [easm_ma]="easm_asset_inventory"
    [easm_expired_domain]="dns historical_recon"
    [easm_cert_expiry]="tls_chain cert_transparency"
    [easm_risk_dashboard]="easm_asset_inventory"
    [easm_breach_db]="secrets"
    [easm_brand_impersonation]="subdomains"
    [easm_exec_exposure]="osint_correlation social_media_osint"
    [easm_change_velocity]="easm_asset_inventory"
    # Track 15: Threat Intelligence
    [ti_leaked_credentials]="secrets"
    [ti_paste_monitoring]="secrets"
    [ti_ttp_correlation]="vuln"
    [ti_cve_feed]="nuclei vuln"
    [ti_exploit_tracking]="vuln exploitation_validation"
    [ti_vendor_advisory]="ti_cve_feed"
    [ti_incident_correlation]="vuln ti_ttp_correlation"
    [ti_industry_trends]="ti_cve_feed ti_ttp_correlation"
    [ti_ioc_crossref]="ti_ttp_correlation ti_cve_feed"
    [ti_source_freshness]="ti_cve_feed ti_vendor_advisory"
    # Track 16: Secrets Deep
    [secrets_entropy]="secrets"
    [secrets_live_check]="secrets"
    [secrets_git_history]="git secrets"
    [secrets_env_exposure]="secrets"
    [secrets_api_key_detect]="secrets crawl"
    [secrets_rotation_age]="secrets secrets_live_check"
    [secrets_cross_repo]="secrets_git_history"
    [secrets_cicd]="secrets cicd_config"
    [secrets_coverage]="secrets"
    [secrets_fp_tuning]="secrets"
    # Track 17: Wireless/IoT
    [iot_device_fingerprint]="ports live"
    [iot_default_cred]="iot_device_fingerprint"
    [iot_firmware_cve]="iot_device_fingerprint"
    [iot_ics_scada]="iot_device_fingerprint ports"
    [iot_upnp]="ports"
    [iot_mqtt]="ports"
    [iot_ble]="ports"
    [iot_wireless_posture]="net_segmentation"
    [iot_smart_building]="iot_device_fingerprint"
    [iot_inventory_correlation]="iot_device_fingerprint iot_default_cred"
    # Track 18: Compliance
    [compliance_asvs]="compliance"
    [compliance_pci]="compliance"
    [compliance_soc2]="compliance"
    [compliance_gdpr]="compliance"
    [compliance_audit_export]="compliance_asvs compliance_pci compliance_soc2"
    [compliance_policy_as_code]="compliance"
    [compliance_auth_tracking]="compliance"
    [compliance_data_retention]="compliance_gdpr"
    [compliance_access_control]="compliance"
    [compliance_regulatory_monitor]="compliance"
    # Track 19: Collaboration
    [collab_multi_operator]="reporting"
    [collab_shared_review]="reporting"
    [collab_rbac]="reporting"
    [collab_handoff]="reporting"
    [collab_workload]="collab_multi_operator"
    [collab_methodology]="reporting"
    [collab_peer_review]="collab_shared_review"
    [collab_calendar]="collab_workload"
    [collab_onboarding]="collab_methodology"
    [collab_knowledge_feed]="collab_methodology"
    # Track 20: UX/CLI
    [ux_interactive]="reporting"
    [ux_tui]="reporting"
    [ux_config_wizard]="reporting"
    [ux_dryrun]="reporting"
    [ux_debug]="reporting"
    [ux_completion]="reporting"
    [ux_sandbox]="reporting"
    [ux_plugin_sdk]="plugin_manifest"
    [ux_exit_codes]="reporting"
    [ux_man_page]="reporting"
    # Track 21: Documentation
    [docs_architecture]="reporting"
    [docs_phase_methodology]="reporting"
    [docs_runbooks]="reporting"
    [docs_video_walkthrough]="reporting"
    [docs_changelog]="changelog"
    [docs_contribution]="docs_architecture"
    [docs_threat_model]="reporting"
    [docs_glossary]="docs_phase_methodology"
    [docs_faq]="docs_runbooks"
    [docs_roadmap_review]="docs_architecture docs_phase_methodology"
)

# Phase enabled flags (300 phases, 22 tracks)
declare -A PHASE_ENABLED
PHASE_ENABLED=(
    # Track 0: Foundation
    [subdomains]=true
    [dns]=true
    [live]=true
    [tech]=true
    [crawl]=true
    [params]=true
    [fuzz]=true
    [takeovers]=true
    # Track 1: Data Model
    [waf]="${WAF_CHECK:-false}"
    [nuclei]="${NUCLEI_CHECK:-false}"
    [ports]="${PORT_SCAN:-false}"
    [ssl]="${SSL_CHECK:-false}"
    [api]="${API_SCAN:-false}"
    [git]="${GIT_SCAN:-false}"
    [secrets]="${SECRETS_SCAN:-false}"
    [screenshots]=true
    [patterns]=true
    # Track 2: Recon & Discovery
    [asn_pivot]="${ASN_PIVOT:-false}"
    [cloud_asset]="${CLOUD_ASSET:-false}"
    [origin_ip]="${ORIGIN_IP:-false}"
    [osint_correlation]="${OSINT_CORRELATION:-false}"
    [dns_checks]="${DNS_CHECKS:-false}"
    [whois_pivot]="${WHOIS_PIVOT:-false}"
    [tls_chain]="${TLS_CHAIN:-false}"
    [port_fingerprint]="${PORT_FINGERPRINT:-false}"
    [crawl_tuning]="${CRAWL_TUNING:-false}"
    [mirror_detect]="${MIRROR_DETECT:-false}"
    [meta_harvest]="${META_HARVEST:-false}"
    [archive_mine]="${ARCHIVE_MINE:-false}"
    [subresource_inventory]="${SUBRESOURCE_INV:-false}"
    [passive_port]="${PASSIVE_PORT:-false}"
    [email_security]="${EMAIL_SECURITY:-false}"
    [dns_historical]="${DNS_HISTORICAL:-false}"
    [cert_transparency]="${CERT_TRANSPARENCY:-false}"
    [wappalyzer_fingerprint]="${WAPPALYZER:-false}"
    [favicon_hash]="${FAVICON_HASH:-false}"
    [social_media_osint]="${SOCIAL_OSINT:-false}"
    # Track 3: Web/API Attack Surface
    [openapi_ingest]="${OPENAPI_INGEST:-false}"
    [graphql_abuse]="${GRAPHQL_ABUSE:-false}"
    [saml_oauth]="${SAML_OAUTH:-false}"
    [nosql_injection]="${NOSQL_INJECT:-false}"
    [ssti_xxe]="${SSTI_XXE:-false}"
    [http_smuggling]="${HTTP_SMUGGLING:-false}"
    [waf_bypass]="${WAF_BYPASS:-false}"
    [redirect_injection]="${REDIRECT_INJECT:-false}"
    [grpc_endpoint]="${GRPC_ENDPOINT:-false}"
    [websocket]="${WEBSOCKET:-false}"
    [sse_polling]="${SSE_POLLING:-false}"
    [file_upload]="${FILE_UPLOAD:-false}"
    [content_type_confusion]="${CONTENT_TYPE_CONFUSION:-false}"
    [cache_poisoning]="${CACHE_POISONING:-false}"
    [clickjack]="${CLICKJACK:-false}"
    [cookie_session]="${COOKIE_SESSION:-false}"
    [api_versioning]="${API_VERSIONING:-false}"
    [rate_limit_fingerprint]="${RATE_LIMIT_FP:-false}"
    [input_validation]="${INPUT_VALIDATION:-false}"
    [api_key_leakage]="${API_KEY_LEAK:-false}"
    # Track 4: Business Logic (THE MOAT)
    [idor_test]="${IDOR_TEST:-false}"
    [priv_esc]="${PRIV_ESC:-false}"
    [race_condition]="${RACE_CONDITION:-false}"
    [password_reset]="${PASSWORD_RESET:-false}"
    [mfa_bypass]="${MFA_BYPASS:-false}"
    [rate_limit_bypass]="${RATE_LIMIT_BYPASS:-false}"
    [chained_vuln]="${CHAINED_VULN:-false}"
    [business_workflow]="${BUSINESS_WORKFLOW:-false}"
    [multi_tenancy]="${MULTI_TENANCY:-false}"
    [session_fixation]="${SESSION_FIXATION:-false}"
    [account_enum]="${ACCOUNT_ENUM:-false}"
    [referral_abuse]="${REFERRAL_ABUSE:-false}"
    [workflow_bypass]="${WORKFLOW_BYPASS:-false}"
    [integer_abuse]="${INTEGER_ABUSE:-false}"
    # Track 5: Cloud/CI/CD
    [cloud]="${CLOUD_SCAN:-false}"
    [cloud_acl]="${CLOUD_ACL:-false}"
    [cloud_iam]="${CLOUD_IAM:-false}"
    [cicd_config]="${CICD_CONFIG:-false}"
    [supply_chain_scan]="${SUPPLY_CHAIN:-false}"
    [container_scan]="${CONTAINER_SCAN:-false}"
    [k8s_scan]="${K8S_SCAN:-false}"
    [webhook_discovery]="${WEBHOOK_DISCOVERY:-false}"
    [service_discovery]="${SERVICE_DISCOVERY:-false}"
    [iac_scan]="${IAC_SCAN:-false}"
    [serverless]="${SERVERLESS:-false}"
    [metadata]="${METADATA:-false}"
    [load_balancer]="${LOAD_BALANCER:-false}"
    [smtp_relay]="${SMTP_RELAY:-false}"
    [dns_api]="${DNS_API:-false}"
    [backup_exposure]="${BACKUP_EXPOSURE:-false}"
    [message_queue]="${MESSAGE_QUEUE:-false}"
    [cdn_config]="${CDN_CONFIG:-false}"
    [log_exposure]="${LOG_EXPOSURE:-false}"
    [secrets_manager]="${SECRETS_MANAGER:-false}"
    [multi_cloud]="${MULTI_CLOUD:-false}"
    # Track 6: Exploitation/Validation
    [vuln]="${VULN_SCAN:-false}"
    [service]="${SERVICE_SCAN:-false}"
    [dns_ssl_whois]="${DNS_SSL_WHOIS_SCAN:-false}"
    [exploitation_gate]="${EXPLOITATION_GATE:-true}"
    [severity_escalation]="${SEVERITY_ESCALATION:-true}"
    [screenshot]="${SCREENSHOT:-false}"
    [response_diff]="${RESPONSE_DIFF:-false}"
    [manual_review]="${MANUAL_REVIEW:-true}"
    [rollback_verify]="${ROLLBACK_VERIFY:-true}"
    [exploitation_validation]="${EXPLOITATION_VALIDATION:-true}"
    [post_exploitation]="${POST_EXPLOITATION:-false}"
    [data_exfiltration]="${DATA_EXFILTRATION:-false}"
    # Track 7: Distributed Scale
    [distributed]="${DISTRIBUTED_SCAN:-false}"
    [redis_queue]="${REDIS_QUEUE:-false}"
    [docker_worker]="${DOCKER_WORKER:-false}"
    [adaptive_ratelimit]="${ADAPTIVE_RATELIMIT:-false}"
    [rotating_egress]="${ROTATING_EGRESS:-false}"
    [autoscaling]="${AUTOSCALING:-false}"
    [resource_scheduling]="${RESOURCE_SCHEDULING:-false}"
    [incremental_streaming]="${INCREMENTAL_STREAMING:-false}"
    [multi_region]="${MULTI_REGION:-false}"
    [spot_instance]="${SPOT_INSTANCE:-false}"
    [work_stealing]="${WORK_STEALING:-false}"
    [bandwidth_throttle]="${BANDWIDTH_THROTTLE:-false}"
    [cost_estimation]="${COST_ESTIMATION:-false}"
    [priority_lanes]="${PRIORITY_LANES:-false}"
    [worker_drain]="${WORKER_DRAIN:-false}"
    [resource_analytics]="${RESOURCE_ANALYTICS:-false}"
    # Track 8: Reporting/Integration
    [reporting]=true
    [live_dashboard]="${LIVE_DASHBOARD:-false}"
    [cvss_mapping]="${CVSS_MAPPING:-true}"
    [hackerone_template]="${HACKERONE_TEMPLATE:-false}"
    [bugcrowd_template]="${BUGCROWD_TEMPLATE:-false}"
    [asvs_tagging]="${ASVS_TAGGING:-false}"
    [slack_webhook]="${SLACK_WEBHOOK:-false}"
    [jira_linear]="${JIRA_LINEAR:-false}"
    [plugin_manifest]="${PLUGIN_MANIFEST:-false}"
    [public_api]="${PUBLIC_API:-false}"
    [sarif_defectdojo]="${SARIF_DEFECTDOJO:-false}"
    [program_profiles]="${PROGRAM_PROFILES:-false}"
    [submission_linter]="${SUBMISSION_LINTER:-false}"
    [bounty_tracking]="${BOUNTY_TRACKING:-false}"
    [team_leaderboard]="${TEAM_LEADERBOARD:-false}"
    [writeup_library]="${WRITEUP_LIBRARY:-false}"
    # Track 9: ML/Triage
    [database]=true
    [webhooks]=true
    [cicd]=true
    [ml_analysis]="${ML_ANALYSIS:-true}"
    [compliance]="${COMPLIANCE_SCAN:-true}"
    [scan_scheduler]="${SCAN_SCHEDULER:-false}"
    [ml_classifier]="${ML_CLASSIFIER:-false}"
    [anomaly_detection]="${ANOMALY_DETECTION:-false}"
    [nl_summarization]="${NL_SUMMARIZATION:-false}"
    [self_tuning]="${SELF_TUNING:-false}"
    [retrospective]="${RETROSPECTIVE:-false}"
    [predictive_rescan]="${PREDICTIVE_RESCAN:-false}"
    [llm_draft]="${LLM_DRAFT:-false}"
    [llm_fp_filter]="${LLM_FP_FILTER:-false}"
    [model_drift]="${MODEL_DRIFT:-false}"
    [program_monitoring]="${PROGRAM_MONITORING:-false}"
    [changelog]="${CHANGELOG:-false}"
    [self_diagnostic]="${SELF_DIAGNOSTIC:-true}"
    [ab_testing]="${AB_TESTING:-false}"
    [knowledge_base]="${KNOWLEDGE_BASE:-false}"
    # Track 10: Mobile
    [mobile_apk_extract]="${MOBILE_APK:-false}"
    [mobile_api_map]="${MOBILE_API_MAP:-false}"
    [mobile_cert_pinning]="${MOBILE_CERT_PIN:-false}"
    [mobile_deeplink]="${MOBILE_DEEPLINK:-false}"
    [mobile_local_storage]="${MOBILE_LOCAL_STORAGE:-false}"
    [mobile_sdk_inventory]="${MOBILE_SDK:-false}"
    [mobile_webview]="${MOBILE_WEBVIEW:-false}"
    [mobile_build_metadata]="${MOBILE_BUILD_META:-false}"
    [mobile_push]="${MOBILE_PUSH:-false}"
    [mobile_version_diff]="${MOBILE_VERSION_DIFF:-false}"
    [mobile_iap]="${MOBILE_IAP:-false}"
    [mobile_cicd_artifact]="${MOBILE_CICD:-false}"
    [mobile_cross_platform]="${MOBILE_CROSS_PLATFORM:-false}"
    [mobile_appstore]="${MOBILE_APPSTORE:-false}"
    [mobile_firmware]="${MOBILE_FIRMWARE:-false}"
    # Track 11: Network/Protocol
    [net_smtp]="${NET_SMTP:-false}"
    [net_ftp]="${NET_FTP:-false}"
    [net_smb]="${NET_SMB:-false}"
    [net_rdp]="${NET_RDP:-false}"
    [net_snmp]="${NET_SNMP:-false}"
    [net_database]="${NET_DATABASE:-false}"
    [net_vpn]="${NET_VPN:-false}"
    [net_protocol_downgrade]="${NET_PROTOCOL_DOWNGRADE:-false}"
    [net_cert_validity]="${NET_CERT_VALIDITY:-false}"
    [net_segmentation]="${NET_SEGMENTATION:-false}"
    [net_doh_dot]="${NET_DOH_DOT:-false}"
    [net_legacy]="${NET_LEGACY:-false}"
    [net_healthcheck]="${NET_HEALTHCHECK:-false}"
    [net_port_correlation]="${NET_PORT_CORRELATION:-false}"
    [net_firewall_inference]="${NET_FIREWALL:-false}"
    # Track 12: Container/K8s
    [container_docker_daemon]="${CONTAINER_DOCKER:-false}"
    [container_k8s_api]="${CONTAINER_K8S_API:-false}"
    [container_etcd]="${CONTAINER_ETCD:-false}"
    [container_registry]="${CONTAINER_REGISTRY:-false}"
    [container_kubelet]="${CONTAINER_KUBELET:-false}"
    [container_pod_security]="${CONTAINER_POD_SECURITY:-false}"
    [container_service_mesh]="${CONTAINER_SERVICE_MESH:-false}"
    [container_escape]="${CONTAINER_ESCAPE:-false}"
    [container_helm]="${CONTAINER_HELM:-false}"
    [container_image_cve]="${CONTAINER_IMAGE_CVE:-false}"
    # Track 13: Supply Chain
    [supply_sbom]="${SUPPLY_SBOM:-false}"
    [supply_dependency_confusion]="${SUPPLY_DEP_CONFUSION:-false}"
    [supply_sri]="${SUPPLY_SRI:-false}"
    [supply_malicious_packages]="${SUPPLY_MALICIOUS_PKG:-false}"
    [supply_provenance]="${SUPPLY_PROVENANCE:-false}"
    [supply_license]="${SUPPLY_LICENSE:-false}"
    [supply_abandoned_vendor]="${SUPPLY_ABANDONED:-false}"
    [supply_maintainer_risk]="${SUPPLY_MAINTAINER:-false}"
    [supply_update_mechanism]="${SUPPLY_UPDATE:-false}"
    [supply_transitive]="${SUPPLY_TRANSITIVE:-false}"
    # Track 14: EASM
    [easm_asset_inventory]="${EASM_INVENTORY:-false}"
    [easm_shadow_it]="${EASM_SHADOW_IT:-false}"
    [easm_ma]="${EASM_MA:-false}"
    [easm_expired_domain]="${EASM_EXPIRED:-false}"
    [easm_cert_expiry]="${EASM_CERT_EXPIRY:-false}"
    [easm_risk_dashboard]="${EASM_RISK:-false}"
    [easm_breach_db]="${EASM_BREACH:-false}"
    [easm_brand_impersonation]="${EASM_BRAND:-false}"
    [easm_exec_exposure]="${EASM_EXEC:-false}"
    [easm_change_velocity]="${EASM_VELOCITY:-false}"
    # Track 15: Threat Intelligence
    [ti_leaked_credentials]="${TI_LEAKED_CREDS:-false}"
    [ti_paste_monitoring]="${TI_PASTE:-false}"
    [ti_ttp_correlation]="${TI_TTP:-false}"
    [ti_cve_feed]="${TI_CVE_FEED:-false}"
    [ti_exploit_tracking]="${TI_EXPLOIT:-false}"
    [ti_vendor_advisory]="${TI_VENDOR:-false}"
    [ti_incident_correlation]="${TI_INCIDENT:-false}"
    [ti_industry_trends]="${TI_INDUSTRY:-false}"
    [ti_ioc_crossref]="${TI_IOC:-false}"
    [ti_source_freshness]="${TI_FRESHNESS:-false}"
    # Track 16: Secrets Deep
    [secrets_entropy]="${SECRETS_ENTROPY:-false}"
    [secrets_live_check]="${SECRETS_LIVE_CHECK:-false}"
    [secrets_git_history]="${SECRETS_GIT:-false}"
    [secrets_env_exposure]="${SECRETS_ENV:-false}"
    [secrets_api_key_detect]="${SECRETS_API_KEY:-false}"
    [secrets_rotation_age]="${SECRETS_ROTATION:-false}"
    [secrets_cross_repo]="${SECRETS_CROSS_REPO:-false}"
    [secrets_cicd]="${SECRETS_CICD:-false}"
    [secrets_coverage]="${SECRETS_COVERAGE:-false}"
    [secrets_fp_tuning]="${SECRETS_FP:-false}"
    # Track 17: Wireless/IoT
    [iot_device_fingerprint]="${IOT_FINGERPRINT:-false}"
    [iot_default_cred]="${IOT_DEFAULT_CRED:-false}"
    [iot_firmware_cve]="${IOT_FIRMWARE:-false}"
    [iot_ics_scada]="${IOT_ICS_SCADA:-false}"
    [iot_upnp]="${IOT_UPNP:-false}"
    [iot_mqtt]="${IOT_MQTT:-false}"
    [iot_ble]="${IOT_BLE:-false}"
    [iot_wireless_posture]="${IOT_WIRELESS:-false}"
    [iot_smart_building]="${IOT_SMART_BUILDING:-false}"
    [iot_inventory_correlation]="${IOT_INVENTORY:-false}"
    # Track 18: Compliance
    [compliance_asvs]="${COMPLIANCE_ASVS:-false}"
    [compliance_pci]="${COMPLIANCE_PCI:-false}"
    [compliance_soc2]="${COMPLIANCE_SOC2:-false}"
    [compliance_gdpr]="${COMPLIANCE_GDPR:-false}"
    [compliance_audit_export]="${COMPLIANCE_AUDIT:-false}"
    [compliance_policy_as_code]="${COMPLIANCE_POLICY:-false}"
    [compliance_auth_tracking]="${COMPLIANCE_AUTH:-false}"
    [compliance_data_retention]="${COMPLIANCE_RETENTION:-false}"
    [compliance_access_control]="${COMPLIANCE_ACCESS:-false}"
    [compliance_regulatory_monitor]="${COMPLIANCE_REGULATORY:-false}"
    # Track 19: Collaboration
    [collab_multi_operator]="${COLLAB_MULTI_OP:-false}"
    [collab_shared_review]="${COLLAB_SHARED_REVIEW:-false}"
    [collab_rbac]="${COLLAB_RBAC:-false}"
    [collab_handoff]="${COLLAB_HANDOFF:-false}"
    [collab_workload]="${COLLAB_WORKLOAD:-false}"
    [collab_methodology]="${COLLAB_METHODOLOGY:-false}"
    [collab_peer_review]="${COLLAB_PEER_REVIEW:-false}"
    [collab_calendar]="${COLLAB_CALENDAR:-false}"
    [collab_onboarding]="${COLLAB_ONBOARDING:-false}"
    [collab_knowledge_feed]="${COLLAB_KNOWLEDGE:-false}"
    # Track 20: UX/CLI
    [ux_interactive]="${UX_INTERACTIVE:-false}"
    [ux_tui]="${UX_TUI:-false}"
    [ux_config_wizard]="${UX_WIZARD:-false}"
    [ux_dryrun]="${UX_DRYRUN:-false}"
    [ux_debug]="${UX_DEBUG:-false}"
    [ux_completion]="${UX_COMPLETION:-false}"
    [ux_sandbox]="${UX_SANDBOX:-false}"
    [ux_plugin_sdk]="${UX_PLUGIN_SDK:-false}"
    [ux_exit_codes]="${UX_EXIT_CODES:-false}"
    [ux_man_page]="${UX_MAN_PAGE:-false}"
    # Track 21: Documentation
    [docs_architecture]="${DOCS_ARCHITECTURE:-false}"
    [docs_phase_methodology]="${DOCS_METHODOLOGY:-false}"
    [docs_runbooks]="${DOCS_RUNBOOKS:-false}"
    [docs_video_walkthrough]="${DOCS_VIDEO:-false}"
    [docs_changelog]="${DOCS_CHANGELOG:-false}"
    [docs_contribution]="${DOCS_CONTRIBUTION:-false}"
    [docs_threat_model]="${DOCS_THREAT_MODEL:-false}"
    [docs_glossary]="${DOCS_GLOSSARY:-false}"
    [docs_faq]="${DOCS_FAQ:-false}"
    [docs_roadmap_review]="${DOCS_ROADMAP:-false}"
)

# Phase execution function
run_phase() {
    local phase="$1"
    local deps=(${PHASE_DEPS[$phase]})
    local enabled="${PHASE_ENABLED[$phase]}"
    
    # Check if phase is enabled
    if [ "$enabled" = false ]; then
        log "INFO" "Phase $phase is disabled, skipping..."
        return 0
    fi
    
    # Check if phase is already completed (resume support)
    local state_file="$CACHE_DIR/state/$phase.done"
    if [ -f "$state_file" ]; then
        log "INFO" "Phase $phase already completed (resume), skipping..."
        return 0
    fi
    
    # Check dependencies
    for dep in $deps; do
        if [ ! -f "$CACHE_DIR/state/$dep.done" ]; then
            log "WARN" "Phase $phase depends on $dep which is not completed"
            return 1
        fi
    done
    
    # Run the phase
    log "INFO" "Running phase: $phase"
    
    # Map phase names to their actual file/function names for original phases
    local phase_map_subdomains="subdomain"
    local phase_map_dns="dns"
    local phase_map_live="live"
    local phase_map_tech="tech"
    local phase_map_crawl="crawl"
    local phase_map_params="params"
    local phase_map_fuzz="fuzz"
    local phase_map_takeovers="takeover"
    # Consolidated v4 phases (20 phases)
    local phase_map_scope="scope"
    local phase_map_livesvc="live"
    local phase_map_techfp="tech"
    local phase_map_urls="urls"
    local phase_map_params="params"
    local phase_map_fuzz="fuzz"
    local phase_map_waf="waf"
    local phase_map_vuln="vuln"
    local phase_map_api="api"
    local phase_map_git="git"
    local phase_map_cloud="cloud"
    local phase_map_comp="comp"
    local phase_map_bl="bl"
    local phase_map_exploit="exploit"
    local phase_map_po="post_exp"
    local phase_map_ti="ti"
    local phase_map_osint="osint"
    local phase_map_ce="ce"
    local phase_map_rp="rp"
    local phase_map_report="report"
    
    local mapped_name="${phase_map_${phase}:-$phase}"
    local phase_file="$(dirname "$0")/${mapped_name}_phase.sh"
    local phase_func="${mapped_name}_phase"
    
    if [ -f "$phase_file" ]; then
        source "$phase_file"
        if type "$phase_func" &>/dev/null; then
            $phase_func "$DOMAIN"
        else
            log "ERROR" "Function $phase_func not found in $phase_file"
            return 1
        fi
    else
        log "ERROR" "Phase file not found: $phase_file"
        return 1
    fi
    
    # Mark phase as completed
    mkdir -p "$CACHE_DIR/state"
    echo "$(date -u +%s)" > "$state_file"
    
    log "INFO" "Phase $phase completed successfully"
}

# Run multiple phases in parallel (respecting dependencies)
run_phases_parallel() {
    local max_jobs="${1:-${PARALLEL_JOBS:-4}}"
    shift
    local phases_to_run=("$@")
    local pids=()
    local phase_names=()
    local running=0

    if [ "${ENABLE_PARALLEL:-false}" != true ]; then
        log "INFO" "Parallel execution disabled, running phases sequentially"
        for phase in "${phases_to_run[@]}"; do
            run_phase "$phase" || log "WARN" "Phase $phase failed"
        done
        return 0
    fi

    log "INFO" "Running ${#phases_to_run[@]} phases in parallel (max $max_jobs concurrent)"

    for phase in "${phases_to_run[@]}"; do
        # Wait if max jobs are running
        while [ "$running" -ge "$max_jobs" ]; do
            for i in "${!pids[@]}"; do
                if [ -n "${pids[$i]:-}" ] && ! kill -0 "${pids[$i]}" 2>/dev/null; then
                    wait "${pids[$i]}" 2>/dev/null || log "WARN" "Phase ${phase_names[$i]} failed"
                    unset 'pids[$i]'
                    unset 'phase_names[$i]'
                    running=$((running - 1))
                fi
            done
            sleep 0.5
        done

        # Launch phase in background
        run_phase "$phase" &
        pids+=($!)
        phase_names+=("$phase")
        running=$((running + 1))
        log "DEBUG" "Started parallel phase ($running/$max_jobs): $phase"
    done

    # Wait for all remaining phases
    for i in "${!pids[@]}"; do
        if [ -n "${pids[$i]:-}" ]; then
            wait "${pids[$i]}" 2>/dev/null || log "WARN" "Phase ${phase_names[$i]:-unknown} failed"
        fi
    done

    log "INFO" "All parallel phases completed"
}

# Get phases that can run in parallel (same dependency level)
get_parallelizable_phases() {
    local -n phase_list=$1
    local -n result=$2

    # Group phases by their dependency depth
    declare -A dep_depth
    for phase in "${phase_list[@]}"; do
        local deps="${PHASE_DEPS[$phase]:-}"
        if [ -z "$deps" ]; then
            dep_depth[$phase]=0
        else
            local max_dep_depth=0
            for dep in $deps; do
                local dep_d=${dep_depth[$dep]:-0}
                if [ "$dep_d" -ge "$max_dep_depth" ]; then
                    max_dep_depth=$((dep_d + 1))
                fi
            done
            dep_depth[$phase]=$max_dep_depth
        fi
    done

    # Return phases grouped by depth
    for phase in "${phase_list[@]}"; do
        result+=("$phase")
    done
}

# Main execution
main() {
    # Parse command line arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            --help)
                echo "Usage: $0 <domain> [--help] [--version] [--resume <phase>] [--skip <phase>] [--jobs <N>] [--timeout <sec>] [--quiet] [--json] [--install] [--fast] [--deep] [--profile <name>]"
                echo ""
                echo "Global flags:"
                echo "  --help                 Show help"
                echo "  --version              Show version"
                echo "  --resume <phase>       Resume from phase"
                echo "  --skip <phase>         Skip phase"
                echo "  --jobs <N>             Number of parallel jobs"
                echo "  --timeout <sec>        Timeout for tools"
                echo "  --quiet                Quiet mode"
                echo "  --json                 JSON output"
                echo "  --install              Install missing tools and assets"
                echo "  --profile <name>       Environment profile (dev/staging/prod)"
                echo ""
                echo "Modes:"
                echo "  --fast                 Fast mode (skip optional phases)"
                echo "  --deep                 Deep mode (run all phases)"
                echo ""
                echo "Phase flags:"
                echo "  --subdomains           Subdomain enumeration (default)"
                echo "  --dns                  DNS record analysis (default)"
                echo "  --live                 Live host detection (default)"
                echo "  --crawl                URL and endpoint discovery (default)"
                echo "  --params               Parameter discovery (default)"
                echo "  --fuzz                 Fuzzing (default)"
                echo "  --takeovers            Subdomain takeover detection (default)"
                echo "  --waf                  WAF detection"
                echo "  --nuclei               Nuclei vulnerability scanning"
                echo "  --portscan            Port scanning"
                echo "  --ssl                  SSL/TLS analysis"
                echo "  --api                  API endpoint discovery"
                echo "  --git                  Git repository scanning"
                echo "  --secrets              Secret scanning"
                echo "  --screenshots          Visual reconnaissance"
                echo "  --patterns             Pattern matching"
                echo "  --cloud                Cloud/infrastructure scanning"
                echo "  --vuln                 Vulnerability scanning"
                echo "  --service              Service enumeration"
                echo "  --dns-ssl-whois        DNS/SSL/WHOIS analysis"
                echo "  --distributed          Distributed/cloud scaling"
                echo "  --osint-intel          OSINT intelligence gathering"
                echo "  --threat-intel         Threat intelligence & IOC correlation"
                echo "  --business-logic       Business logic testing (IDOR/BOLA/BFLA)"
                echo "  --advanced-exploitation Advanced exploitation (blind SSRF, file upload, rate limiting)"
                echo "  --database             Database security scanning"
                echo "  --webhooks             Webhook & API integration security"
                echo "  --cicd                 CI/CD pipeline security"
                echo "  --ml-analysis          ML-assisted anomaly detection & pattern recognition"
                echo "  --compliance           Compliance scanning (GDPR/HIPAA/PCI DSS/SOC2)"
                echo "  --scope-program        Scope & program analysis"
                echo "  --target-intake        Target intake & validation"
                echo "  --historical-recon     Historical reconnaissance (Wayback, DNS history)"
                echo "  --third-party          Third-party & dependency analysis"
                echo "  --exploitation-validate Exploitation & PoC validation"
                echo "  --post-exploitation    Post-exploitation & lateral movement"
                echo "  --data-exfiltration    Data exfiltration & sensitive data discovery"
                echo "  --continuous-monitor   Continuous monitoring & re-scan"
                 echo "  --howtohunt            HowToHunt vulnerability methodology integration"
                echo ""
                exit 0
                ;;
            --version)
                echo "Dark Recon Framework 1.0.1"
                exit 0
                ;;
            --install)
                install_tools
                configure_assets
                exit 0
                ;;
            --profile)
                ENV_PROFILE="$2"
                load_profile "$ENV_PROFILE"
                shift 2
                ;;
            --parallel)
                ENABLE_PARALLEL=true
                shift
                ;;
            --fast)
                # Disable optional phases
                WAF_CHECK=false
                NUCLEI_CHECK=false
                PORT_SCAN=false
                SSL_CHECK=false
                API_SCAN=false
                GIT_SCAN=false
                SECRETS_SCAN=false
                CLOUD_SCAN=false
                VULN_SCAN=false
                SERVICE_SCAN=false
                DNS_SSL_WHOIS_SCAN=false
                DISTRIBUTED_SCAN=false
                OSINT_INTEL=false
                THREAT_INTEL=false
                BUSINESS_LOGIC=false
                ADVANCED_EXPLOITATION=false
                DATABASE_SCAN=false
                WEBHOOKS_SCAN=false
                CICD_SCAN=false
                ML_ANALYSIS=false
                COMPLIANCE_SCAN=false
                SCOPE_PROGRAM=false
                TARGET_INTAKE=false
                HISTORICAL_RECON=false
                THIRD_PARTY=false
                EXPLOITATION_VALIDATION=false
                POST_EXPLOITATION=false
                DATA_EXFILTRATION=false
                CONTINUOUS_MONITORING=false
                HOWTOHUNT_METHOD=false
                ;;
            --deep)
                # Enable optional phases
                WAF_CHECK=true
                NUCLEI_CHECK=true
                PORT_SCAN=true
                SSL_CHECK=true
                API_SCAN=true
                GIT_SCAN=true
                SECRETS_SCAN=true
                CLOUD_SCAN=true
                VULN_SCAN=true
                SERVICE_SCAN=true
                DNS_SSL_WHOIS_SCAN=true
                DISTRIBUTED_SCAN=true
                OSINT_INTEL=true
                THREAT_INTEL=true
                BUSINESS_LOGIC=true
                ADVANCED_EXPLOITATION=true
                DATABASE_SCAN=true
                WEBHOOKS_SCAN=true
                CICD_SCAN=true
                ML_ANALYSIS=true
                COMPLIANCE_SCAN=true
                SCOPE_PROGRAM=true
                TARGET_INTAKE=true
                HISTORICAL_RECON=true
                THIRD_PARTY=true
                EXPLOITATION_VALIDATION=true
                POST_EXPLOITATION=true
                DATA_EXFILTRATION=true
                CONTINUOUS_MONITORING=true
                HOWTOHUNT_METHOD=true
                ;;
            *)
                break
                ;;
        esac
        shift
    done
    
    # Set up domain and output directory
    if [ $# -lt 1 ]; then
        log "ERROR" "Domain is required"
        exit 1
    fi
    
    DOMAIN="$1"
    shift
    
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUTDIR="$OUTPUT_DIR/$DOMAIN/recon_$TIMESTAMP"
    mkdir -p "$OUTDIR"
    
    # Update config paths with actual domain
    RESOLVERS="$CACHE_DIR/resolvers.txt"
    WORDLIST="$CACHE_DIR/wordlists/common.txt"
    CUSTOM_WORDLIST="$CACHE_DIR/wordlists/custom.txt"
    API_WORDLIST="$CACHE_DIR/wordlists/api.txt"
    
    # Generate custom wordlist if domain provided
    configure_assets "$DOMAIN"
    
    # Parse remaining flags
    while [ $# -gt 0 ]; do
        case "$1" in
            --resume)
                RESUME_PHASE="$2"
                shift 2
                ;;
            --skip)
                SKIP_PHASE="$2"
                shift 2
                ;;
            --jobs)
                THREADS="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --quiet)
                QUIET=true
                shift
                ;;
            --json)
                JSON_OUTPUT=true
                shift
                ;;
            *)
                # Phase flags
                case "$1" in
                    --waf) WAF_CHECK=true ;;
                    --nuclei) NUCLEI_CHECK=true ;;
                    --portscan) PORT_SCAN=true ;;
                    --ssl) SSL_CHECK=true ;;
                    --api) API_SCAN=true ;;
                    --git) GIT_SCAN=true ;;
                    --secrets) SECRETS_SCAN=true ;;
                    --dirsearch) DIRSEARCH=true ;;
                    --cloud) CLOUD_SCAN=true ;;
                    --vuln) VULN_SCAN=true ;;
                    --service) SERVICE_SCAN=true ;;
                    --dns-ssl-whois) DNS_SSL_WHOIS_SCAN=true ;;
                    --distributed) DISTRIBUTED_SCAN=true ;;
                    --osint-intel) OSINT_INTEL=true ;;
                    --threat-intel) THREAT_INTEL=true ;;
                    --business-logic) BUSINESS_LOGIC=true ;;
                    --advanced-exploitation) ADVANCED_EXPLOITATION=true ;;
                    --database) DATABASE_SCAN=true ;;
                    --webhooks) WEBHOOKS_SCAN=true ;;
                    --cicd) CICD_SCAN=true ;;
                    --ml-analysis) ML_ANALYSIS=true ;;
                    --compliance) COMPLIANCE_SCAN=true ;;
                    --scope-program) SCOPE_PROGRAM=true ;;
                    --target-intake) TARGET_INTAKE=true ;;
                    --historical-recon) HISTORICAL_RECON=true ;;
                    --third-party) THIRD_PARTY=true ;;
                    --exploitation-validate) EXPLOITATION_VALIDATION=true ;;
                    --post-exploitation) POST_EXPLOITATION=true ;;
                    --data-exfiltration) DATA_EXFILTRATION=true ;;
                    --continuous-monitor) CONTINUOUS_MONITORING=true ;;
                     --howtohunt) HOWTOHUNT_METHOD=true ;;
                    *) log "WARN" "Unknown flag: $1" ;;
                esac
                shift
                ;;
        esac
    done
    
    # Override phase settings from command line
    if [ -n "$SKIP_PHASE" ]; then
        PHASE_ENABLED["$SKIP_PHASE"]=false
    fi
    PHASE_ENABLED["waf"]="$WAF_CHECK"
    PHASE_ENABLED["nuclei"]="$NUCLEI_CHECK"
    PHASE_ENABLED["ports"]="$PORT_SCAN"
    PHASE_ENABLED["ssl"]="$SSL_CHECK"
    PHASE_ENABLED["api"]="$API_SCAN"
    PHASE_ENABLED["git"]="$GIT_SCAN"
    PHASE_ENABLED["secrets"]="$SECRETS_SCAN"
    PHASE_ENABLED["dirsearch"]="${DIRSEARCH:-false}"
    PHASE_ENABLED["cloud"]="$CLOUD_SCAN"
    PHASE_ENABLED["vuln"]="$VULN_SCAN"
    PHASE_ENABLED["service"]="$SERVICE_SCAN"
    PHASE_ENABLED["dns_ssl_whois"]="$DNS_SSL_WHOIS_SCAN"
    PHASE_ENABLED["distributed"]="$DISTRIBUTED_SCAN"
    PHASE_ENABLED["osint_intel"]="${OSINT_INTEL:-false}"
    PHASE_ENABLED["threat_intel"]="${THREAT_INTEL:-false}"
    PHASE_ENABLED["business_logic"]="${BUSINESS_LOGIC:-false}"
    PHASE_ENABLED["advanced_exploitation"]="${ADVANCED_EXPLOITATION:-false}"
    PHASE_ENABLED["database"]="${DATABASE_SCAN:-true}"
    PHASE_ENABLED["webhooks"]="${WEBHOOKS_SCAN:-true}"
    PHASE_ENABLED["cicd"]="${CICD_SCAN:-true}"
    PHASE_ENABLED["ml_analysis"]="${ML_ANALYSIS:-true}"
    PHASE_ENABLED["compliance"]="${COMPLIANCE_SCAN:-true}"
    PHASE_ENABLED["scope_program_analysis"]="${SCOPE_PROGRAM:-true}"
    PHASE_ENABLED["target_intake_validation"]="${TARGET_INTAKE:-true}"
    PHASE_ENABLED["historical_recon"]="${HISTORICAL_RECON:-false}"
    PHASE_ENABLED["third_party_dependency"]="${THIRD_PARTY:-false}"
    PHASE_ENABLED["exploitation_validation"]="${EXPLOITATION_VALIDATION:-true}"
    PHASE_ENABLED["post_exploitation"]="${POST_EXPLOITATION:-false}"
    PHASE_ENABLED["data_exfiltration"]="${DATA_EXFILTRATION:-false}"
    PHASE_ENABLED["continuous_monitoring"]="${CONTINUOUS_MONITORING:-false}"
    PHASE_ENABLED["howtohunt_methodology"]="${HOWTOHUNT_METHOD:-false}"

    # Run core phases in dependency order
    local phases=("subdomains" "dns" "live" "tech" "crawl" "params" "fuzz" "takeovers")

    for phase in "${phases[@]}"; do
        run_phase "$phase"
    done

    # Run optional phases (parallel when enabled)
    local optional_phases=()
    local optional_waf=()

    # Group A: Independent scanning phases (can run in parallel)
    [ "$WAF_CHECK" = true ] && optional_waf+=("waf")
    [ "$NUCLEI_CHECK" = true ] && optional_waf+=("nuclei")
    [ "$PORT_SCAN" = true ] && optional_waf+=("ports")
    [ "$SSL_CHECK" = true ] && optional_waf+=("ssl")
    [ "$GIT_SCAN" = true ] && optional_waf+=("git")
    [ "${PHASE_ENABLED[screenshots]}" = true ] && optional_waf+=("screenshots")
    [ "$CLOUD_SCAN" = true ] && optional_waf+=("cloud")
    [ "$VULN_SCAN" = true ] && optional_waf+=("vuln")
    [ "$SERVICE_SCAN" = true ] && optional_waf+=("service")
    [ "$DNS_SSL_WHOIS_SCAN" = true ] && optional_waf+=("dns_ssl_whois")

    if [ ${#optional_waf[@]} -gt 0 ]; then
        run_phases_parallel "${PARALLEL_JOBS:-4}" "${optional_waf[@]}"
    fi

    # API and secrets depend on crawl/live
    [ "$API_SCAN" = true ] && optional_phases+=("api")
    [ "$SECRETS_SCAN" = true ] && optional_phases+=("secrets")
    [ "${PHASE_ENABLED[patterns]}" = true ] && optional_phases+=("patterns")

    if [ ${#optional_phases[@]} -gt 0 ]; then
        run_phases_parallel "${PARALLEL_JOBS:-4}" "${optional_phases[@]}"
    fi

    # Distributed scanning
    if [ "$DISTRIBUTED_SCAN" = true ]; then
        run_phase "distributed"
    fi

    # Run advanced intelligence phases if enabled
    if [ "${OSINT_INTEL:-false}" = true ]; then
        run_phase "osint_intel"
    fi

    if [ "${THREAT_INTEL:-false}" = true ]; then
        run_phase "threat_intel"
    fi

    if [ "${BUSINESS_LOGIC:-false}" = true ]; then
        run_phase "business_logic"
    fi

    if [ "${ADVANCED_EXPLOITATION:-false}" = true ]; then
        run_phase "advanced_exploitation"
    fi

    # Run reporting phase (must be sequential - aggregates all results)
    run_phase "reporting"

    # Run post-reporting phases in parallel where possible
    local post_phases=()
    [ "${DATABASE_SCAN:-true}" = true ] && post_phases+=("database")
    [ "${WEBHOOKS_SCAN:-true}" = true ] && post_phases+=("webhooks")
    [ "${CICD_SCAN:-true}" = true ] && post_phases+=("cicd")
    [ "${ML_ANALYSIS:-true}" = true ] && post_phases+=("ml_analysis")
    [ "${COMPLIANCE_SCAN:-true}" = true ] && post_phases+=("compliance")
    [ "${SCOPE_PROGRAM:-true}" = true ] && post_phases+=("scope_program_analysis")
    [ "${TARGET_INTAKE:-true}" = true ] && post_phases+=("target_intake_validation")
    [ "${HISTORICAL_RECON:-false}" = true ] && post_phases+=("historical_recon")
    [ "${THIRD_PARTY:-false}" = true ] && post_phases+=("third_party_dependency")
    [ "${EXPLOITATION_VALIDATION:-true}" = true ] && post_phases+=("exploitation_validation")
    [ "${POST_EXPLOITATION:-false}" = true ] && post_phases+=("post_exploitation")
    [ "${DATA_EXFILTRATION:-false}" = true ] && post_phases+=("data_exfiltration")
    [ "${CONTINUOUS_MONITORING:-false}" = true ] && post_phases+=("continuous_monitoring")
    [ "${HOWTOHUNT_METHOD:-false}" = true ] && post_phases+=("howtohunt_methodology")

    if [ ${#post_phases[@]} -gt 0 ]; then
        run_phases_parallel "${PARALLEL_JOBS:-4}" "${post_phases[@]}"
    fi

    log "INFO" "Dark Recon Framework v4 completed successfully"
    log "INFO" "Results saved to: $OUTDIR"
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi