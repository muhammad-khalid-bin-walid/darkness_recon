# Dark Recon Framework 300-Phase Implementation Tasks

## TRACK 0 — Foundation & Reliability

- [x] 1. Unified data schema (Asset/Finding/Endpoint/Credential/ScanRun models)
  - Create `lib/__init__.py` and `lib/schema.py` with Pydantic models for Asset, Finding, Endpoint, Credential, ScanRun
  - Add JSON serialization/deserialization helpers and schema version field
  - Write `tests/test_schema.py` with pytest coverage for all models
  - **Files**: `lib/__init__.py`, `lib/schema.py`, `tests/__init__.py`, `tests/test_schema.py`

- [x] 2. Schema validation layer
  - Create `lib/validator.py` with validate_and_write() that rejects malformed phase output
  - Integrate validation into core.sh write paths via a thin shell wrapper `lib/validate_output.sh`
  - Write `tests/test_validator.py`
  - **Files**: `lib/validator.py`, `lib/validate_output.sh`, `tests/test_validator.py`

- [-] 3. Extract inline Python heredocs into lib modules
  - Audit all phase `.sh` files for `python3 -c "..."` blocks
  - Extract each into a named function in the appropriate `lib/*.py` module
  - Replace heredocs with `python3 -m lib.<module> <args>` calls
  - Write tests for each extracted module
  - **Files**: `lib/url_utils.py`, `lib/dns_utils.py`, `lib/report_utils.py`, `tests/test_url_utils.py`, `tests/test_dns_utils.py`

- [~] 4. Implement fuzz_phase.sh with baseline response diffing
  - Implement full `fuzz_phase()` with ffuf, gobuster, baseline diffing, and result dedup
  - Add baseline capture before fuzzing and diff logic to flag anomalies
  - Write `tests/bats/test_fuzz_phase.bats`
  - **Files**: `phases/fuzz_phase.sh`, `tests/bats/test_fuzz_phase.bats`

- [~] 5. Config validation on startup
  - Create `lib/config_validator.py` that lints all `.conf` files for required keys and type safety
  - Add call to validator in `core/core.sh` before any phase runs
  - Write `tests/test_config_validator.py`
  - **Files**: `lib/config_validator.py`, `tests/test_config_validator.py`

- [~] 6. Tool auto-detection with graceful degradation logging
  - Create `lib/tool_registry.py` mapping tools to capabilities and degradation fallbacks
  - Update `core/core.sh` tool_available() to log structured degradation events
  - Write `tests/test_tool_registry.py`
  - **Files**: `lib/tool_registry.py`, `tests/test_tool_registry.py`

- [~] 7. Structured JSON logging
  - Upgrade `core/core.sh` log() to emit `{"level","phase","target","event","duration_ms","timestamp"}` JSON
  - Add `lib/logger.py` for Python phases to emit the same schema
  - Write `tests/test_logger.py` and `tests/bats/test_logging.bats`
  - **Files**: `lib/logger.py`, `tests/test_logger.py`, `tests/bats/test_logging.bats`

- [~] 8. CI test suite (bats + pytest)
  - Create `.github/workflows/ci.yml` with bats and pytest jobs
  - Add `tests/bats/` scaffold with helper setup and common fixtures
  - Add `pytest.ini` / `pyproject.toml` for pytest config
  - **Files**: `.github/workflows/ci.yml`, `tests/bats/setup.bash`, `pytest.ini`

- [~] 9. Per-target per-phase checkpoint/resume
  - Replace coarse RESUME_PHASE/SKIP_PHASE with fine-grained `cache/state/<target>/<phase>.done` checkpoints
  - Update `phases/phase_manager.sh` check_checkpoint() and mark_done() helpers
  - Write `tests/bats/test_checkpoint.bats`
  - **Files**: `phases/phase_manager.sh`, `tests/bats/test_checkpoint.bats`

- [~] 10. Secrets hygiene audit
  - Create `.pre-commit-config.yaml` with gitleaks/trufflehog hooks
  - Audit `.gitignore` and add patterns for cache/output/logs secrets
  - Create `lib/secrets_hygiene.py` scanner for CI use
  - **Files**: `.pre-commit-config.yaml`, `.gitignore`, `lib/secrets_hygiene.py`, `tests/test_secrets_hygiene.py`

- [~] 11. Dependency pinning and reproducible builds
  - Create `requirements.txt` with pinned Python deps and `requirements-dev.txt`
  - Add `lib/tool_versions.conf` pinning every wrapped tool version
  - Update `Dockerfile` to use pinned versions
  - **Files**: `requirements.txt`, `requirements-dev.txt`, `lib/tool_versions.conf`

- [~] 12. Crash isolation — phase failure never kills run
  - Wrap every `run_phase()` call in `phases/phase_manager.sh` with isolated subshell + error capture
  - Add `lib/phase_isolation.sh` with run_isolated() helper
  - Write `tests/bats/test_crash_isolation.bats`
  - **Files**: `lib/phase_isolation.sh`, `tests/bats/test_crash_isolation.bats`

- [~] 13. Idempotent phase design
  - Add idempotency guards to all phases: skip if output already exists and is valid
  - Create `lib/idempotency.sh` with is_phase_output_valid() helper
  - Write `tests/bats/test_idempotency.bats`
  - **Files**: `lib/idempotency.sh`, `tests/bats/test_idempotency.bats`

- [~] 14. Centralized error taxonomy
  - Create `lib/errors.py` with ErrorCode enum: NETWORK, AUTH, RATE_LIMIT, PARSE, TOOL_MISSING
  - Add shell counterpart `lib/errors.sh` with classify_error() function
  - Integrate into core.sh handle_error()
  - **Files**: `lib/errors.py`, `lib/errors.sh`, `tests/test_errors.py`

- [~] 15. Health-check command
  - Create `lib/healthcheck.py` that checks tool availability, config validity, disk space, network
  - Add `--healthcheck` flag to `phases/phase_manager.sh`
  - Write `tests/test_healthcheck.py`
  - **Files**: `lib/healthcheck.py`, `tests/test_healthcheck.py`


## TRACK 1 — Data Model & Correlation Intelligence

- [~] 16. Confidence-scoring engine
  - Create `lib/scoring.py` with ConfidenceEngine weighting tool reliability coefficients
  - Add per-tool reliability weights config in `config/tool_weights.conf`
  - Write `tests/test_scoring.py`
  - **Files**: `lib/scoring.py`, `config/tool_weights.conf`, `tests/test_scoring.py`

- [~] 17. Cross-phase correlation graph
  - Create `lib/correlation.py` building asset→techstack→CVE→phase graph using networkx
  - Add `lib/correlation_graph.json` schema for the graph data layer
  - Write `tests/test_correlation.py`
  - **Files**: `lib/correlation.py`, `tests/test_correlation.py`

- [~] 18. Persistent false-positive suppression list
  - Create `lib/false_positives.py` with per-program FP list stored in `cache/fp/<program>.json`
  - Add CLI command `--add-fp` and `--list-fp` to phase_manager.sh
  - Write `tests/test_false_positives.py`
  - **Files**: `lib/false_positives.py`, `tests/test_false_positives.py`

- [~] 19. Delta/diff engine
  - Create `lib/delta.py` diffing current scan results against last known-good state
  - Store baselines in `cache/baselines/<target>/<phase>.json`
  - Write `tests/test_delta.py`
  - **Files**: `lib/delta.py`, `tests/test_delta.py`

- [~] 20. Adaptive scan depth
  - Add `lib/adaptive_depth.py` that gates expensive phases behind delta check
  - Integrate with phase_manager.sh via should_run_deep_phase() helper
  - Write `tests/test_adaptive_depth.py`
  - **Files**: `lib/adaptive_depth.py`, `tests/test_adaptive_depth.py`

- [~] 21. Asset criticality auto-tagging
  - Create `lib/asset_tagger.py` classifying assets as prod/staging/dev, auth-gated/public, API/web
  - Output tags into Asset schema criticality field
  - Write `tests/test_asset_tagger.py`
  - **Files**: `lib/asset_tagger.py`, `tests/test_asset_tagger.py`

- [~] 22. Finding deduplication with normalized fingerprints
  - Create `lib/dedup.py` normalizing findings to fingerprints before dedup (not exact string match)
  - Integrate into validator write path
  - Write `tests/test_dedup.py`
  - **Files**: `lib/dedup.py`, `tests/test_dedup.py`

- [~] 23. Historical trend store
  - Create `lib/trend_store.py` recording findings/hour, false-positive rate, mean-time-to-validate
  - Store trends in `cache/trends/<program>.jsonl`
  - Write `tests/test_trend_store.py`
  - **Files**: `lib/trend_store.py`, `tests/test_trend_store.py`

- [~] 24. Per-program scope engine
  - Create `lib/scope_engine.py` enforcing in/out-of-scope rules before any active phase fires
  - Store scope rules in `config/scopes/<program>.json`
  - Write `tests/test_scope_engine.py`
  - **Files**: `lib/scope_engine.py`, `tests/test_scope_engine.py`

- [~] 25. Risk-based target prioritization queue
  - Create `lib/priority_queue.py` scoring and ordering targets for time-constrained engagements
  - Write `tests/test_priority_queue.py`
  - **Files**: `lib/priority_queue.py`, `tests/test_priority_queue.py`

- [~] 26. Entity-resolution layer
  - Create `lib/entity_resolution.py` merging duplicate assets from different naming conventions
  - Write `tests/test_entity_resolution.py`
  - **Files**: `lib/entity_resolution.py`, `tests/test_entity_resolution.py`

- [~] 27. Confidence decay over time
  - Add decay logic in `lib/scoring.py`: stale unconfirmed findings auto-queued for re-validation
  - Write `tests/test_confidence_decay.py`
  - **Files**: `lib/scoring.py` (extend), `tests/test_confidence_decay.py`

- [~] 28. Cross-program correlation
  - Create `lib/cross_program.py` correlating shared infra/vendor findings across programs
  - Write `tests/test_cross_program.py`
  - **Files**: `lib/cross_program.py`, `tests/test_cross_program.py`

- [~] 29. Graph-based attack-path data layer
  - Create `lib/attack_graph.py` building exploitable attack paths from correlation data
  - Output graph to `output/<target>/attack_paths.json`
  - Write `tests/test_attack_graph.py`
  - **Files**: `lib/attack_graph.py`, `tests/test_attack_graph.py`

- [~] 30. Feedback loop from triager verdicts
  - Create `lib/feedback.py` ingesting accepted/rejected verdicts and updating scoring weights
  - Write `tests/test_feedback.py`
  - **Files**: `lib/feedback.py`, `tests/test_feedback.py`


## TRACK 2 — Recon & Discovery Depth

- [~] 31. Subdomain takeover fingerprint database
  - Create `lib/takeover_db.py` with per-provider fingerprints (AWS/Azure/Heroku/GitHub Pages)
  - Update `phases/takeover_phase.sh` to use the database
  - **Files**: `lib/takeover_db.py`, `data/takeover_fingerprints.json`, `tests/test_takeover_db.py`

- [~] 32. Historical DNS/CT mining
  - Create `phases/historical_dns_phase.sh` querying crt.sh, certspotter, DNS history APIs
  - Deduplicate against live crawl results
  - **Files**: `phases/historical_dns_phase.sh`, `lib/ct_mining.py`, `tests/test_ct_mining.py`

- [~] 33. ASN and IP-range pivoting
  - Create `phases/asn_pivot_phase.sh` using bgpview/ARIN/RIPE APIs
  - **Files**: `phases/asn_pivot_phase.sh`, `lib/asn_utils.py`, `tests/test_asn_utils.py`

- [~] 34. Cloud asset discovery via cert SANs / bucket heuristics
  - Create `lib/cloud_discovery.py` for SAN extraction, bucket naming patterns, CDN leakage
  - **Files**: `lib/cloud_discovery.py`, `tests/test_cloud_discovery.py`

- [~] 35. Origin IP discovery behind CDN/WAF
  - Create `lib/origin_ip.py` using passive signal correlation
  - **Files**: `lib/origin_ip.py`, `tests/test_origin_ip.py`

- [~] 36. Wayback/gau/waymore historical endpoint mining with dedup
  - Update `phases/historical_recon_phase.sh`, add `lib/wayback_utils.py`
  - **Files**: `lib/wayback_utils.py`, `tests/test_wayback_utils.py`

- [~] 37. JS file analysis pipeline
  - Implement `scripts/analyze_js.sh` with endpoint extraction, secret regex, dep fingerprinting
  - Add `lib/js_analyzer.py`
  - **Files**: `scripts/analyze_js.sh`, `lib/js_analyzer.py`, `tests/test_js_analyzer.py`

- [~] 38. Third-party/vendor integration mapping
  - Create `lib/vendor_mapper.py` detecting SaaS integrations from headers and JS includes
  - **Files**: `lib/vendor_mapper.py`, `tests/test_vendor_mapper.py`

- [~] 39. Passive OSINT correlation
  - Create `phases/osint_passive_phase.sh` and `lib/osint_utils.py`
  - **Files**: `phases/osint_passive_phase.sh`, `lib/osint_utils.py`, `tests/test_osint_utils.py`

- [~] 40. DNS zone transfer / misconfiguration checks
  - Update `phases/dns_phase.sh` with AXFR checks, wildcard, open resolver detection
  - **Files**: `phases/dns_phase.sh` (extend), `tests/bats/test_dns_misconfig.bats`

- [~] 41. Reverse WHOIS pivoting
  - Create `lib/whois_pivot.py`
  - **Files**: `lib/whois_pivot.py`, `tests/test_whois_pivot.py`

- [~] 42. Favicon hash fingerprinting
  - Create `lib/favicon_hash.py` (mmh3 hashes for Shodan)
  - **Files**: `lib/favicon_hash.py`, `tests/test_favicon_hash.py`

- [~] 43. TLS certificate chain analysis
  - Create `lib/tls_chain.py`
  - **Files**: `lib/tls_chain.py`, `tests/test_tls_chain.py`

- [~] 44. robots.txt / sitemap.xml / security.txt harvesting
  - Create `lib/meta_harvest.py`
  - **Files**: `lib/meta_harvest.py`, `tests/test_meta_harvest.py`

- [~] 45. Archive.org / public archive mining
  - Create `lib/archive_mining.py`
  - **Files**: `lib/archive_mining.py`, `tests/test_archive_mining.py`

- [~] 46. Subresource and third-party script inventory
  - Create `lib/subresource_inventory.py`
  - **Files**: `lib/subresource_inventory.py`, `tests/test_subresource_inventory.py`

- [~] 47. Passive port/service fingerprinting
  - Create `lib/passive_ports.py` (Shodan/Censys)
  - **Files**: `lib/passive_ports.py`, `tests/test_passive_ports.py`

- [~] 48. Email/domain reputation and SPF/DKIM/DMARC
  - Create `lib/email_security.py`
  - **Files**: `lib/email_security.py`, `tests/test_email_security.py`

- [~] 49. Autonomous crawl depth tuning
  - Create `lib/crawl_tuner.py`
  - **Files**: `lib/crawl_tuner.py`, `tests/test_crawl_tuner.py`

- [~] 50. Duplicate/mirror site detection
  - Create `lib/mirror_detection.py`
  - **Files**: `lib/mirror_detection.py`, `tests/test_mirror_detection.py`


## TRACK 3 — Web/API Attack Surface Testing

- [~] 51. OpenAPI/Swagger/GraphQL spec auto-ingestion
  - Create `lib/spec_ingestor.py` parsing OpenAPI/Swagger/GraphQL into structured test cases
  - **Files**: `lib/spec_ingestor.py`, `tests/test_spec_ingestor.py`

- [~] 52. GraphQL introspection abuse and batching/aliasing DoS detection
  - Create `lib/graphql_tester.py` with introspection and batching tests
  - **Files**: `lib/graphql_tester.py`, `tests/test_graphql_tester.py`

- [~] 53. GraphQL field-level authorization test harness
  - Extend `lib/graphql_tester.py` with field-level auth checks
  - **Files**: `lib/graphql_tester.py` (extend), `tests/test_graphql_auth.py`

- [~] 54. JWT deep-testing module
  - Create `lib/jwt_tester.py` with alg confusion, kid injection, weak-secret, claim tampering
  - **Files**: `lib/jwt_tester.py`, `tests/test_jwt_tester.py`

- [~] 55. SAML/OAuth flow test module
  - Create `lib/oauth_tester.py` with redirect validation, state/nonce checks
  - **Files**: `lib/oauth_tester.py`, `tests/test_oauth_tester.py`

- [~] 56. Parameter pollution and mass-assignment detection
  - Create `lib/param_pollution.py`
  - **Files**: `lib/param_pollution.py`, `tests/test_param_pollution.py`

- [~] 57. NoSQL injection coverage
  - Create `lib/nosql_injection.py` with Mongo/Elasticsearch patterns
  - **Files**: `lib/nosql_injection.py`, `tests/test_nosql_injection.py`

- [~] 58. SSTI/XXE detection with engine-specific payloads
  - Create `lib/ssti_xxe.py` and payload files in `data/payloads/`
  - **Files**: `lib/ssti_xxe.py`, `data/payloads/ssti.txt`, `data/payloads/xxe.txt`, `tests/test_ssti_xxe.py`

- [~] 59. HTTP request smuggling / desync detection
  - Create `lib/http_smuggling.py`
  - **Files**: `lib/http_smuggling.py`, `tests/test_http_smuggling.py`

- [~] 60. WAF/CDN bypass technique library
  - Create `lib/waf_bypass.py` with versioned bypass techniques per vendor
  - **Files**: `lib/waf_bypass.py`, `data/waf_signatures.json`, `tests/test_waf_bypass.py`

- [~] 61. Open redirect and host-header injection
  - Create `lib/redirect_host_injection.py`
  - **Files**: `lib/redirect_host_injection.py`, `tests/test_redirect_host_injection.py`

- [~] 62. gRPC/Protobuf endpoint discovery and fuzzing
  - Create `lib/grpc_tester.py`
  - **Files**: `lib/grpc_tester.py`, `tests/test_grpc_tester.py`

- [~] 63. WebSocket protocol testing
  - Create `lib/websocket_tester.py` (auth, message tampering, origin validation)
  - **Files**: `lib/websocket_tester.py`, `tests/test_websocket_tester.py`

- [~] 64. Server-Sent Events / long-poll endpoint testing
  - Create `lib/sse_tester.py`
  - **Files**: `lib/sse_tester.py`, `tests/test_sse_tester.py`

- [~] 65. File upload testing harness
  - Create `lib/file_upload_tester.py` (type confusion, path traversal, storage misconfig)
  - **Files**: `lib/file_upload_tester.py`, `tests/test_file_upload_tester.py`

- [~] 66. Content-Type confusion and response-splitting
  - Create `lib/content_type_tester.py`
  - **Files**: `lib/content_type_tester.py`, `tests/test_content_type_tester.py`

- [~] 67. Caching layer poisoning test module
  - Create `lib/cache_poisoning.py`
  - **Files**: `lib/cache_poisoning.py`, `tests/test_cache_poisoning.py`

- [~] 68. CORS misconfiguration matrix testing
  - Create `lib/cors_tester.py` with systematic origin matrix
  - **Files**: `lib/cors_tester.py`, `tests/test_cors_tester.py`

- [~] 69. Clickjacking / frame-ancestors policy testing
  - Create `lib/clickjacking_tester.py`
  - **Files**: `lib/clickjacking_tester.py`, `tests/test_clickjacking_tester.py`

- [~] 70. Subdomain-scoped cookie and session-isolation testing
  - Create `lib/cookie_isolation_tester.py`
  - **Files**: `lib/cookie_isolation_tester.py`, `tests/test_cookie_isolation.py`

- [~] 71. API versioning surface mapping
  - Create `lib/api_version_mapper.py`
  - **Files**: `lib/api_version_mapper.py`, `tests/test_api_version_mapper.py`

- [~] 72. Rate-limit header / 429-behavior fingerprinting
  - Create `lib/rate_limit_fingerprint.py`
  - **Files**: `lib/rate_limit_fingerprint.py`, `tests/test_rate_limit_fingerprint.py`

- [~] 73. Input validation boundary testing
  - Create `lib/input_validation_tester.py` (length, encoding, unicode normalization)
  - **Files**: `lib/input_validation_tester.py`, `tests/test_input_validation.py`

- [~] 74. Response-header security posture audit
  - Create `lib/header_audit.py` (CSP, HSTS, X-Frame-Options)
  - **Files**: `lib/header_audit.py`, `tests/test_header_audit.py`

- [~] 75. API key/token leakage detection
  - Create `lib/api_key_leakage.py` scanning bundles and responses
  - **Files**: `lib/api_key_leakage.py`, `tests/test_api_key_leakage.py`


## TRACK 4 — Business Logic & Auth Depth

- [~] 76. Stateful multi-request test engine
  - Create `lib/session_engine.py` managing session-aware request chains
  - **Files**: `lib/session_engine.py`, `tests/test_session_engine.py`

- [~] 77. IDOR test harness
  - Create `lib/idor_tester.py` with systematic object-reference substitution
  - **Files**: `lib/idor_tester.py`, `tests/test_idor_tester.py`

- [~] 78. Privilege-escalation test harness
  - Create `lib/privesc_tester.py` (horizontal and vertical)
  - **Files**: `lib/privesc_tester.py`, `tests/test_privesc_tester.py`

- [~] 79. Race-condition test harness
  - Create `lib/race_condition_tester.py` with parallel request firing and timing analysis
  - **Files**: `lib/race_condition_tester.py`, `tests/test_race_condition.py`

- [~] 80. Password-reset flow methodology execution
  - Create `lib/password_reset_tester.py`
  - **Files**: `lib/password_reset_tester.py`, `tests/test_password_reset.py`

- [~] 81. MFA-bypass methodology execution
  - Create `lib/mfa_bypass_tester.py`
  - **Files**: `lib/mfa_bypass_tester.py`, `tests/test_mfa_bypass.py`

- [~] 82. Rate-limit bypass systematic testing
  - Create `lib/rate_limit_bypass.py` (header manipulation, distributed detection)
  - **Files**: `lib/rate_limit_bypass.py`, `tests/test_rate_limit_bypass.py`

- [~] 83. Chained-vulnerability graph traversal
  - Create `lib/vuln_chain.py` combining low-severity findings into critical paths
  - **Files**: `lib/vuln_chain.py`, `tests/test_vuln_chain.py`

- [~] 84. Business-workflow abuse detection
  - Create `lib/workflow_abuse.py` (coupon/payment/quota logic)
  - **Files**: `lib/workflow_abuse.py`, `tests/test_workflow_abuse.py`

- [~] 85. Multi-tenancy isolation testing
  - Create `lib/multitenancy_tester.py`
  - **Files**: `lib/multitenancy_tester.py`, `tests/test_multitenancy.py`

- [~] 86. Session fixation and invalidation-on-logout testing
  - Create `lib/session_fixation_tester.py`
  - **Files**: `lib/session_fixation_tester.py`, `tests/test_session_fixation.py`

- [~] 87. Account-enumeration timing/response-difference testing
  - Create `lib/account_enum_tester.py`
  - **Files**: `lib/account_enum_tester.py`, `tests/test_account_enum.py`

- [~] 88. Referral/invite-flow abuse testing
  - Create `lib/referral_abuse_tester.py`
  - **Files**: `lib/referral_abuse_tester.py`, `tests/test_referral_abuse.py`

- [~] 89. Workflow state-bypass testing
  - Create `lib/state_bypass_tester.py`
  - **Files**: `lib/state_bypass_tester.py`, `tests/test_state_bypass.py`

- [~] 90. Negative-value / integer-boundary abuse testing
  - Create `lib/boundary_tester.py`
  - **Files**: `lib/boundary_tester.py`, `tests/test_boundary_tester.py`

## TRACK 5 — Cloud, CI/CD & Infra

- [~] 91. Active S3/GCS/Azure Blob ACL enumeration
  - Create `lib/cloud_acl.py` for full ACL/policy enumeration beyond existence checks
  - **Files**: `lib/cloud_acl.py`, `tests/test_cloud_acl.py`

- [~] 92. Cloud IAM misconfiguration checks
  - Create `lib/cloud_iam.py`
  - **Files**: `lib/cloud_iam.py`, `tests/test_cloud_iam.py`

- [~] 93. CI/CD pipeline config pull for secret exposure
  - Update `phases/cicd_phase.sh` to pull and scan GitHub Actions/GitLab CI/Jenkinsfiles
  - **Files**: `phases/cicd_phase.sh` (extend), `lib/cicd_scanner.py`, `tests/test_cicd_scanner.py`

- [~] 94. Supply-chain dependency risk scan
  - Create `lib/dependency_risk.py` scanning manifests for known-vulnerable packages
  - **Files**: `lib/dependency_risk.py`, `tests/test_dependency_risk.py`

- [~] 95. Container/image exposure checks
  - Create `lib/container_exposure.py`
  - **Files**: `lib/container_exposure.py`, `tests/test_container_exposure.py`

- [~] 96. Kubernetes misconfiguration checks
  - Create `lib/k8s_misconfig.py`
  - **Files**: `lib/k8s_misconfig.py`, `tests/test_k8s_misconfig.py`

- [~] 97. Webhook endpoint discovery and validation-bypass testing
  - Update `phases/webhooks_phase.sh` with validation-bypass tests
  - **Files**: `phases/webhooks_phase.sh` (extend), `lib/webhook_tester.py`, `tests/test_webhook_tester.py`

- [~] 98. Internal service discovery via non-destructive pivoting
  - Create `lib/internal_discovery.py`
  - **Files**: `lib/internal_discovery.py`, `tests/test_internal_discovery.py`

- [~] 99. Infrastructure-as-code artifact scanning
  - Create `lib/iac_scanner.py` (Terraform/CloudFormation)
  - **Files**: `lib/iac_scanner.py`, `tests/test_iac_scanner.py`

- [~] 100. Serverless function exposure checks
  - Create `lib/serverless_checker.py` (Lambda/Cloud Functions)
  - **Files**: `lib/serverless_checker.py`, `tests/test_serverless_checker.py`

- [~] 101. Cloud metadata-service exposure checks
  - Create `lib/metadata_exposure.py` (SSRF-adjacent, non-destructive)
  - **Files**: `lib/metadata_exposure.py`, `tests/test_metadata_exposure.py`

- [~] 102. Load balancer/reverse-proxy misconfiguration detection
  - Create `lib/lb_misconfig.py`
  - **Files**: `lib/lb_misconfig.py`, `tests/test_lb_misconfig.py`

- [~] 103. Email/SMTP relay misconfiguration checks
  - Create `lib/smtp_checker.py`
  - **Files**: `lib/smtp_checker.py`, `tests/test_smtp_checker.py`

- [~] 104. DNS provider API exposure checks
  - Create `lib/dns_api_exposure.py`
  - **Files**: `lib/dns_api_exposure.py`, `tests/test_dns_api_exposure.py`

- [~] 105. Backup/snapshot exposure checks
  - Create `lib/backup_exposure.py`
  - **Files**: `lib/backup_exposure.py`, `tests/test_backup_exposure.py`

- [~] 106. Message-queue exposure checks
  - Create `lib/mq_exposure.py` (Kafka/RabbitMQ/Redis)
  - **Files**: `lib/mq_exposure.py`, `tests/test_mq_exposure.py`

- [~] 107. CDN configuration audit
  - Create `lib/cdn_audit.py`
  - **Files**: `lib/cdn_audit.py`, `tests/test_cdn_audit.py`

- [~] 108. Log/monitoring endpoint exposure checks
  - Create `lib/monitoring_exposure.py` (Kibana/Grafana/Elasticsearch)
  - **Files**: `lib/monitoring_exposure.py`, `tests/test_monitoring_exposure.py`

- [~] 109. Secrets-manager misconfiguration checks
  - Create `lib/secrets_manager_checker.py`
  - **Files**: `lib/secrets_manager_checker.py`, `tests/test_secrets_manager.py`

- [~] 110. Multi-cloud asset correlation
  - Create `lib/multicloud_correlation.py`
  - **Files**: `lib/multicloud_correlation.py`, `tests/test_multicloud.py`


## TRACK 6 — Exploitation, Validation & PoC

- [~] 111. Non-destructive exploitation gate
  - Create `lib/exploitation_gate.py` — hard rule: confirmation only, never data modification
  - **Files**: `lib/exploitation_gate.py`, `tests/test_exploitation_gate.py`

- [~] 112. Automated PoC generation
  - Create `lib/poc_generator.py` generating curl/Python snippets per validated finding
  - **Files**: `lib/poc_generator.py`, `tests/test_poc_generator.py`

- [~] 113. Severity escalation logic
  - Create `lib/severity_escalator.py` adjusting CVSS from chain impact
  - **Files**: `lib/severity_escalator.py`, `tests/test_severity_escalator.py`

- [~] 114. Screenshot/visual evidence capture at validation
  - Create `lib/evidence_capture.py` integrating gowitness/aquatone
  - **Files**: `lib/evidence_capture.py`, `tests/test_evidence_capture.py`

- [~] 115. Response-diff evidence capture
  - Create `lib/response_diff.py` (before/after for logic and race findings)
  - **Files**: `lib/response_diff.py`, `tests/test_response_diff.py`

- [~] 116. Manual-review queue for low-confidence findings
  - Create `lib/manual_queue.py` managing review backlog
  - **Files**: `lib/manual_queue.py`, `tests/test_manual_queue.py`

- [~] 117. Rollback/cleanup verification
  - Create `lib/cleanup_verifier.py` ensuring test state is reverted
  - **Files**: `lib/cleanup_verifier.py`, `tests/test_cleanup_verifier.py`

- [~] 118. Rules-of-engagement pre-flight check
  - Create `lib/roe_preflight.py` checking authorization before active phases
  - **Files**: `lib/roe_preflight.py`, `tests/test_roe_preflight.py`

- [~] 119. Blast-radius estimation
  - Create `lib/blast_radius.py` (isolated vs. systemic pattern)
  - **Files**: `lib/blast_radius.py`, `tests/test_blast_radius.py`

- [~] 120. Impact-proof templating per vulnerability class
  - Create `lib/impact_templates.py` with per-class evidence structures
  - **Files**: `lib/impact_templates.py`, `data/templates/`, `tests/test_impact_templates.py`

- [~] 121. Duplicate-finding cross-check against program disclosure history
  - Create `lib/disclosure_checker.py`
  - **Files**: `lib/disclosure_checker.py`, `tests/test_disclosure_checker.py`

- [~] 122. Time-to-first-response tracking against program SLA
  - Create `lib/sla_tracker.py`
  - **Files**: `lib/sla_tracker.py`, `tests/test_sla_tracker.py`

- [~] 123. Confirmed-finding replay verification
  - Create `lib/replay_verifier.py`
  - **Files**: `lib/replay_verifier.py`, `tests/test_replay_verifier.py`

- [~] 124. Evidence redaction pipeline
  - Create `lib/evidence_redaction.py` stripping PII/secrets from captured evidence
  - **Files**: `lib/evidence_redaction.py`, `tests/test_evidence_redaction.py`

- [~] 125. Chain-of-custody logging
  - Create `lib/chain_of_custody.py` (timestamp, tool version, operator per evidence item)
  - **Files**: `lib/chain_of_custody.py`, `tests/test_chain_of_custody.py`

## TRACK 7 — Distributed Scale & Performance

- [~] 126. Target-sharded distributed scanning
  - Create `lib/distributed_scheduler.py` for Docker/K8s worker sharding
  - **Files**: `lib/distributed_scheduler.py`, `tests/test_distributed_scheduler.py`

- [~] 127. Central results queue
  - Create `lib/results_queue.py` (Redis/SQS backend) replacing disk aggregation
  - **Files**: `lib/results_queue.py`, `tests/test_results_queue.py`

- [~] 128. Per-target adaptive rate-limiting and backoff
  - Create `lib/adaptive_ratelimit.py`
  - **Files**: `lib/adaptive_ratelimit.py`, `tests/test_adaptive_ratelimit.py`

- [~] 129. Optional rotating-egress support
  - Create `lib/egress_rotation.py`
  - **Files**: `lib/egress_rotation.py`, `tests/test_egress_rotation.py`

- [~] 130. Horizontal autoscaling of worker pools
  - Create `lib/autoscaler.py` based on queue depth
  - **Files**: `lib/autoscaler.py`, `tests/test_autoscaler.py`

- [~] 131. Resource-aware scheduling
  - Create `lib/resource_scheduler.py` routing heavy phases to larger workers
  - **Files**: `lib/resource_scheduler.py`, `tests/test_resource_scheduler.py`

- [~] 132. Incremental result streaming
  - Create `lib/result_streamer.py` replacing batch writes
  - **Files**: `lib/result_streamer.py`, `tests/test_result_streamer.py`

- [~] 133. Multi-region worker deployment
  - Update `docker-compose.yml` and `Dockerfile` with multi-region support
  - **Files**: `docker-compose.yml` (extend), `lib/region_router.py`, `tests/test_region_router.py`

- [~] 134. Spot/preemptible-instance support
  - Create `lib/spot_instance_manager.py`
  - **Files**: `lib/spot_instance_manager.py`, `tests/test_spot_manager.py`

- [~] 135. Work-stealing queue design
  - Extend `lib/results_queue.py` with work-stealing logic
  - **Files**: `lib/results_queue.py` (extend), `tests/test_work_stealing.py`

- [~] 136. Bandwidth-aware throttling
  - Create `lib/bandwidth_throttle.py`
  - **Files**: `lib/bandwidth_throttle.py`, `tests/test_bandwidth_throttle.py`

- [~] 137. Scan-cost estimation/budgeting
  - Create `lib/cost_estimator.py`
  - **Files**: `lib/cost_estimator.py`, `tests/test_cost_estimator.py`

- [~] 138. Priority-lane scheduling
  - Extend `lib/resource_scheduler.py` with priority lanes
  - **Files**: `lib/resource_scheduler.py` (extend), `tests/test_priority_lanes.py`

- [~] 139. Graceful worker drain/shutdown
  - Create `lib/worker_lifecycle.py`
  - **Files**: `lib/worker_lifecycle.py`, `tests/test_worker_lifecycle.py`

- [~] 140. Cross-run resource-usage analytics
  - Create `lib/resource_analytics.py`
  - **Files**: `lib/resource_analytics.py`, `tests/test_resource_analytics.py`


## TRACK 8 — Reporting, Integration & Ecosystem

- [~] 141. Central results store + live dashboard data layer
  - Create `lib/results_store.py` with scan progress and findings feed API
  - **Files**: `lib/results_store.py`, `tests/test_results_store.py`

- [~] 142. Auto-mapping findings to CVSS and program severity rubrics
  - Create `lib/cvss_mapper.py`
  - **Files**: `lib/cvss_mapper.py`, `tests/test_cvss_mapper.py`

- [~] 143. Auto-drafted platform-formatted submissions
  - Create `lib/submission_formatter.py` (HackerOne/Bugcrowd markdown templates)
  - **Files**: `lib/submission_formatter.py`, `data/templates/h1_template.md`, `data/templates/bugcrowd_template.md`, `tests/test_submission_formatter.py`

- [~] 144. OWASP ASVS / Top 10 compliance tagging
  - Create `lib/owasp_tagger.py`
  - **Files**: `lib/owasp_tagger.py`, `data/owasp_mappings.json`, `tests/test_owasp_tagger.py`

- [~] 145. Slack/Discord/webhook notification integration
  - Create `lib/notifier.py`
  - **Files**: `lib/notifier.py`, `tests/test_notifier.py`

- [~] 146. Ticketing integration (Jira/Linear)
  - Create `lib/ticketing.py`
  - **Files**: `lib/ticketing.py`, `tests/test_ticketing.py`

- [~] 147. Plugin manifest system
  - Create `lib/plugin_manifest.py` and `config/plugins/` directory
  - New tools/phases registered via config, not core.sh edits
  - **Files**: `lib/plugin_manifest.py`, `config/plugins/README.md`, `tests/test_plugin_manifest.py`

- [~] 148. Public API layer for the framework
  - Create `lib/api_server.py` (FastAPI) with scan trigger and findings pull endpoints
  - **Files**: `lib/api_server.py`, `tests/test_api_server.py`

- [~] 149. Export pipeline (SARIF, DefectDojo, CSV)
  - Create `lib/exporter.py`
  - **Files**: `lib/exporter.py`, `tests/test_exporter.py`

- [~] 150. Program-specific rate-limit/scope-rule config profiles
  - Create `config/programs/` directory with versioned per-target profiles
  - **Files**: `config/programs/example.json`, `lib/program_config.py`, `tests/test_program_config.py`

- [~] 151. Submission-quality linter
  - Create `lib/report_linter.py` checking draft against platform formatting rules
  - **Files**: `lib/report_linter.py`, `tests/test_report_linter.py`

- [~] 152. Bounty/payout tracking dashboard data
  - Create `lib/bounty_tracker.py`
  - **Files**: `lib/bounty_tracker.py`, `tests/test_bounty_tracker.py`

- [~] 153. Team leaderboard/attribution tracking
  - Create `lib/team_attribution.py`
  - **Files**: `lib/team_attribution.py`, `tests/test_team_attribution.py`

- [~] 154. Historical write-up library
  - Create `lib/writeup_library.py` (searchable by vuln class and tech stack)
  - **Files**: `lib/writeup_library.py`, `tests/test_writeup_library.py`

- [~] 155. Client-facing report generator (PDF/DOCX)
  - Create `lib/report_generator.py` using jinja2 + weasyprint/python-docx
  - **Files**: `lib/report_generator.py`, `data/templates/client_report.html`, `tests/test_report_generator.py`

## TRACK 9 — Continuous Ops, ML & Future

- [~] 156. Real scheduler wiring for continuous monitoring
  - Create `lib/scheduler.py` (cron/systemd-timer/k8s CronJob integration)
  - **Files**: `lib/scheduler.py`, `config/cron/monitoring.cron`, `tests/test_scheduler.py`

- [~] 157. ML-assisted triage classifier
  - Create `lib/ml_triage.py` trained on historical validated vs. rejected findings
  - **Files**: `lib/ml_triage.py`, `tests/test_ml_triage.py`

- [~] 158. Anomaly detection on asset/behavior baselines
  - Create `lib/anomaly_detection.py`
  - **Files**: `lib/anomaly_detection.py`, `tests/test_anomaly_detection.py`

- [~] 159. Natural-language finding summarization
  - Create `lib/nl_summarizer.py` for non-technical stakeholder reports
  - **Files**: `lib/nl_summarizer.py`, `tests/test_nl_summarizer.py`

- [~] 160. Self-tuning scan parameters
  - Create `lib/param_tuner.py` adjusting thread count/rate limits from target history
  - **Files**: `lib/param_tuner.py`, `tests/test_param_tuner.py`

- [~] 161. Post-engagement retrospective generator
  - Create `lib/retrospective.py` aggregating metrics per program
  - **Files**: `lib/retrospective.py`, `tests/test_retrospective.py`

- [~] 162. Predictive re-scan scheduling
  - Create `lib/predictive_scheduler.py` adapting frequency to historical change rate
  - **Files**: `lib/predictive_scheduler.py`, `tests/test_predictive_scheduler.py`

- [~] 163. LLM-assisted report-writing draft pass
  - Create `lib/llm_report_drafter.py` (human-reviewed, never auto-submitted)
  - **Files**: `lib/llm_report_drafter.py`, `tests/test_llm_drafter.py`

- [~] 164. LLM-assisted false-positive pre-filtering
  - Create `lib/llm_fp_filter.py`
  - **Files**: `lib/llm_fp_filter.py`, `tests/test_llm_fp_filter.py`

- [~] 165. Model drift monitoring
  - Create `lib/model_drift_monitor.py` with retrain trigger on accuracy decay
  - **Files**: `lib/model_drift_monitor.py`, `tests/test_model_drift.py`

- [~] 166. Program-change monitoring
  - Create `lib/program_monitor.py` diffing scope/bounty-tier pages
  - **Files**: `lib/program_monitor.py`, `tests/test_program_monitor.py`

- [~] 167. Automated changelog/release-notes generation
  - Create `lib/changelog_generator.py` from git commit history
  - **Files**: `lib/changelog_generator.py`, `tests/test_changelog_generator.py`

- [~] 168. Self-diagnostic mode
  - Extend `lib/healthcheck.py` with full config/tool drift audit
  - **Files**: `lib/healthcheck.py` (extend), `tests/test_self_diagnostic.py`

- [~] 169. A/B testing harness for scan strategies
  - Create `lib/ab_testing.py`
  - **Files**: `lib/ab_testing.py`, `tests/test_ab_testing.py`

- [~] 170. Long-term knowledge base auto-curation
  - Create `lib/knowledge_base.py` from validated finding patterns
  - **Files**: `lib/knowledge_base.py`, `tests/test_knowledge_base.py`


## TRACK 10 — Mobile Application Security

- [~] 171. APK/IPA static extraction pipeline
  - Create `lib/mobile_extractor.py` (strings, endpoints, hardcoded secrets)
  - **Files**: `lib/mobile_extractor.py`, `tests/test_mobile_extractor.py`

- [~] 172. Mobile manifest/permission audit
  - Create `lib/manifest_auditor.py`
  - **Files**: `lib/manifest_auditor.py`, `tests/test_manifest_auditor.py`

- [~] 173. Mobile-to-backend API mapping
  - Create `lib/mobile_api_mapper.py`
  - **Files**: `lib/mobile_api_mapper.py`, `tests/test_mobile_api_mapper.py`

- [~] 174. Certificate pinning detection
  - Create `lib/cert_pinning_detector.py` (detection only, not bypass)
  - **Files**: `lib/cert_pinning_detector.py`, `tests/test_cert_pinning.py`

- [~] 175. Mobile deep-link / intent-filter exposure testing
  - Create `lib/deeplink_tester.py`
  - **Files**: `lib/deeplink_tester.py`, `tests/test_deeplink_tester.py`

- [~] 176. Local storage/keychain sensitive-data checks
  - Create `lib/local_storage_checker.py` (static analysis only)
  - **Files**: `lib/local_storage_checker.py`, `tests/test_local_storage.py`

- [~] 177. Mobile SDK/third-party library CVE correlation
  - Create `lib/mobile_sdk_cve.py`
  - **Files**: `lib/mobile_sdk_cve.py`, `tests/test_mobile_sdk_cve.py`

- [~] 178. WebView configuration audit
  - Create `lib/webview_auditor.py` (JS bridge exposure, mixed content)
  - **Files**: `lib/webview_auditor.py`, `tests/test_webview_auditor.py`

- [~] 179. Mobile build-artifact metadata leakage
  - Create `lib/build_artifact_checker.py`
  - **Files**: `lib/build_artifact_checker.py`, `tests/test_build_artifact.py`

- [~] 180. Push-notification service misconfiguration
  - Create `lib/push_notif_checker.py`
  - **Files**: `lib/push_notif_checker.py`, `tests/test_push_notif.py`

- [~] 181. Mobile app version-history diffing
  - Create `lib/mobile_version_diff.py`
  - **Files**: `lib/mobile_version_diff.py`, `tests/test_mobile_version_diff.py`

- [~] 182. In-app purchase/receipt-validation logic review
  - Create `lib/iap_reviewer.py` (static, non-destructive)
  - **Files**: `lib/iap_reviewer.py`, `tests/test_iap_reviewer.py`

- [~] 183. Mobile CI/CD artifact exposure checks
  - Create `lib/mobile_cicd_checker.py`
  - **Files**: `lib/mobile_cicd_checker.py`, `tests/test_mobile_cicd.py`

- [~] 184. Cross-platform framework fingerprinting
  - Create `lib/mobile_framework_fp.py` (React Native/Flutter)
  - **Files**: `lib/mobile_framework_fp.py`, `tests/test_mobile_framework_fp.py`

- [~] 185. Mobile app store metadata/OSINT correlation
  - Create `lib/app_store_osint.py`
  - **Files**: `lib/app_store_osint.py`, `tests/test_app_store_osint.py`

## TRACK 11 — Network & Protocol-Level Testing

- [~] 186. SMTP misconfiguration and relay-abuse testing
  - Create `lib/smtp_relay_tester.py`
  - **Files**: `lib/smtp_relay_tester.py`, `tests/test_smtp_relay.py`

- [~] 187. FTP/SFTP exposure and anonymous-access checks
  - Create `lib/ftp_checker.py`
  - **Files**: `lib/ftp_checker.py`, `tests/test_ftp_checker.py`

- [~] 188. SMB/NetBIOS exposure checks
  - Create `lib/smb_checker.py`
  - **Files**: `lib/smb_checker.py`, `tests/test_smb_checker.py`

- [~] 189. RDP/VNC exposure and posture checks
  - Create `lib/remote_desktop_checker.py`
  - **Files**: `lib/remote_desktop_checker.py`, `tests/test_remote_desktop.py`

- [~] 190. SNMP default-community-string exposure
  - Create `lib/snmp_checker.py`
  - **Files**: `lib/snmp_checker.py`, `tests/test_snmp_checker.py`

- [~] 191. Database port exposure checks
  - Create `lib/db_exposure_checker.py` (Mongo/Redis/Postgres/MySQL)
  - **Files**: `lib/db_exposure_checker.py`, `tests/test_db_exposure.py`

- [~] 192. VPN/remote-access endpoint fingerprinting
  - Create `lib/vpn_fingerprint.py`
  - **Files**: `lib/vpn_fingerprint.py`, `tests/test_vpn_fingerprint.py`

- [~] 193. Protocol-downgrade testing
  - Create `lib/protocol_downgrade.py`
  - **Files**: `lib/protocol_downgrade.py`, `tests/test_protocol_downgrade.py`

- [~] 194. Certificate validity/chain/expiry monitoring
  - Create `lib/cert_monitor.py`
  - **Files**: `lib/cert_monitor.py`, `tests/test_cert_monitor.py`

- [~] 195. Network segmentation inference
  - Create `lib/network_segmentation.py` (passive only)
  - **Files**: `lib/network_segmentation.py`, `tests/test_network_segmentation.py`

- [~] 196. DNS-over-HTTPS/DoT misconfiguration checks
  - Create `lib/doh_checker.py`
  - **Files**: `lib/doh_checker.py`, `tests/test_doh_checker.py`

- [~] 197. Legacy protocol exposure checks
  - Create `lib/legacy_protocol_checker.py` (Telnet, SSLv3, unencrypted FTP)
  - **Files**: `lib/legacy_protocol_checker.py`, `tests/test_legacy_protocols.py`

- [~] 198. Load-balancer health-check endpoint exposure audit
  - Create `lib/lb_healthcheck_audit.py`
  - **Files**: `lib/lb_healthcheck_audit.py`, `tests/test_lb_healthcheck.py`

- [~] 199. Port-scan result correlation with service-banner CVE database
  - Create `lib/port_cve_correlator.py`
  - **Files**: `lib/port_cve_correlator.py`, `tests/test_port_cve.py`

- [~] 200. Firewall/ACL rule-inference via reachability probing
  - Create `lib/firewall_inference.py` (non-destructive)
  - **Files**: `lib/firewall_inference.py`, `tests/test_firewall_inference.py`


## TRACK 12 — Container & Kubernetes Security

- [~] 201. Exposed Docker daemon/API detection
  - Create `lib/docker_exposure.py`
  - **Files**: `lib/docker_exposure.py`, `tests/test_docker_exposure.py`

- [~] 202. Kubernetes API server exposure and RBAC checks
  - Create `lib/k8s_api_checker.py`
  - **Files**: `lib/k8s_api_checker.py`, `tests/test_k8s_api.py`

- [~] 203. Exposed etcd instance detection
  - Create `lib/etcd_checker.py`
  - **Files**: `lib/etcd_checker.py`, `tests/test_etcd_checker.py`

- [~] 204. Container registry misconfiguration checks
  - Create `lib/registry_checker.py`
  - **Files**: `lib/registry_checker.py`, `tests/test_registry_checker.py`

- [~] 205. Kubelet API exposure checks
  - Create `lib/kubelet_checker.py`
  - **Files**: `lib/kubelet_checker.py`, `tests/test_kubelet_checker.py`

- [~] 206. Pod security policy / admission-controller posture audit
  - Create `lib/pod_security_auditor.py`
  - **Files**: `lib/pod_security_auditor.py`, `tests/test_pod_security.py`

- [~] 207. Service mesh misconfiguration checks
  - Create `lib/service_mesh_checker.py` (Istio/Linkerd)
  - **Files**: `lib/service_mesh_checker.py`, `tests/test_service_mesh.py`

- [~] 208. Container escape surface mapping
  - Create `lib/container_escape_mapper.py` (static analysis of exposed configs)
  - **Files**: `lib/container_escape_mapper.py`, `tests/test_container_escape.py`

- [~] 209. Helm chart/manifest exposure checks
  - Create `lib/helm_exposure_checker.py`
  - **Files**: `lib/helm_exposure_checker.py`, `tests/test_helm_exposure.py`

- [~] 210. Container image vulnerability correlation
  - Create `lib/image_vuln_correlator.py`
  - **Files**: `lib/image_vuln_correlator.py`, `tests/test_image_vuln.py`

## TRACK 13 — Supply Chain & Dependency Security

- [~] 211. SBOM auto-generation per scanned target
  - Create `lib/sbom_generator.py`
  - **Files**: `lib/sbom_generator.py`, `tests/test_sbom_generator.py`

- [~] 212. Dependency confusion / typosquatting exposure checks
  - Create `lib/dep_confusion_checker.py`
  - **Files**: `lib/dep_confusion_checker.py`, `tests/test_dep_confusion.py`

- [~] 213. Third-party script integrity checks (SRI)
  - Create `lib/sri_checker.py`
  - **Files**: `lib/sri_checker.py`, `tests/test_sri_checker.py`

- [~] 214. NPM/PyPI/RubyGems malicious-package correlation
  - Create `lib/package_malice_checker.py`
  - **Files**: `lib/package_malice_checker.py`, `tests/test_package_malice.py`

- [~] 215. Build-pipeline artifact provenance checks
  - Create `lib/artifact_provenance.py`
  - **Files**: `lib/artifact_provenance.py`, `tests/test_artifact_provenance.py`

- [~] 216. License-compliance auditing
  - Create `lib/license_auditor.py`
  - **Files**: `lib/license_auditor.py`, `tests/test_license_auditor.py`

- [~] 217. Abandoned/unmaintained dependency flagging
  - Create `lib/dep_staleness_checker.py`
  - **Files**: `lib/dep_staleness_checker.py`, `tests/test_dep_staleness.py`

- [~] 218. Vendor breach-history correlation
  - Create `lib/vendor_breach_checker.py`
  - **Files**: `lib/vendor_breach_checker.py`, `tests/test_vendor_breach.py`

- [~] 219. Open-source contributor account-compromise risk signals
  - Create `lib/contributor_risk_checker.py` (public signals only)
  - **Files**: `lib/contributor_risk_checker.py`, `tests/test_contributor_risk.py`

- [~] 220. Software update-mechanism security review
  - Create `lib/update_mechanism_checker.py`
  - **Files**: `lib/update_mechanism_checker.py`, `tests/test_update_mechanism.py`

## TRACK 14 — External Attack Surface Management (EASM)

- [~] 221. Continuous asset-inventory reconciliation
  - Create `lib/asset_inventory.py`
  - **Files**: `lib/asset_inventory.py`, `tests/test_asset_inventory.py`

- [~] 222. Shadow-IT detection
  - Create `lib/shadow_it_detector.py`
  - **Files**: `lib/shadow_it_detector.py`, `tests/test_shadow_it.py`

- [~] 223. M&A-driven asset absorption
  - Create `lib/ma_asset_tracker.py`
  - **Files**: `lib/ma_asset_tracker.py`, `tests/test_ma_tracker.py`

- [~] 224. Expired-domain/dangling-DNS risk monitoring
  - Create `lib/expired_domain_monitor.py`
  - **Files**: `lib/expired_domain_monitor.py`, `tests/test_expired_domain.py`

- [~] 225. Certificate-expiry-driven risk alerts
  - Create `lib/cert_expiry_alerter.py`
  - **Files**: `lib/cert_expiry_alerter.py`, `tests/test_cert_expiry.py`

- [~] 226. Asset risk-scoring dashboard data layer
  - Create `lib/asset_risk_scorer.py`
  - **Files**: `lib/asset_risk_scorer.py`, `tests/test_asset_risk_scorer.py`

- [~] 227. Public breach-database correlation for org email domains
  - Create `lib/breach_correlator.py`
  - **Files**: `lib/breach_correlator.py`, `tests/test_breach_correlator.py`

- [~] 228. Brand-impersonation/phishing-domain monitoring
  - Create `lib/brand_monitor.py` (typosquat detection)
  - **Files**: `lib/brand_monitor.py`, `tests/test_brand_monitor.py`

- [~] 229. Executive/employee public-exposure monitoring
  - Create `lib/employee_exposure_monitor.py` (informational only)
  - **Files**: `lib/employee_exposure_monitor.py`, `tests/test_employee_exposure.py`

- [~] 230. Attack-surface change velocity metric
  - Create `lib/surface_velocity.py`
  - **Files**: `lib/surface_velocity.py`, `tests/test_surface_velocity.py`

## TRACK 15 — Threat Intelligence & Dark Web Monitoring

- [~] 231. Leaked-credential monitoring
  - Create `lib/leaked_cred_monitor.py` (publicly available breach indices)
  - **Files**: `lib/leaked_cred_monitor.py`, `tests/test_leaked_cred.py`

- [~] 232. Paste-site monitoring
  - Create `lib/paste_monitor.py`
  - **Files**: `lib/paste_monitor.py`, `tests/test_paste_monitor.py`

- [~] 233. Threat-actor TTP correlation
  - Create `lib/ttp_correlator.py`
  - **Files**: `lib/ttp_correlator.py`, `tests/test_ttp_correlator.py`

- [~] 234. CVE feed integration with asset correlation
  - Create `lib/cve_feed.py`
  - **Files**: `lib/cve_feed.py`, `tests/test_cve_feed.py`

- [~] 235. Exploit-availability tracking
  - Create `lib/exploit_tracker.py` (public PoC/Metasploit existence)
  - **Files**: `lib/exploit_tracker.py`, `tests/test_exploit_tracker.py`

- [~] 236. Vendor security-advisory monitoring
  - Create `lib/vendor_advisory_monitor.py`
  - **Files**: `lib/vendor_advisory_monitor.py`, `tests/test_vendor_advisory.py`

- [~] 237. Historical incident correlation
  - Create `lib/incident_correlator.py`
  - **Files**: `lib/incident_correlator.py`, `tests/test_incident_correlator.py`

- [~] 238. Industry-sector threat-trend contextualization
  - Create `lib/sector_threat_context.py`
  - **Files**: `lib/sector_threat_context.py`, `tests/test_sector_threat.py`

- [~] 239. IOC feed cross-referencing
  - Create `lib/ioc_correlator.py`
  - **Files**: `lib/ioc_correlator.py`, `tests/test_ioc_correlator.py`

- [~] 240. Threat-intel source freshness auditing
  - Create `lib/intel_freshness_auditor.py`
  - **Files**: `lib/intel_freshness_auditor.py`, `tests/test_intel_freshness.py`


## TRACK 16 — Secrets & Credential Security

- [~] 241. Entropy-based secret detection
  - Create `lib/entropy_detector.py` beyond regex pattern matching
  - **Files**: `lib/entropy_detector.py`, `tests/test_entropy_detector.py`

- [~] 242. Verified-live-credential checking
  - Create `lib/cred_validator.py` (read-only validation, never use for access)
  - **Files**: `lib/cred_validator.py`, `tests/test_cred_validator.py`

- [~] 243. Git-history secret scanning
  - Create `lib/git_history_scanner.py` (full commit history where in scope)
  - **Files**: `lib/git_history_scanner.py`, `tests/test_git_history_scanner.py`

- [~] 244. Environment-file (.env) exposure checks
  - Create `lib/env_exposure_checker.py`
  - **Files**: `lib/env_exposure_checker.py`, `tests/test_env_exposure.py`

- [~] 245. Hardcoded-API-key detection
  - Create `lib/api_key_detector.py` (client-side and server-side artifacts)
  - **Files**: `lib/api_key_detector.py`, `tests/test_api_key_detector.py`

- [~] 246. Secrets-rotation-age inference
  - Create `lib/rotation_age_inferrer.py`
  - **Files**: `lib/rotation_age_inferrer.py`, `tests/test_rotation_age.py`

- [~] 247. Cross-repository secret correlation
  - Create `lib/cross_repo_secret_correlator.py`
  - **Files**: `lib/cross_repo_secret_correlator.py`, `tests/test_cross_repo_secrets.py`

- [~] 248. CI/CD secret-injection misconfiguration checks
  - Create `lib/cicd_secret_checker.py`
  - **Files**: `lib/cicd_secret_checker.py`, `tests/test_cicd_secrets.py`

- [~] 249. Secret-scanning coverage gap analysis
  - Create `lib/secret_coverage_analyzer.py`
  - **Files**: `lib/secret_coverage_analyzer.py`, `tests/test_secret_coverage.py`

- [~] 250. False-positive tuning for secret detection
  - Create `lib/secret_fp_tuner.py`
  - **Files**: `lib/secret_fp_tuner.py`, `tests/test_secret_fp_tuner.py`

## TRACK 17 — Wireless & IoT

- [~] 251. IoT device fingerprinting via web management interfaces
  - Create `lib/iot_fingerprint.py`
  - **Files**: `lib/iot_fingerprint.py`, `tests/test_iot_fingerprint.py`

- [~] 252. Default-credential exposure checks for IoT/embedded interfaces
  - Create `lib/iot_default_creds.py`
  - **Files**: `lib/iot_default_creds.py`, `tests/test_iot_default_creds.py`

- [~] 253. Firmware-version fingerprinting and CVE correlation
  - Create `lib/firmware_fp.py`
  - **Files**: `lib/firmware_fp.py`, `tests/test_firmware_fp.py`

- [~] 254. Exposed ICS/SCADA interface detection
  - Create `lib/ics_detector.py` (informational only)
  - **Files**: `lib/ics_detector.py`, `tests/test_ics_detector.py`

- [~] 255. UPnP exposure checks
  - Create `lib/upnp_checker.py`
  - **Files**: `lib/upnp_checker.py`, `tests/test_upnp_checker.py`

- [~] 256. MQTT broker exposure and auth-misconfiguration checks
  - Create `lib/mqtt_checker.py`
  - **Files**: `lib/mqtt_checker.py`, `tests/test_mqtt_checker.py`

- [~] 257. Bluetooth/BLE device discovery documentation
  - Create `lib/ble_discovery.py` (passive only)
  - **Files**: `lib/ble_discovery.py`, `tests/test_ble_discovery.py`

- [~] 258. Wireless network posture assessment framework hooks
  - Create `lib/wireless_assessment.py` (explicit physical scope)
  - **Files**: `lib/wireless_assessment.py`, `tests/test_wireless_assessment.py`

- [~] 259. Smart-building/IoT management-platform exposure checks
  - Create `lib/smart_building_checker.py`
  - **Files**: `lib/smart_building_checker.py`, `tests/test_smart_building.py`

- [~] 260. Device-inventory correlation into main asset graph
  - Create `lib/iot_asset_correlator.py`
  - **Files**: `lib/iot_asset_correlator.py`, `tests/test_iot_asset_correlator.py`

## TRACK 18 — Compliance & Governance

- [~] 261. OWASP ASVS level-mapping per finding (full checklist coverage)
  - Create `lib/asvs_mapper.py`
  - **Files**: `lib/asvs_mapper.py`, `data/asvs_checklist.json`, `tests/test_asvs_mapper.py`

- [~] 262. PCI-DSS control mapping for payment-flow findings
  - Create `lib/pci_mapper.py`
  - **Files**: `lib/pci_mapper.py`, `tests/test_pci_mapper.py`

- [~] 263. SOC 2 control-gap flagging
  - Create `lib/soc2_gap_flagger.py`
  - **Files**: `lib/soc2_gap_flagger.py`, `tests/test_soc2_flagger.py`

- [~] 264. GDPR/data-residency exposure flagging
  - Create `lib/gdpr_flagger.py` (informational only)
  - **Files**: `lib/gdpr_flagger.py`, `tests/test_gdpr_flagger.py`

- [~] 265. Audit-trail export for compliance consumption
  - Create `lib/audit_trail_exporter.py`
  - **Files**: `lib/audit_trail_exporter.py`, `tests/test_audit_trail.py`

- [~] 266. Policy-as-code engine for testing-rule constraints
  - Create `lib/policy_engine.py`
  - **Files**: `lib/policy_engine.py`, `config/policies/`, `tests/test_policy_engine.py`

- [~] 267. Engagement-authorization document tracking
  - Create `lib/auth_doc_tracker.py` linking scans to signed authorizations
  - **Files**: `lib/auth_doc_tracker.py`, `tests/test_auth_doc_tracker.py`

- [~] 268. Data-retention policy enforcement
  - Create `lib/retention_enforcer.py` (auto-purge after defined window)
  - **Files**: `lib/retention_enforcer.py`, `tests/test_retention_enforcer.py`

- [~] 269. Access-control audit on the framework's results store
  - Create `lib/results_access_control.py`
  - **Files**: `lib/results_access_control.py`, `tests/test_results_access.py`

- [~] 270. Regulatory-change monitoring
  - Create `lib/regulatory_monitor.py`
  - **Files**: `lib/regulatory_monitor.py`, `tests/test_regulatory_monitor.py`


## TRACK 19 — Team Collaboration & Workflow

- [~] 271. Multi-operator scan-run coordination
  - Create `lib/operator_coordination.py`
  - **Files**: `lib/operator_coordination.py`, `tests/test_operator_coordination.py`

- [~] 272. Shared finding-review workflow
  - Create `lib/finding_review.py` (assign, comment, resolve)
  - **Files**: `lib/finding_review.py`, `tests/test_finding_review.py`

- [~] 273. Role-based access control for results dashboard
  - Create `lib/rbac.py` (viewer/operator/admin tiers)
  - **Files**: `lib/rbac.py`, `tests/test_rbac.py`

- [~] 274. Handoff documentation auto-generation
  - Create `lib/handoff_generator.py`
  - **Files**: `lib/handoff_generator.py`, `tests/test_handoff_generator.py`

- [~] 275. Team capacity/workload dashboard data
  - Create `lib/workload_tracker.py`
  - **Files**: `lib/workload_tracker.py`, `tests/test_workload_tracker.py`

- [~] 276. Shared methodology/checklist library (versioned)
  - Create `lib/methodology_library.py`
  - **Files**: `lib/methodology_library.py`, `methodologies/`, `tests/test_methodology_library.py`

- [~] 277. Peer-review gate before high-severity submission
  - Create `lib/peer_review_gate.py`
  - **Files**: `lib/peer_review_gate.py`, `tests/test_peer_review.py`

- [~] 278. Engagement calendar/scheduling integration
  - Create `lib/engagement_calendar.py`
  - **Files**: `lib/engagement_calendar.py`, `tests/test_engagement_calendar.py`

- [~] 279. Onboarding mode — guided first-run walkthrough
  - Create `lib/onboarding_wizard.py`
  - **Files**: `lib/onboarding_wizard.py`, `tests/test_onboarding.py`

- [~] 280. Internal knowledge-sharing feed
  - Create `lib/knowledge_feed.py`
  - **Files**: `lib/knowledge_feed.py`, `tests/test_knowledge_feed.py`

## TRACK 20 — UX, CLI & Developer Experience

- [~] 281. Interactive CLI mode with guided prompts
  - Create `lib/interactive_cli.py` distinct from flag-driven automation mode
  - **Files**: `lib/interactive_cli.py`, `tests/test_interactive_cli.py`

- [~] 282. Rich terminal UI (progress bars, live phase status)
  - Create `lib/rich_ui.py` using rich library
  - **Files**: `lib/rich_ui.py`, `tests/test_rich_ui.py`

- [~] 283. Config-profile wizard for first-time setup
  - Create `lib/setup_wizard.py` replacing hand-edited .conf files
  - **Files**: `lib/setup_wizard.py`, `tests/test_setup_wizard.py`

- [~] 284. Dry-run mode
  - Add `--dry-run` flag to `phases/phase_manager.sh` showing what would execute without network traffic
  - **Files**: `phases/phase_manager.sh` (extend), `lib/dry_run.py`, `tests/test_dry_run.py`

- [~] 285. Verbose/debug mode with structured filterable output
  - Extend `lib/logger.py` with filterable structured debug output
  - **Files**: `lib/logger.py` (extend), `tests/test_verbose_mode.py`

- [~] 286. Shell-completion scripts (bash/zsh/fish)
  - Create `completions/dark_recon.bash`, `completions/dark_recon.zsh`, `completions/dark_recon.fish`
  - **Files**: `completions/dark_recon.bash`, `completions/dark_recon.zsh`, `completions/dark_recon.fish`

- [~] 287. Sandboxed local test-target mode
  - Create `lib/sandbox_target.py` for safely learning/testing the framework
  - **Files**: `lib/sandbox_target.py`, `tests/test_sandbox_target.py`

- [~] 288. Plugin-development SDK with scaffolding templates
  - Create `lib/plugin_sdk.py` and `templates/new_phase_template.sh`
  - **Files**: `lib/plugin_sdk.py`, `templates/new_phase_template.sh`, `templates/new_lib_template.py`

- [~] 289. Consistent exit-code and machine-readable output contract
  - Create `lib/exit_codes.py` and enforce across all phases in phase_manager.sh
  - **Files**: `lib/exit_codes.py`, `tests/test_exit_codes.py`, `tests/bats/test_exit_codes.bats`

- [~] 290. Man-page and --help auto-sync
  - Create `lib/help_generator.py` generating man-page from flag definitions
  - **Files**: `lib/help_generator.py`, `docs/dark_recon.1`, `tests/test_help_generator.py`

## TRACK 21 — Documentation, Training & Knowledge Base

- [~] 291. Full architecture documentation
  - Write `docs/architecture.md` (data flow, phase dependency graph, schema reference)
  - **Files**: `docs/architecture.md`, `docs/phase_dependency_graph.md`

- [~] 292. Per-phase methodology documentation
  - Write `docs/phases/` directory with per-phase docs linking to HowToHunt techniques
  - **Files**: `docs/phases/README.md`, `docs/phases/subdomain_phase.md`, `docs/phases/fuzz_phase.md`

- [~] 293. Runbook library for common failure modes
  - Write `docs/runbooks/` with runbooks for tool-missing, rate-limited, target-down scenarios
  - **Files**: `docs/runbooks/tool_missing.md`, `docs/runbooks/rate_limited.md`, `docs/runbooks/target_down.md`

- [~] 294. Video/screencast walkthroughs placeholder and script
  - Write `docs/screencasts/` with walkthrough scripts for new operators
  - **Files**: `docs/screencasts/01_first_scan.md`, `docs/screencasts/02_advanced_mode.md`

- [~] 295. Versioned changelog with migration notes
  - Create `CHANGELOG.md` with v1.0.0→1.0.1→1.0.2 migration notes
  - **Files**: `CHANGELOG.md`

- [~] 296. Contribution guide for adding phases/tools
  - Write `CONTRIBUTING.md` with phase plugin contribution guide
  - **Files**: `CONTRIBUTING.md`, `docs/contributing/adding_a_phase.md`

- [~] 297. Threat-model document for the framework itself
  - Write `docs/threat_model.md`
  - **Files**: `docs/threat_model.md`

- [~] 298. Glossary of vulnerability classes and severity rubrics
  - Write `docs/glossary.md`
  - **Files**: `docs/glossary.md`

- [~] 299. FAQ/troubleshooting knowledge base
  - Write `docs/faq.md` from historical support questions
  - **Files**: `docs/faq.md`

- [~] 300. Annual roadmap-review process documentation
  - Write `docs/roadmap_process.md` documenting the review ritual
  - **Files**: `docs/roadmap_process.md`
