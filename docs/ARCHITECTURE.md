# Dark Recon Framework — Architecture Documentation

## Overview

Dark Recon Framework v1.0.2 is a modular, authorized penetration testing and bug bounty reconnaissance platform for K&R Industries. All active phases are gated behind signed Rules of Engagement (ROE) documents.

## Directory Structure

```
dark_recon_framework/
├── core/
│   └── core.sh              # Core bash utilities: log(), tool_available(), cleanup()
├── lib/                     # Python library modules (new in 1.0.2)
│   ├── schema.py            # Unified data models (Asset/Finding/Endpoint/Credential/ScanRun)
│   ├── validator.py         # Schema validation layer
│   ├── logger.py            # Structured JSON logging
│   ├── errors.py            # Centralized error taxonomy
│   ├── scoring.py           # Confidence-scoring engine + decay
│   ├── delta.py             # Delta/diff engine
│   ├── dedup.py             # Finding deduplication
│   ├── scope_engine.py      # Per-program scope enforcement
│   ├── false_positives.py   # FP suppression lists
│   ├── correlation.py       # Cross-phase correlation graph
│   ├── asset_tagger.py      # Asset criticality auto-tagging
│   ├── tool_registry.py     # Tool auto-detection + degradation
│   ├── config_validator.py  # Config validation on startup
│   ├── healthcheck.py       # Framework readiness check
│   ├── secrets_hygiene.py   # Pre-commit secret scanning
│   ├── report_utils.py      # Report generation
│   ├── url_utils.py         # URL normalization + extraction
│   ├── dns_utils.py         # DNS parsing utilities
│   ├── js_analyzer.py       # JS file analysis
│   ├── jwt_tester.py        # JWT security analysis
│   ├── header_audit.py      # HTTP security header audit
│   ├── cors_tester.py       # CORS misconfiguration testing
│   ├── poc_generator.py     # PoC snippet generation
│   ├── takeover_db.py       # Subdomain takeover fingerprints
│   ├── favicon_hash.py      # MurmurHash3 favicon fingerprinting
│   ├── attack_graph.py      # Attack path data layer
│   ├── evidence_redaction.py # PII/secret redaction
│   ├── sbom.py              # Software Bill of Materials
│   └── ...
├── phases/                  # Shell phase scripts
│   ├── phase_manager.sh     # Phase orchestration + dependency DAG
│   ├── fuzz_phase.sh        # Directory fuzzing with baseline diffing
│   └── ...
├── config/
│   ├── settings.conf        # Global settings
│   ├── tools.conf           # Tool lists
│   ├── tool_weights.conf    # Confidence engine tool weights
│   ├── scopes/              # Per-program scope rules
│   └── profiles/            # Environment profiles (dev/staging/prod)
├── tests/
│   ├── test_schema.py       # Schema model tests
│   ├── test_validator.py    # Validation layer tests
│   ├── test_logger.py       # Logger tests
│   └── bats/                # Shell (bats) tests
├── cache/
│   ├── state/               # Per-target/per-phase checkpoint files
│   ├── baselines/           # Last known-good scan baselines
│   ├── fp/                  # False-positive suppression lists
│   ├── trends/              # Historical metrics
│   └── feedback/            # Triager verdict feedback
├── output/                  # Scan results (per target)
├── logs/                    # Structured JSON logs
└── plan.md                  # 300-phase implementation roadmap
```

## Data Flow

```
Target Input → Scope Check → Phase Manager → Phase Execution
                                                    ↓
                              Schema Validation ← Raw Tool Output
                                    ↓
                           Confidence Scoring
                                    ↓
                         FP Suppression Filter
                                    ↓
                          Deduplication Engine
                                    ↓
                        Delta/Diff vs Baseline
                                    ↓
                         Correlation Graph
                                    ↓
                        Attack Path Analysis
                                    ↓
                      Evidence Redaction → PoC Generation
                                    ↓
                            Report Output
```

## Phase Dependency Graph

```
scope_program_analysis
        ↓
target_intake_validation
        ↓
subdomains ──────────────────────────────────────┐
        ↓                                         │
       dns                                        │
        ↓                                         │
       live ──── tech                             │
        ↓         ↓                               │
      crawl ── params ── fuzz ── takeovers(←──────┘)
        ↓
[parallel group: waf, nuclei, ports, ssl, api, git, secrets, cloud, vuln, service]
        ↓
    reporting
        ↓
[parallel: database, webhooks, cicd, ml_analysis, compliance]
        ↓
continuous_monitoring
```

## Schema Version

Current: **1.0.2**

All phase outputs must conform to the Pydantic v2 models in `lib/schema.py`.
Use `lib/validator.py:validate_and_write()` for all file writes.

## Confidence Scoring

Scores are computed by `lib/scoring.py:ConfidenceEngine`:
- Tool reliability weight (from `config/tool_weights.conf`)
- Source corroboration count
- Evidence quality (reproduced / strong / moderate / weak)
- Cross-validation bonus
- Manual verification bonus

Scores decay over time via exponential decay (half-life: 30 days) if not re-validated.

## Error Taxonomy

All errors classified via `lib/errors.py:ErrorCode`:
- `NETWORK` — connection failures, timeouts
- `AUTH` — 401/403, credential issues
- `RATE_LIMIT` — 429, throttling
- `PARSE` — malformed output
- `TOOL_MISSING` — binary not in PATH
- `DISK` — write failures
- `CONFIG` — invalid configuration
- `SCOPE` — out-of-scope target

## Security Controls

1. **ROE Gate**: Exploitation phases check for signed authorization before any active test
2. **Non-destructive constraint**: Phase 111 hard-codes confirmation-only mode
3. **Secrets hygiene**: Pre-commit hooks + CI scanning via `lib/secrets_hygiene.py`
4. **Evidence redaction**: All output stripped of incidental PII before storage
5. **Scope enforcement**: `lib/scope_engine.py` validates every target before active phases
