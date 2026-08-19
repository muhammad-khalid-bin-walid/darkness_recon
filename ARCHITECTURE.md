# Dark Recon Framework — Architecture

## System Overview

Dark Recon is a 300-phase, 22-track automated security reconnaissance framework. It combines a **bash shell layer** (phase orchestration, tool invocation, checkpoint management) with a **Python lib layer** (schema validation, scoring, deduplication, scope enforcement).

```
dark_recon_framework/
├── core/core.sh              # Shell runtime: logging, error handling, retry, tool detection
├── phases/
│   ├── phase_manager.sh      # Phase registry, dependency graph, execution order
│   ├── phase_bridge.sh → lib/phase_bridge.sh   # Shell→Python bridge calls
│   └── <n>_phase.sh          # Individual phase scripts (298 files)
├── lib/
│   ├── schema.py             # Pydantic v2 models (Asset, Finding, Endpoint, Credential, ScanRun)
│   ├── phase_bridge.py       # Python CLI bridge (validate, log, score, dedup, scope)
│   ├── errors.py             # Centralized error taxonomy (NETWORK, AUTH, RATE_LIMIT, ...)
│   ├── scope_engine.py       # Per-program in-scope/out-of-scope enforcement
│   ├── scoring.py            # Confidence scoring engine
│   ├── dedup.py              # Fingerprint-based finding deduplication
│   ├── checkpoint.py         # Per-target, per-phase checkpoint/resume
│   ├── tool_registry.py      # Tool auto-detection with graceful degradation
│   └── ...                   # 40+ additional Python modules
├── scripts/                  # Standalone helper scripts
├── config/
│   ├── settings.conf         # Global runtime settings
│   ├── tools.conf            # Tool-specific config
│   ├── tool_weights.conf     # Confidence model weights per tool
│   └── profiles/             # Per-program scan profiles
├── output/                   # Scan results (JSON)
├── logs/                     # Structured JSON + human-readable logs
└── cache/                    # Checkpoints, state, temp files
```

---

## Data Flow

```
Target Input
     │
     ▼
┌─────────────────┐
│ Scope Validation │  py_scope_check / scope_engine.py
└────────┬────────┘
         │  in-scope targets only
         ▼
┌─────────────────┐
│ Phase Execution  │  phase_manager.sh → phases/<name>_phase.sh
│  (ordered by     │
│   dependency)    │
└────────┬────────┘
         │  each phase produces JSON artifacts
         ▼
┌─────────────────┐
│ Bridge Layer     │  py_validate / py_log / py_score
│  (schema + log)  │
└────────┬────────┘
         │  validated, typed objects
         ▼
┌─────────────────┐
│ Findings         │  lib/dedup.py, lib/scoring.py
│ Aggregation      │
└────────┬────────┘
         │  deduplicated, scored findings
         ▼
┌─────────────────┐
│ Report           │  phases/reporting_phase.sh, lib/report_utils.py
│ Generation       │  (SARIF, HTML, JSON, platform templates)
└─────────────────┘
```

---

## Core Components

### `core/core.sh` — Shell Runtime

The foundation layer. Every phase script sources this. Provides:

| Function | Purpose |
|----------|---------|
| `log` | Structured JSON + human-readable logging |
| `handle_error` | Graceful degradation on non-critical failures |
| `retry_with_backoff` | Exponential backoff for transient errors |
| `tool_available` | Check if a CLI tool exists in PATH |
| `check_essential_tools` | Fail-fast on missing required tools |
| `cleanup` | EXIT trap — checkpoint state, remove temp files |

Key configuration:
- `DEFAULT_THREADS=150` — parallel job count
- `DEFAULT_TIMEOUT=300` — per-command timeout (seconds)
- `DEFAULT_RATE_LIMIT=1000` — requests per second cap
- `MAX_RETRIES=2` — retry attempts before giving up

### `phases/phase_manager.sh` — Phase Orchestrator

Loads `PHASE_DEPS` (dependency graph) and `PHASE_ENABLED` (toggle map). Executes phases in topological order respecting dependencies:

```bash
# From phase_manager.sh
declare -A PHASE_DEPS
PHASE_DEPS=(
    [subdomains]=""
    [dns]="subdomains"
    [live]="dns"
    [tech]="live"
    [crawl]="live"
    [params]="crawl"
    [fuzz]="live"
    [takeovers]="subdomains live"
    ...
)
```

### `lib/phase_bridge.sh` + `lib/phase_bridge.py` — Shell↔Python Bridge

Shell phases call Python lib functions through bridge wrappers:

```bash
# Validate and write an asset to output
py_validate "asset" "$asset_json" "$OUTPUT_DIR/assets.json"

# Structured logging
py_log INFO "scan_started" --phase "subdomains" --target "example.com"

# Scope check (returns 0 if in scope, 1 if not)
py_scope_check "evil.example.com" "example_program"

# Confidence scoring
py_score 3 0.8 true  # source_count, evidence_quality, cross_validated
```

### `lib/schema.py` — Unified Data Models

All phases read/write these Pydantic v2 models. See [Schema Reference](#schema-reference) below.

---

## Phase Lifecycle

Every phase follows a 5-step lifecycle:

```
1. PREFLIGHT
   ├── Check essential tools (tool_available)
   ├── Validate target is in scope (py_scope_check)
   └── Load checkpoint — skip if already completed (idempotent)

2. EXECUTE
   ├── Run tool commands with retry_with_backoff
   ├── Capture stdout/stderr
   └── Handle errors gracefully (handle_error / GRACEFUL_DEGRADATION)

3. VALIDATE
   ├── Parse raw tool output into JSON
   ├── Validate against schema (py_validate)
   └── Reject malformed output at write time

4. BRIDGE
   ├── Emit structured logs (py_log)
   ├── Write findings with write_finding (dedup fingerprint)
   ├── Update asset/endpoint inventory
   └── Compute confidence score (py_score)

5. CHECKPOINT
   ├── Write phase completion marker to cache/state/
   ├── Save partial results for resume
   └── Update ScanRun.phases_run list
```

Idempotent design: re-running a phase never duplicates or corrupts prior output. Checkpoints are per-target, per-phase.

---

## Schema Reference

### `Asset`

A unique discovered entity in the target environment.

```json
{
  "id": "uuid",
  "domain": "example.com",
  "ip": "93.184.216.34",
  "asn": "AS15133",
  "type": "web|api|infra",
  "criticality": "prod|staging|dev",
  "tags": ["cdn", "cloudflare"],
  "discovered_at": "2026-01-15T10:30:00Z",
  "source": "subfinder"
}
```

### `Finding`

A security observation attached to an asset.

```json
{
  "id": "uuid",
  "asset_id": "asset-uuid",
  "title": "IDOR on /api/v1/users/{id}",
  "description": "...",
  "severity": "critical|high|medium|low|info",
  "confidence": 0.85,
  "status": "new|validated|false_positive|duplicate",
  "phase": "idor_test",
  "tool": "custom_idor_engine",
  "evidence": { "poc_curl": "curl ..." },
  "fingerprint": "sha256-dedup-hash",
  "created_at": "2026-01-15T10:30:00Z",
  "updated_at": "2026-01-15T10:30:00Z"
}
```

### `Endpoint`

A specific HTTP endpoint discovered on an asset.

```json
{
  "id": "uuid",
  "asset_id": "asset-uuid",
  "url": "https://api.example.com/v1/users",
  "method": "GET",
  "status_code": 200,
  "content_type": "application/json",
  "parameters": ["id", "token"],
  "headers": {},
  "discovered_at": "2026-01-15T10:30:00Z"
}
```

### `Credential`

A discovered credential. **Plaintext is never stored** — only its SHA-256 hash.

```json
{
  "id": "uuid",
  "asset_id": "asset-uuid",
  "type": "api_key|password|token|certificate",
  "value_hash": "sha256-hex-digest",
  "source": "js-bundle-analysis",
  "discovered_at": "2026-01-15T10:30:00Z",
  "rotation_age_days": 90
}
```

### `ScanRun`

Top-level container for one complete (or in-progress) scan execution.

```json
{
  "id": "uuid",
  "target": "example.com",
  "profile": "prod",
  "started_at": "2026-01-15T10:00:00Z",
  "completed_at": null,
  "phases_run": ["subdomains", "dns", "live"],
  "findings_count": 12,
  "status": "running|completed|failed|paused",
  "schema_version": "1.0.2"
}
```

---

## Dependency Graph (22 Tracks)

Tracks 0–1 are load-bearing for everything after them — do not parallelize ahead of them.

| Track | Name | Phases | Dependencies |
|-------|------|--------|--------------|
| 0 | Foundation & Reliability | 1–15 | None (foundational) |
| 1 | Data Model & Correlation | 16–30 | Track 0 |
| 2 | Recon & Discovery | 31–50 | Tracks 0–1 |
| 3 | Web/API Attack Surface | 51–75 | Tracks 0–1 |
| 4 | Business Logic & Auth | 76–90 | Tracks 0–3 |
| 5 | Cloud, CI/CD & Infra | 91–110 | Tracks 0–2 |
| 6 | Exploitation & Validation | 111–125 | Tracks 0–5 |
| 7 | Distributed Scale | 126–140 | Tracks 0–1 |
| 8 | Reporting & Integration | 141–155 | Tracks 0–6 |
| 9 | Continuous Ops & ML | 156–170 | Tracks 0–8 |
| 10 | Mobile App Security | 171–185 | Tracks 0–3 |
| 11 | Network & Protocol | 186–200 | Tracks 0–2 |
| 12 | Container & Orchestration | 201–215 | Tracks 0–2, 5 |
| 13 | Supply Chain Security | 216–230 | Tracks 0–2 |
| 14 | Threat Intelligence | 231–245 | Tracks 0–2 |
| 15 | Compliance & Standards | 246–260 | Tracks 0–8 |
| 16 | Collaboration & Workflow | 261–270 | Tracks 0–1, 8 |
| 17 | EASM & Brand Protection | 271–280 | Tracks 0–2 |
| 18 | Secrets & Credential Mgmt | 281–285 | Tracks 0–2 |
| 19 | IoT & Embedded | 286–290 | Tracks 0–2, 11 |
| 20 | Serverless & Edge | 291–295 | Tracks 0–2, 5 |
| 21 | UX & Operator Experience | 296–300 | Tracks 0–1 |

---

## Extension Points

### Adding a New Phase

1. Create `phases/<name>_phase.sh` following the [phase template](CONTRIBUTING.md#phase-script-template)
2. Register dependencies in `PHASE_DEPS` within `phases/phase_manager.sh`
3. Add tool entries to `TOOL_PACKAGES` in `core/core.sh` if using new tools
4. Add tool metadata to `lib/tool_registry.py` for auto-detection and fallback

### Adding a New Tool

1. Add tool name to `TOOL_PACKAGES` in `core/core.sh`
2. Add `ToolEntry` to `REGISTRY` in `lib/tool_registry.py`
3. Add fallback chain and degraded-mode warnings
4. Pin version in `lib/tool_versions.conf`

### Adding a New Report Format

1. Add export function to `lib/report_utils.py`
2. Register the format in `phases/reporting_phase.sh`
3. Add output path configuration to `config/settings.conf`

### Adding a New Schema Field

1. Add field to the relevant model in `lib/schema.py`
2. Add validation rule if needed
3. Update `SCHEMA_REGISTRY` in `lib/validator.py`
4. Bump `SCHEMA_VERSION` constant

---

## Cross-References

- [CONTRIBUTING.md](CONTRIBUTING.md) — How to add phases and tools
- [THREAT_MODEL.md](THREAT_MODEL.md) — Security model for the framework
- [GLOSSARY.md](GLOSSARY.md) — Vulnerability classes and terminology
- [FAQ.md](FAQ.md) — Troubleshooting and configuration
- [RUNBOOKS.md](RUNBOOKS.md) — Operational runbooks for common failures
