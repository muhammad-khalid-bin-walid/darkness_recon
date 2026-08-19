# Dark Recon Framework — Threat Model

This document describes the security model for the Dark Recon Framework itself — what it trusts, what it doesn't, and how it defends against abuse.

---

## Trust Boundaries

### Trusted (Framework Assumes Honest)

| Component | Trust Level | Notes |
|-----------|-------------|-------|
| Local filesystem | Full | Config files, checkpoints, logs |
| User-supplied scope rules | Full | `config/scopes/*.json` define legal boundaries |
| Python lib layer | Full | Internal code, not user-input-facing |
| Shell scripts | Full | Author-controlled, shellcheck-linted |

### Untrusted (Framework Defends Against)

| Component | Threat | Mitigation |
|-----------|--------|------------|
| Target domain responses | Malicious payloads, server-side attacks | Read-only scanning, no payload execution |
| Tool output | Malformed JSON, injection attempts | Schema validation at bridge layer |
| Network data | MitM, DNS hijacking | No credential transmission, HTTPS preference |
| Credential discoveries | Plaintext exposure | SHA-256 hash only, never stored in plaintext |
| Parallel tool output | Race conditions on shared files | Per-phase file isolation, atomic writes |

---

## Input Validation

### Target Domain Validation

```python
# lib/scope_engine.py — _extract_host()
def _extract_host(target: str) -> str:
    """Extract hostname from URL or return as-is."""
    if "://" in target:
        return urlparse(target).netloc.split(":")[0].lower()
    return target.split("/")[0].split(":")[0].lower()
```

Scope enforcement happens **before any active phase fires**:

```bash
# Every phase must call this before scanning
if ! py_scope_check "$TARGET" "$PROGRAM"; then
    log "WARN" "$TARGET is out of scope — skipping"
    exit 0
fi
```

Scope rules are per-program, stored in `config/scopes/<program>.json`:

```json
{
  "in_scope": ["*.example.com", "api.example.com"],
  "out_of_scope": ["admin.example.com", "*.internal.example.com"],
  "wildcards": ["example.com"]
}
```

### Scope Enforcement Rules

1. **Explicit opt-in**: Targets must appear in `in_scope` or match a wildcard
2. **Explicit opt-out**: `out_of_scope` takes precedence over `in_scope`
3. **No implicit scope**: Unknown domains are treated as out-of-scope
4. **Pre-phase gate**: `py_scope_check` runs before every active phase
5. **Subdomain inheritance**: `*.example.com` includes all subdomains but not `example.com` itself

---

## Secrets Handling

### Never Store Plaintext

The `Credential` model stores only the SHA-256 hash of discovered credentials:

```python
class Credential(BaseModel):
    value_hash: str = Field(
        description="SHA-256 hex digest — never store plaintext"
    )

    @staticmethod
    def hash_value(plaintext: str) -> str:
        """Return SHA-256 hex digest of plaintext."""
        return hashlib.sha256(plaintext.encode()).hexdigest()
```

### Secrets Hygiene

- `lib/secrets_hygiene.py` — Pre-commit hook scans for leaked keys
- `.gitignore` excludes `cache/`, `output/`, `logs/`, `temp/`
- No credential values in structured JSON logs
- Evidence redaction pipeline strips incidental PII before storage

### Credential Checks Are Read-Only

The framework **never** uses discovered credentials to authenticate. It only:

1. Detects their existence (entropy analysis, regex matching)
2. Records their location (file/URL/header)
3. Hashes their value for deduplication
4. Reports them as findings

---

## Tool Integrity

### Auto-Detection with Fallback

`lib/tool_registry.py` manages tool availability:

```python
@dataclass
class ToolEntry:
    name: str
    capabilities: list[str]
    fallbacks: list[str]          # Alternative tools if primary missing
    degraded_mode_warning: str    # What gets skipped
    essential: bool               # Fail-fast if missing
    install_hint: str             # How to install
```

### Version Pinning

Tool versions are pinned in `lib/tool_versions.conf`:

```
subfinder=v2.6.7
httpx=v1.6.1
katana=v1.1.7
nuclei=v3.3.7
```

### No Auto-Update Without Verification

- Framework checks installed tool versions against pinned versions
- Mismatch triggers a warning, never an automatic update
- `--install` flag installs pinned versions only
- Tool checksums verified where available (e.g., nuclei template hashes)

---

## Output Integrity

### Findings Are Append-Only

Findings are written once and never mutated in place:

```python
class Finding(BaseModel):
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    status: FindingStatus = Field(default=FindingStatus.NEW)
```

Status transitions: `new → validated | false_positive | duplicate`

No status can revert to `new`. No finding can be deleted by the framework.

### Tamper-Evident Logging

Structured JSON logs include timestamps and phase metadata:

```json
{
  "timestamp": "2026-01-15T10:30:00Z",
  "level": "INFO",
  "phase": "idor_test",
  "target": "example.com",
  "event": "finding_written",
  "duration_ms": 1250
}
```

Log files are append-only and never rotated by the framework.

### Fingerprint-Based Deduplication

Findings are deduplicated using content-based fingerprints, not IDs:

```python
# lib/dedup.py
fingerprint = sha256(asset_id + title + severity + phase)
```

Same vulnerability found by different tools produces a single finding with the highest confidence score.

---

## Network Safety

### Rate Limiting

```bash
# Default rate limit (configurable per program)
readonly DEFAULT_RATE_LIMIT=1000  # requests per second

# Per-target adaptive rate limiting
# lib/adaptive_depth.py adjusts based on target responsiveness
```

### Scope Guards

```bash
# Every active phase checks scope before firing
py_scope_check "$TARGET" "$PROGRAM" || exit 0

# Wildcard patterns prevent accidental out-of-scope scanning
```

### No Destructive Operations

The framework is **read-only** against targets:

- **No exploitation** that modifies data (Track 6 phase 111: "confirmation only, never data modification")
- **No authentication bypass** that creates sessions
- **No file uploads** that persist on target
- **No credential stuffing** or brute-force
- **No denial-of-service** testing (rate limits enforced)

### Retry with Backoff

```bash
retry_with_backoff() {
    local max_retries="${1:-$MAX_RETRIES}"
    local delay="${2:-1}"
    # Exponential backoff: 1s, 2s, 4s...
    # Prevents hammering rate-limited targets
}
```

---

## Privilege Model

### Runs as User

- No root/sudo required for any operation
- No credential storage beyond hash values
- No system service installation
- No firewall or network configuration changes

### Principle of Least Privilege

| Operation | Required Access |
|-----------|-----------------|
| Tool execution | User-level PATH only |
| File writes | `output/`, `cache/`, `logs/` directories |
| Network reads | Outbound HTTP/HTTPS/DNS only |
| Config reads | `config/` directory |
| No inbound connections required | Framework never listens on ports |

---

## Supply Chain Risks

### Dependency Pinning

```txt
# requirements.txt
pydantic>=2.0,<3.0
requests>=2.31,<3.0
```

### Tool Version Locking

All wrapped tools are pinned to specific versions in `lib/tool_versions.conf`. The framework:

1. Checks installed version against pinned version
2. Warns on mismatch
3. Never auto-updates without explicit user action
4. Verifies checksums where tool provides them

### No Remote Code Execution

- No `eval()` on tool output
- No `exec()` on network-received data
- No dynamic import based on user input
- Shell scripts use `set -euo pipefail` to prevent silent failures

---

## Error Taxonomy

`lib/errors.py` centralizes error handling:

| Code | Category | Typical Cause | Framework Response |
|------|----------|---------------|-------------------|
| `NETWORK` | Connectivity | DNS failure, timeout | Retry with backoff, then skip |
| `AUTH` | Authentication | 401/403 response | Log, skip phase, alert |
| `RATE_LIMIT` | Throttling | 429 response | Backoff, reduce parallelism |
| `PARSE` | Malformed data | Unexpected tool output | Log error, continue with partial |
| `TOOL_MISSING` | Availability | Tool not in PATH | Check fallback, degrade gracefully |
| `DISK` | Storage | Full disk | Clean temp files, checkpoint |
| `CONFIG` | Configuration | Missing/invalid config | Fail-fast, report error |
| `SCOPE` | Scope violation | Target out of scope | Skip silently, log warning |

---

## Cross-References

- [ARCHITECTURE.md](ARCHITECTURE.md) — Component details and data flow
- [GLOSSARY.md](GLOSSARY.md) — Security terminology
- [RUNBOOKS.md](RUNBOOKS.md) — Operational response to security events
