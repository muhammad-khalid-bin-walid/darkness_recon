# Dark Recon Framework — Contributing Guide

## Prerequisites

- **bash** (4.0+) — strict mode (`set -euo pipefail`)
- **python3** (3.10+) — Pydantic v2, type hints
- **shellcheck** — lint all shell scripts before submitting
- **pytest** — run `pytest` from project root
- Required tools: `subfinder`, `httpx`, `katana`, `whatweb`, `unfurl`, `jq` (see `ESSENTIAL_TOOLS` in `core/core.sh`)

---

## Phase Script Template

Copy an existing phase and adapt. Every phase lives at `phases/<name>_phase.sh`.

```bash
#!/bin/bash
# phases/<name>_phase.sh — <Short description>
# shellcheck shell=bash

set -euo pipefail

# Source core + bridge
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../core/core.sh"
source "$SCRIPT_DIR/../lib/phase_bridge.sh"

# --- Configuration ---
PHASE_NAME="<name>"
PHASE_TARGET="${1:?Usage: $0 <target>}"
PHASE_OUTPUT="$OUTPUT_DIR/$PHASE_NAME"

mkdir -p "$PHASE_OUTPUT"

log "INFO" "Starting $PHASE_NAME phase for $PHASE_TARGET"

# --- Preflight: scope check ---
if ! py_scope_check "$PHASE_TARGET" "${PROGRAM:-default}"; then
    log "WARN" "$PHASE_TARGET is out of scope — skipping $PHASE_NAME"
    exit 0
fi

# --- Preflight: checkpoint ---
CHECKPOINT_FILE="$CACHE_DIR/state/${PHASE_NAME}_${PHASE_TARGET}.done"
if [ -f "$CHECKPOINT_FILE" ]; then
    log "INFO" "$PHASE_NAME already completed for $PHASE_TARGET — skipping"
    exit 0
fi

# --- Execute: run tools ---
# Example: subdomain enumeration
TOOL_OUTPUT="$PHASE_NAME_raw.json"
subfinder -d "$PHASE_TARGET" -silent -o "$PHASE_NAME_raw.txt" || {
    log "WARN" "subfinder failed — continuing with partial results"
}

# --- Validate: parse and validate ---
# Convert raw output to JSON
python3 -c "
import json, sys
results = []
with open('$PHASE_NAME_raw.txt') as f:
    for line in f:
        line = line.strip()
        if line:
            results.append({'domain': line, 'source': 'subfinder'})
json.dump(results, sys.stdout, indent=2)
" > "$PHASE_NAME_parsed.json"

# Validate against schema
py_validate_file "asset" "$PHASE_NAME_parsed.json" "$PHASE_OUTPUT/assets.json"

# --- Bridge: log + findings ---
py_log INFO "phase_completed" \
    --phase "$PHASE_NAME" \
    --target "$PHASE_TARGET" \
    --extra "{\"tool\": \"subfinder\", \"results\": $(wc -l < "$PHASE_NAME_raw.txt")}"

# Write findings if any
if [ -s "$PHASE_OUTPUT/assets.json" ]; then
    write_finding "$PHASE_TARGET" "$PHASE_NAME" "subdomain_discovery" "info" \
        "Discovered $(wc -l < "$PHASE_NAME_raw.txt") subdomains"
fi

# --- Checkpoint ---
touch "$CHECKPOINT_FILE"

log "INFO" "Completed $PHASE_NAME phase for $PHASE_TARGET"
```

### Function Naming Conventions

| Pattern | Purpose |
|---------|---------|
| `run_<tool>()` | Wrapper for a single tool invocation |
| `parse_<tool>_output()` | Convert raw tool output to structured JSON |
| `check_<condition>()` | Preflight or guard checks |
| `handle_<error_type>()` | Error-specific recovery logic |

### Bridge Calls (Required)

Every phase **must** call these at the end:

```bash
# Structured logging (required)
py_log INFO "phase_completed" --phase "$PHASE_NAME" --target "$PHASE_TARGET"

# Write findings (if any discovered)
write_finding "$TARGET" "$PHASE" "$TITLE" "$SEVERITY" "$DESCRIPTION"
```

See `lib/phase_bridge.sh` for all available bridge functions.

---

## Phase Registration

Add to `phases/phase_manager.sh`:

```bash
# In PHASE_DEPS array:
declare -A PHASE_DEPS
PHASE_DEPS=(
    ...
    [your_phase]="dependency1 dependency2"  # space-separated deps
    ...
)
```

**Rules:**
- Dependencies must be other phase names registered in `PHASE_DEPS`
- Empty string `""` means no dependencies (runs in Track 0)
- Topological sort determines execution order
- Do not create circular dependencies

---

## Python Lib Module Conventions

All `lib/*.py` modules follow these conventions:

```python
"""
lib/<module>.py — <Description> (plan Phase <N>)

Brief explanation of what this module does and which phase(s) it supports.
"""
from __future__ import annotations

import json
from typing import Any, Optional

from pydantic import BaseModel, Field


class MyModel(BaseModel):
    """Pydantic model with docstrings on every field."""

    id: str = Field(description="Unique identifier")
    name: str = Field(description="Human-readable name")
    value: Optional[float] = Field(default=None, description="Optional numeric value")

    def to_json(self, *, indent: int | None = None) -> str:
        return self.model_dump_json(indent=indent)

    @classmethod
    def from_json(cls, data: str | bytes) -> "MyModel":
        return cls.model_validate_json(data)


def my_function(target: str, *, timeout: int = 30) -> dict[str, Any]:
    """Do something with the target.

    Args:
        target: The domain or IP to operate on.
        timeout: Maximum seconds to wait.

    Returns:
        Dict with 'success' key and optional 'data' or 'error'.
    """
    ...
```

**Rules:**
- Always use `from __future__ import annotations`
- All fields must have `Field(description=...)`
- Models need `to_json()` and `from_json()` class methods
- Functions return `dict[str, Any]` with `success`/`error` keys
- Type hints on all parameters and return values
- Docstrings on public functions (Google style)
- No `import *` — explicit imports only
- Pin dependencies in `requirements.txt`

---

## Testing Requirements

### Python (pytest)

```bash
# Run all tests
pytest

# Run specific module tests
pytest tests/test_schema.py

# Run with coverage
pytest --cov=lib --cov-report=term-missing
```

Tests live in `tests/` and mirror `lib/` structure:

```
tests/
├── test_schema.py
├── test_scoring.py
├── test_dedup.py
├── test_scope_engine.py
└── ...
```

### Shell (shellcheck + bats)

```bash
# Lint all shell scripts
shellcheck phases/*.sh core/*.sh lib/*.sh

# Run integration tests (if bats installed)
bats tests/
```

### Test Requirements for New Code

| Type | Minimum | Tool |
|------|---------|------|
| Python unit tests | 80% coverage | pytest + coverage |
| Shell lint | 0 warnings | shellcheck |
| Schema validation | All models tested | pytest |
| Phase scripts | Smoke test with mock target | bats |

---

## PR Checklist

Before submitting a pull request:

- [ ] **Tests pass**: `pytest` green, `shellcheck` clean
- [ ] **Schema valid**: New/modified models pass `py_validate`
- [ ] **Bridge calls present**: Phase scripts call `py_log` and `write_finding`
- [ ] **Checkpoint support**: Phase uses checkpoint file for idempotency
- [ ] **Scope check**: Phase calls `py_scope_check` before active operations
- [ ] **No secrets in output**: Credential values hashed via `Credential.hash_value()`
- [ ] **Error handling**: Graceful degradation for non-critical failures
- [ ] **Docstrings**: All public Python functions documented
- [ ] **Type hints**: All function signatures typed
- [ ] **shellcheck clean**: No shellcheck warnings
- [ ] **One logical change**: PR contains one focused change

---

## Code Style

### Bash

```bash
#!/bin/bash
set -euo pipefail

# Use log() for output, never raw echo for errors
log "INFO" "message"
log "ERROR" "something broke"

# Use py_log at the end of every phase
py_log INFO "phase_completed" --phase "$PHASE_NAME"

# Use write_finding for discoveries, never raw echo
write_finding "$TARGET" "$PHASE" "$TITLE" "$SEVERITY" "$DESC"

# Use retry_with_backoff for flaky network operations
retry_with_backoff 3 2 "curl -sSf https://target.com"

# Quote all variables: "$VAR" not $VAR
# Use [[ ]] not [ ] for conditionals
# Use $(command) not `command`
```

### Python

```python
# Prefer const/let over var (TypeScript mindset in Python)
# Use dataclasses or Pydantic, not raw dicts for structured data
# Use pathlib, not os.path
# f-strings, not .format() or %
# walrus operator where it improves readability
# No mutable default arguments
def my_func(items: list[str] | None = None) -> dict[str, Any]:
    if items is None:
        items = []
    ...
```

---

## Cross-References

- [ARCHITECTURE.md](ARCHITECTURE.md) — System overview and phase lifecycle
- [GLOSSARY.md](GLOSSARY.md) — Terminology reference
- [RUNBOOKS.md](RUNBOOKS.md) — Common failure modes and fixes
