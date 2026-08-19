# Contributing to Dark Recon Framework

## Adding a New Phase

1. Create `phases/<name>_phase.sh` following the template:

```bash
#!/bin/bash
# <name>_phase.sh — <description>

<name>_phase() {
    local domain="$1"
    local output_dir="${OUTPUT_DIR}/${domain}/recon_${TIMESTAMP}"
    local phase_dir="${output_dir}/<name>"
    local state_file="${CACHE_DIR}/state/${domain}/<name>.done"

    # Idempotency
    source "$(dirname "$0")/../lib/idempotency.sh"
    skip_if_done "${domain}" "<name>" && return 0

    mkdir -p "${phase_dir}"
    log "INFO" "[<name>] Starting for ${domain}"

    # ... implementation ...

    # Validate and write output using schema
    # python3 -m lib.validator finding '{"asset_id":"...","title":"...","severity":"..."}' "${phase_dir}/findings.json"

    mark_phase_done "${domain}" "<name>"
    log "INFO" "[<name>] Complete for ${domain}"
}
```

2. Register in `phases/phase_manager.sh`:
   - Add to `PHASE_DEPS` with dependencies
   - Add to `PHASE_ENABLED` with default flag
   - Add `case` handler in `run_phase()`
   - Add CLI flag in `main()`

3. Write tests in `tests/bats/test_<name>_phase.bats`

4. Document in `docs/phases/<name>.md` with methodology source

## Adding a New Python Module

1. Create `lib/<name>.py` with functions and CLI entry point
2. Add to `lib/__main__.py` SUBCOMMANDS dict
3. Write `tests/test_<name>.py` with pytest coverage ≥ 80%
4. Import from phases via `python3 -m lib.<name> <args>`

## Code Standards

- Shell: shellcheck-clean, `set -euo pipefail` in scripts (not in sourced functions)
- Python: Pydantic v2, type hints, no external dependencies beyond requirements.txt
- Tests: pytest for Python, bats for shell
- Logging: always use `log()` / `lib/logger.py` — never bare `echo` in phase logic
- Output: always validate through `lib/validator.py` before writing

## Pull Request Checklist

- [ ] All existing tests pass (`pytest` + `bats tests/bats/*.bats`)
- [ ] New tests added for new functionality
- [ ] shellcheck passes for all modified `.sh` files
- [ ] `lib/secrets_hygiene.py` scan clean on changed files
- [ ] ARCHITECTURE.md updated if data flow changed
- [ ] plan.md checkbox marked for implemented phases
