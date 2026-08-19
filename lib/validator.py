"""
lib/validator.py — Schema validation layer for Dark Recon Framework

Public API
----------
validate_and_write(data, model_class, output_path) -> bool
    Validate a raw dict against a Pydantic model, then write JSON on success.

validate_finding(data) -> bool
    Convenience wrapper: validate dict against the Finding model.

validate_asset(data) -> bool
    Convenience wrapper: validate dict against the Asset model.

validate_json_file(filepath, model_class) -> tuple[bool, list]
    Read an existing JSON file and validate it; returns (ok, errors).

All validation errors are written to stderr as a JSON object with
keys: level, error, data.

When invoked as a module (python3 -m lib.validator <model_type> <json_string>
[output_file]) it exits 0 on valid, 1 on invalid, 2 on bad usage.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Type

from pydantic import BaseModel, ValidationError

from lib.schema import Asset, Credential, Endpoint, Finding, ScanRun

# ---------------------------------------------------------------------------
# Registry: maps CLI / convenience names to Pydantic model classes
# ---------------------------------------------------------------------------

SCHEMA_REGISTRY: dict[str, Type[BaseModel]] = {
    "asset": Asset,
    "finding": Finding,
    "endpoint": Endpoint,
    "credential": Credential,
    "scanrun": ScanRun,
    # alternate spellings kept for backwards compatibility
    "scan_run": ScanRun,
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _log_error(error_msg: str, data: Any) -> None:
    """Write a structured error record to stderr as a JSON line."""
    record = json.dumps(
        {"level": "ERROR", "error": error_msg, "data": data},
        default=str,
    )
    print(record, file=sys.stderr)


def _format_pydantic_errors(exc: ValidationError) -> list[str]:
    """Return a list of human-readable error strings from a ValidationError."""
    messages: list[str] = []
    for err in exc.errors():
        loc = " -> ".join(str(x) for x in err["loc"]) if err["loc"] else "<root>"
        messages.append(f"field='{loc}' msg='{err['msg']}'")
    return messages


# ---------------------------------------------------------------------------
# Core public functions
# ---------------------------------------------------------------------------


def validate_and_write(
    data: dict,
    model_class: Type[BaseModel],
    output_path: str,
) -> bool:
    """
    Validate *data* against *model_class* and, on success, write the
    validated JSON to *output_path*.

    Parameters
    ----------
    data:
        Raw dictionary to validate.
    model_class:
        A Pydantic model class (Asset, Finding, Endpoint, Credential, ScanRun).
    output_path:
        Destination file path.  Parent directories are created automatically.

    Returns
    -------
    bool
        True if validation succeeded and the file was written, False otherwise.
        On failure a JSON error record is emitted to stderr.
    """
    try:
        instance = model_class.model_validate(data)
    except ValidationError as exc:
        error_details = "; ".join(_format_pydantic_errors(exc))
        _log_error(
            f"Validation failed for {model_class.__name__}: {error_details}",
            data,
        )
        return False
    except Exception as exc:  # noqa: BLE001
        _log_error(f"Unexpected error during validation: {exc}", data)
        return False

    # Write to disk
    try:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(instance.to_json(indent=2), encoding="utf-8")
    except OSError as exc:
        _log_error(f"Failed to write output file '{output_path}': {exc}", data)
        return False

    return True


def validate_finding(data: dict) -> bool:
    """
    Convenience wrapper: validate *data* against the Finding model.

    Returns True on success, False on failure (error written to stderr).
    Output is not persisted; use validate_and_write for persistence.
    """
    try:
        Finding.model_validate(data)
        return True
    except ValidationError as exc:
        error_details = "; ".join(_format_pydantic_errors(exc))
        _log_error(f"Finding validation failed: {error_details}", data)
        return False
    except Exception as exc:  # noqa: BLE001
        _log_error(f"Unexpected error validating Finding: {exc}", data)
        return False


def validate_asset(data: dict) -> bool:
    """
    Convenience wrapper: validate *data* against the Asset model.

    Returns True on success, False on failure (error written to stderr).
    Output is not persisted; use validate_and_write for persistence.
    """
    try:
        Asset.model_validate(data)
        return True
    except ValidationError as exc:
        error_details = "; ".join(_format_pydantic_errors(exc))
        _log_error(f"Asset validation failed: {error_details}", data)
        return False
    except Exception as exc:  # noqa: BLE001
        _log_error(f"Unexpected error validating Asset: {exc}", data)
        return False


def validate_json_file(
    filepath: str,
    model_class: Type[BaseModel],
) -> tuple[bool, list]:
    """
    Read an existing JSON file and validate its contents against *model_class*.

    Parameters
    ----------
    filepath:
        Path to the JSON file to validate.
    model_class:
        Pydantic model class to validate against.

    Returns
    -------
    tuple[bool, list]
        (True, []) when the file is valid.
        (False, [error_string, ...]) when validation fails.
        The error list describes parse errors or schema violations.
    """
    p = Path(filepath)

    # --- read file ---
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"Cannot read '{filepath}': {exc}"
        _log_error(msg, {"filepath": filepath})
        return False, [msg]

    # --- parse JSON ---
    try:
        data: Any = json.loads(raw)
    except json.JSONDecodeError as exc:
        msg = f"Invalid JSON in '{filepath}' at line {exc.lineno}, col {exc.colno}: {exc.msg}"
        _log_error(msg, {"filepath": filepath, "raw_snippet": raw[:200]})
        return False, [msg]

    # --- schema validation ---
    try:
        model_class.model_validate(data)
        return True, []
    except ValidationError as exc:
        errors = _format_pydantic_errors(exc)
        for err in errors:
            _log_error(
                f"Schema validation failed for {model_class.__name__} in '{filepath}': {err}",
                data,
            )
        return False, errors
    except Exception as exc:  # noqa: BLE001
        msg = f"Unexpected validation error in '{filepath}': {exc}"
        _log_error(msg, {"filepath": filepath})
        return False, [msg]


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------


def _cli_main(argv: list[str]) -> int:
    """
    Usage: python3 -m lib.validator <model_type> <json_string> [output_file]

    model_type: asset | finding | endpoint | credential | scanrun
    json_string: JSON-encoded dict to validate
    output_file: (optional) path to write validated JSON

    Exit codes: 0 = valid, 1 = invalid, 2 = usage error
    """
    if len(argv) < 2:
        print(
            "Usage: python3 -m lib.validator <model_type> <json_string> [output_file]",
            file=sys.stderr,
        )
        return 2

    model_type = argv[0].lower()
    json_string = argv[1]
    output_file = argv[2] if len(argv) >= 3 else None

    model_class = SCHEMA_REGISTRY.get(model_type)
    if model_class is None:
        known = ", ".join(sorted(SCHEMA_REGISTRY.keys()))
        print(
            json.dumps(
                {
                    "level": "ERROR",
                    "error": f"Unknown model_type '{model_type}'. Known types: {known}",
                    "data": None,
                }
            ),
            file=sys.stderr,
        )
        return 2

    # Parse JSON string
    try:
        data = json.loads(json_string)
    except json.JSONDecodeError as exc:
        print(
            json.dumps(
                {
                    "level": "ERROR",
                    "error": f"Invalid JSON input: {exc}",
                    "data": json_string[:200],
                }
            ),
            file=sys.stderr,
        )
        return 1

    if output_file:
        success = validate_and_write(data, model_class, output_file)
    else:
        # Validate only — no persistence
        try:
            model_class.model_validate(data)
            success = True
        except ValidationError as exc:
            errors = "; ".join(_format_pydantic_errors(exc))
            print(
                json.dumps(
                    {
                        "level": "ERROR",
                        "error": f"Validation failed for {model_class.__name__}: {errors}",
                        "data": data,
                    },
                    default=str,
                ),
                file=sys.stderr,
            )
            success = False

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(_cli_main(sys.argv[1:]))
