"""
lib/evidence_redaction.py — Evidence redaction pipeline (plan Phase 124)
Strips incidental PII/secrets from captured evidence before storage/submission.
"""
from __future__ import annotations

import re

_PII_PATTERNS = [
    (re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b', re.I), "[EMAIL_REDACTED]"),
    (re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'), "[PHONE_REDACTED]"),
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), "[SSN_REDACTED]"),
    (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'), "[CARD_REDACTED]"),
    (re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+'), "[PASSWORD_REDACTED]"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "[AWS_KEY_REDACTED]"),
    (re.compile(r'gh[pousr]_[A-Za-z0-9]{36,}'), "[GH_TOKEN_REDACTED]"),
    (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), "[JWT_REDACTED]"),
    (re.compile(r'(?i)(api[_-]?key|secret|token)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}["\']?'), "[API_KEY_REDACTED]"),
]


def redact_string(text: str) -> str:
    """Apply all PII/secret patterns to a string and return redacted version."""
    for pattern, replacement in _PII_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_dict(data: dict) -> dict:
    """Recursively redact a dictionary's string values."""
    result = {}
    for k, v in data.items():
        if isinstance(v, str):
            result[k] = redact_string(v)
        elif isinstance(v, dict):
            result[k] = redact_dict(v)
        elif isinstance(v, list):
            result[k] = [redact_string(i) if isinstance(i, str) else (redact_dict(i) if isinstance(i, dict) else i) for i in v]
        else:
            result[k] = v
    return result


def redact_finding(finding: dict) -> dict:
    """Redact PII from a finding's evidence, description, and title fields."""
    redacted = dict(finding)
    for field in ("description", "title"):
        if isinstance(redacted.get(field), str):
            redacted[field] = redact_string(redacted[field])
    if isinstance(redacted.get("evidence"), dict):
        redacted["evidence"] = redact_dict(redacted["evidence"])
    return redacted


def redact_all_findings(findings: list[dict]) -> list[dict]:
    return [redact_finding(f) for f in findings]
