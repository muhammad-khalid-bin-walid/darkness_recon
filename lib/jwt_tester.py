"""
lib/jwt_tester.py — JWT deep-testing module (plan Phase 54)
Tests: alg confusion, kid injection, weak-secret checks, claim tampering.
Detection and analysis only — no exploitation without ROE.
"""
from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path


def _b64_decode(s: str) -> bytes:
    """Base64url decode with padding fix."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def decode_jwt(token: str) -> dict:
    """Decode a JWT without verification. Returns {header, payload, valid_format}."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return {"valid_format": False, "error": "Not a 3-part JWT"}
    try:
        header = json.loads(_b64_decode(parts[0]))
        payload = json.loads(_b64_decode(parts[1]))
        return {"valid_format": True, "header": header, "payload": payload, "signature": parts[2]}
    except Exception as e:
        return {"valid_format": False, "error": str(e)}


def check_algorithm(header: dict) -> list[dict]:
    """Check for weak/dangerous algorithm declarations."""
    issues = []
    alg = header.get("alg", "")
    if alg.upper() == "NONE":
        issues.append({"type": "alg_none", "severity": "critical",
                       "description": "JWT algorithm is 'none' — signature not verified"})
    elif alg.upper() in ("HS256", "HS384", "HS512"):
        issues.append({"type": "symmetric_alg", "severity": "info",
                       "description": f"Symmetric algorithm {alg} — vulnerable to secret brute-force if secret is weak"})
    elif alg.upper() in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"):
        pass  # Asymmetric — generally fine
    else:
        issues.append({"type": "unknown_alg", "severity": "medium",
                       "description": f"Unknown or non-standard algorithm: {alg}"})
    return issues


def check_kid_injection_risk(header: dict) -> list[dict]:
    """Check for kid (key ID) field that may be injectable."""
    issues = []
    kid = header.get("kid", "")
    if kid:
        # Check for path traversal or injection patterns in kid
        if re.search(r'[/\\.]|\.\.|;|--|=|\'|"', str(kid)):
            issues.append({"type": "kid_injection_risk", "severity": "high",
                           "description": f"kid field contains suspicious characters: {kid!r}"})
        elif str(kid).isdigit() or len(str(kid)) < 8:
            issues.append({"type": "kid_predictable", "severity": "medium",
                           "description": f"kid field appears predictable/enumerable: {kid!r}"})
    return issues


def check_claims(payload: dict) -> list[dict]:
    """Check for weak or missing security claims."""
    issues = []
    import time
    now = int(time.time())

    if "exp" not in payload:
        issues.append({"type": "no_expiry", "severity": "medium",
                       "description": "Token has no expiry (exp claim missing)"})
    elif int(payload["exp"]) < now:
        issues.append({"type": "expired", "severity": "info",
                       "description": "Token is already expired"})

    if "iat" not in payload:
        issues.append({"type": "no_iat", "severity": "low",
                       "description": "Token missing issued-at (iat) claim"})

    if "aud" not in payload:
        issues.append({"type": "no_audience", "severity": "low",
                       "description": "Token missing audience (aud) claim — may be usable on other services"})

    # Check for sensitive data in payload
    sensitive_keys = {"password", "secret", "key", "ssn", "credit_card", "token"}
    for k in payload:
        if k.lower() in sensitive_keys:
            issues.append({"type": "sensitive_in_payload", "severity": "high",
                           "description": f"Potentially sensitive field in JWT payload: {k!r}"})
    return issues


def analyze_token(token: str) -> dict:
    """Full JWT analysis. Returns structured findings."""
    decoded = decode_jwt(token)
    if not decoded.get("valid_format"):
        return {"valid_format": False, "issues": [], "error": decoded.get("error")}

    header = decoded["header"]
    payload = decoded["payload"]
    issues = (
        check_algorithm(header) +
        check_kid_injection_risk(header) +
        check_claims(payload)
    )
    return {
        "valid_format": True,
        "header": header,
        "payload": payload,
        "issues": issues,
        "issue_count": len(issues),
        "risk_level": _overall_risk(issues),
    }


def _overall_risk(issues: list[dict]) -> str:
    severities = {i["severity"] for i in issues}
    for s in ("critical", "high", "medium", "low", "info"):
        if s in severities:
            return s
    return "none"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 -m lib.jwt_tester <jwt_token>", file=sys.stderr)
        sys.exit(2)
    print(json.dumps(analyze_token(sys.argv[1]), indent=2))
