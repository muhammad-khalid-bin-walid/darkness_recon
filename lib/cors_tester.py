"""
lib/cors_tester.py — CORS misconfiguration systematic matrix testing (plan Phase 68)
"""
from __future__ import annotations

import urllib.request
import urllib.error
from urllib.parse import urlparse


_TEST_ORIGINS = [
    "https://evil.example.com",
    "https://attacker.com",
    "null",
    "https://{target}evil.com",       # prefix bypass attempt
    "https://evil.{target}",          # suffix bypass
]


def _test_cors(url: str, origin: str, timeout: int = 10) -> dict:
    try:
        req = urllib.request.Request(url, headers={"Origin": origin, "User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            acao = headers.get("access-control-allow-origin", "")
            acac = headers.get("access-control-allow-credentials", "").lower()
            return {
                "origin_sent": origin,
                "acao": acao,
                "acac": acac,
                "status": resp.status,
                "vulnerable": _is_vulnerable(origin, acao, acac),
            }
    except Exception as e:
        return {"origin_sent": origin, "error": str(e), "vulnerable": False}


def _is_vulnerable(origin: str, acao: str, acac: str) -> bool:
    if acao == "*" and acac == "true":
        return True  # Wildcard + credentials (browsers block this, but still misconfigured)
    if acao == origin and acao not in ("", "null"):
        if acac == "true":
            return True  # Reflects arbitrary origin with credentials
    return False


def test_cors(url: str, timeout: int = 10) -> dict:
    """
    Run CORS matrix test against a URL.
    Returns {url, results, vulnerable, issues}.
    """
    host = urlparse(url).netloc
    origins = [o.replace("{target}", host) for o in _TEST_ORIGINS]
    results = [_test_cors(url, origin, timeout) for origin in origins]
    vulnerable = any(r.get("vulnerable") for r in results)
    issues = [r for r in results if r.get("vulnerable")]

    return {
        "url": url,
        "results": results,
        "vulnerable": vulnerable,
        "vulnerable_origins": [r["origin_sent"] for r in issues],
        "severity": "high" if vulnerable else "info",
    }
