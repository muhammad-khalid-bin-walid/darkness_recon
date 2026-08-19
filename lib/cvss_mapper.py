"""
lib/cvss_mapper.py — Automatic CVSS v3.1 scoring and vector generation.
Maps vulnerability findings to CVSS scores and severity labels.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# CVSS v3.1 severity thresholds
_CVSS_THRESHOLDS = [
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (0.1, "Low"),
    (0.0, "None"),
]

# Common vulnerability class to CVSS vector component mappings
_VULN_CLASS_VECTORS: dict[str, dict[str, str]] = {
    "xss": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S": "C", "C": "L", "I": "L", "A": "N",
    },
    "reflected_xss": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S": "U", "C": "L", "I": "L", "A": "N",
    },
    "stored_xss": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S": "C", "C": "L", "I": "L", "A": "N",
    },
    "sqli": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "N",
    },
    "blind_sqli": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "L", "I": "N", "A": "N",
    },
    "ssrf": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S": "U", "C": "H", "I": "L", "A": "N",
    },
    "idor": {
        "AV": "N", "AC": "L", "PR": "L", "UI": "N",
        "S": "U", "C": "H", "I": "L", "A": "N",
    },
    "lfi": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S": "U", "C": "H", "I": "N", "A": "N",
    },
    "rfi": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S": "U", "C": "H", "I": "H", "A": "N",
    },
    "open_redirect": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S": "U", "C": "L", "I": "L", "A": "N",
    },
    "csrf": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S": "U", "C": "N", "I": "L", "A": "N",
    },
    "command_injection": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "H",
    },
    "deserialization": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "H",
    },
    "auth_bypass": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "N",
    },
    "info_disclosure": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S": "U", "C": "L", "I": "N", "A": "N",
    },
    "misconfiguration": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "L", "I": "N", "A": "N",
    },
    "weak_crypto": {
        "AV": "N", "AC": "H", "PR": "N", "UI": "N",
        "S": "U", "C": "L", "I": "N", "A": "N",
    },
    "path_traversal": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "R",
        "S": "U", "C": "H", "I": "N", "A": "N",
    },
    "xxe": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "N",
    },
    "race_condition": {
        "AV": "N", "AC": "H", "PR": "L", "UI": "R",
        "S": "U", "C": "H", "I": "L", "A": "N",
    },
    "memory_corruption": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "H",
    },
    "privilege_escalation": {
        "AV": "L", "AC": "L", "PR": "L", "UI": "N",
        "S": "U", "C": "H", "I": "H", "A": "N",
    },
    "dos": {
        "AV": "N", "AC": "L", "PR": "N", "UI": "N",
        "S": "U", "C": "N", "I": "N", "A": "H",
    },
}

# CVSS v3.1 metric value weights
_CVSS_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "N": {"U": 0.85, "C": 0.85},
        "L": {"U": 0.62, "C": 0.68},
        "H": {"U": 0.27, "C": 0.50},
    },
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": "U", "C": "C"},
    "C": {"N": 0.00, "L": 0.22, "H": 0.56},
    "I": {"N": 0.00, "L": 0.22, "H": 0.56},
    "A": {"N": 0.00, "L": 0.22, "H": 0.56},
}


@dataclass
class CVSSResult:
    """Result of CVSS scoring."""
    score: float
    severity: str
    vector_string: str
    explanation: str


def severity_from_score(score: float) -> str:
    """Return the severity label for a CVSS score."""
    for threshold, label in _CVSS_THRESHOLDS:
        if score >= threshold:
            return label
    return "None"


def generate_vector_string(finding: dict) -> str:
    """Generate a CVSS v3.1 vector string from a finding dict."""
    vuln_class = _detect_vuln_class(finding)
    base = _VULN_CLASS_VECTORS.get(vuln_class, _VULN_CLASS_VECTORS["misconfiguration"])

    # Refine based on finding attributes
    asset = (finding.get("asset_type") or "").lower()
    if asset in ("internal", "intranet", "private"):
        base["AV"] = "L"
    if asset in ("mobile", "iot"):
        base["AV"] = "P"

    scope = base.get("S", "U")
    pr_val = base.get("PR", "N")
    pr_score = _CVSS_METRICS["PR"][pr_val]
    if isinstance(pr_score, dict):
        pr_score = pr_score.get(scope, 0.85)

    exploitability = (
        _CVSS_METRICS["AV"][base["AV"]]
        * _CVSS_METRICS["AC"][base["AC"]]
        * pr_score
        * _CVSS_METRICS["UI"][base["UI"]]
    )

    impact_sub = (
        _CVSS_METRICS["C"][base["C"]]
        + _CVSS_METRICS["I"][base["I"]]
        + _CVSS_METRICS["A"][base["A"]]
    )

    if scope == "U":
        impact = 6.42 * impact_sub
    else:
        impact = 7.52 * (impact_sub - 0.029) - 3.25 * ((impact_sub - 0.02) ** 15)

    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = min(exploitability + impact, 10.0)
    else:
        score = min(1.08 * (exploitability + impact), 10.0)

    score = round_up(min(score, 10.0))

    vector = (
        f"CVSS:3.1/AV:{base['AV']}/AC:{base['AC']}/PR:{base['PR']}"
        f"/UI:{base['UI']}/S:{base['S']}/C:{base['C']}/I:{base['I']}/A:{base['A']}"
    )
    return vector


def round_up(score: float) -> float:
    """Round up to one decimal place per CVSS 3.1 spec."""
    import math
    return math.ceil(score * 10) / 10


def calculate_base_score(vector: str) -> CVSSResult:
    """Calculate CVSS v3.1 base score from a vector string."""
    metrics = _parse_vector(vector)

    scope = metrics.get("S", "U")
    pr_val = metrics.get("PR", "N")
    pr_score = _CVSS_METRICS["PR"][pr_val]
    if isinstance(pr_score, dict):
        pr_score = pr_score.get(scope, 0.85)

    exploitability = (
        _CVSS_METRICS["AV"][metrics["AV"]]
        * _CVSS_METRICS["AC"][metrics["AC"]]
        * pr_score
        * _CVSS_METRICS["UI"][metrics["UI"]]
    )

    impact_sub = (
        _CVSS_METRICS["C"][metrics["C"]]
        + _CVSS_METRICS["I"][metrics["I"]]
        + _CVSS_METRICS["A"][metrics["A"]]
    )

    if scope == "U":
        impact = 6.42 * impact_sub
    else:
        impact = 7.52 * (impact_sub - 0.029) - 3.25 * ((impact_sub - 0.02) ** 15)

    if impact <= 0:
        score = 0.0
    elif scope == "U":
        score = min(exploitability + impact, 10.0)
    else:
        score = min(1.08 * (exploitability + impact), 10.0)

    score = round_up(min(score, 10.0))
    severity = severity_from_score(score)

    explanation = (
        f"Exploitability: {exploitability:.2f} | "
        f"Impact: {impact:.2f} | "
        f"Scope: {scope}"
    )
    return CVSSResult(
        score=score,
        severity=severity,
        vector_string=vector,
        explanation=explanation,
    )


def _parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS v3.1 vector string into a metrics dict."""
    metrics: dict[str, str] = {}
    for part in vector.split("/"):
        if ":" in part:
            key, val = part.split(":", 1)
            metrics[key] = val
    return metrics


def _detect_vuln_class(finding: dict) -> str:
    """Auto-detect vulnerability class from finding fields."""
    text = " ".join([
        finding.get("title", ""),
        finding.get("description", ""),
        finding.get("vuln_class", ""),
        finding.get("vuln_type", ""),
    ]).lower()

    class_keywords = {
        "stored_xss": ["stored xss", "stored cross-site", "persistent xss"],
        "reflected_xss": ["reflected xss", "reflected cross-site"],
        "xss": ["xss", "cross-site scripting"],
        "blind_sqli": ["blind sql", "blind injection"],
        "sqli": ["sql injection", "sqli", "sql inj"],
        "ssrf": ["ssrf", "server-side request forgery", "server side request forgery"],
        "idor": ["idor", "insecure direct object", "direct object reference"],
        "lfi": ["lfi", "local file inclusion", "file inclusion"],
        "rfi": ["rfi", "remote file inclusion"],
        "open_redirect": ["open redirect", "open redirector", "url redirect"],
        "csrf": ["csrf", "cross-site request forgery"],
        "command_injection": ["command injection", "os command", "rce", "remote code execution"],
        "deserialization": ["deserialization", "unsafe deserialization", "insecure deserialization"],
        "auth_bypass": ["auth bypass", "authentication bypass", "access control bypass"],
        "info_disclosure": ["info disclosure", "information disclosure", "data exposure"],
        "misconfiguration": ["misconfiguration", "config issue", "default config"],
        "weak_crypto": ["weak crypto", "weak cipher", "deprecated ssl", "deprecated tls"],
        "path_traversal": ["path traversal", "directory traversal", "dot-dot-slash"],
        "xxe": ["xxe", "xml external entity", "xml injection"],
        "race_condition": ["race condition", "time-of-check", "toctou"],
        "memory_corruption": ["buffer overflow", "heap overflow", "stack overflow", "use-after-free", "memory corruption"],
        "privilege_escalation": ["privilege escalation", "privesc", "elevation of privilege"],
        "dos": ["denial of service", "dos", "ddos"],
    }

    for vuln_class, keywords in class_keywords.items():
        for kw in keywords:
            if kw in text:
                return vuln_class

    return "misconfiguration"


def map_vuln_class_to_cvss(vuln_class: str) -> CVSSResult:
    """Return a CVSS result for a given vulnerability class."""
    class_lower = vuln_class.lower().replace(" ", "_").replace("-", "_")
    vector = _build_vector_from_class(class_lower)
    return calculate_base_score(vector)


def map_cvss(finding: dict) -> CVSSResult:
    """Map a finding to its CVSS v3.1 score automatically."""
    # Check for explicit vector
    if finding.get("cvss_vector"):
        return calculate_base_score(finding["cvss_vector"])

    # Check for explicit score
    if finding.get("cvss_score") is not None:
        score = float(finding["cvss_score"])
        return CVSSResult(
            score=score,
            severity=severity_from_score(score),
            vector_string=finding.get("cvss_vector", "N/A"),
            explanation="Score provided directly in finding.",
        )

    # Auto-generate from vulnerability class
    vuln_class = _detect_vuln_class(finding)
    vector = _build_vector_from_class(vuln_class)

    # Refine with context from the finding
    vector = _refine_vector(vector, finding)

    result = calculate_base_score(vector)

    # Add explanation
    result.explanation = (
        f"Auto-detected vulnerability class: {vuln_class}. "
        f"{result.explanation}"
    )
    return result


def _build_vector_from_class(vuln_class: str) -> str:
    """Build a CVSS vector string from a vulnerability class."""
    mapping = _VULN_CLASS_VECTORS.get(vuln_class, _VULN_CLASS_VECTORS["misconfiguration"])
    return (
        f"CVSS:3.1/AV:{mapping['AV']}/AC:{mapping['AC']}/PR:{mapping['PR']}"
        f"/UI:{mapping['UI']}/S:{mapping['S']}/C:{mapping['C']}/I:{mapping['I']}/A:{mapping['A']}"
    )


def _refine_vector(vector: str, finding: dict) -> str:
    """Refine a CVSS vector based on specific finding context."""
    metrics = _parse_vector(vector)

    # Auth required: if the vulnerability requires prior auth, raise PR
    if finding.get("requires_auth") or finding.get("authenticated"):
        metrics["PR"] = "L"

    # Public-facing: if asset is internet-facing, use Network AV
    asset_type = (finding.get("asset_type") or "").lower()
    if asset_type in ("internal", "intranet", "private"):
        metrics["AV"] = "A"

    # Confidentiality impact hints
    desc = (finding.get("description") or "").lower()
    if any(kw in desc for kw in ["credential", "password", "token", "secret", "key"]):
        metrics["C"] = "H"
    if any(kw in desc for kw in ["modify", "delete", "alter", "tamper"]):
        metrics["I"] = "H"
    if any(kw in desc for kw in ["denial", "downtime", "crash", "unavailable"]):
        metrics["A"] = "H"

    scope = metrics.get("S", "U")
    return (
        f"CVSS:3.1/AV:{metrics['AV']}/AC:{metrics['AC']}/PR:{metrics['PR']}"
        f"/UI:{metrics['UI']}/S:{scope}/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}"
    )
