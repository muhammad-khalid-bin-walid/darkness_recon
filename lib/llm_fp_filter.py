"""lib/llm_fp_filter.py — LLM-assisted false-positive filtering (plan Phase 164)"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# False-positive indicators
# ---------------------------------------------------------------------------

FP_INDICATORS: dict[str, str] = {
    "unusual_port": (
        "The finding targets a port outside the standard web range (80/443/8080/8443), "
        "which may indicate a service not intended for production."
    ),
    "no_response_body": (
        "The server returned a response with an empty body, suggesting the "
        "endpoint may not host meaningful content."
    ),
    "default_header": (
        "The response contains default or boilerplate headers commonly seen "
        "in out-of-the-box deployments rather than real misconfigurations."
    ),
    "known_fingerprint": (
        "The response signature matches a known default or test page that "
        "often triggers false positives in automated scanners."
    ),
    "timing_anomaly": (
        "Response timing deviates significantly from baseline, which may "
        "indicate network issues rather than a genuine vulnerability."
    ),
}


@dataclass
class FPClassification:
    """Result of a false-positive classification for a single finding."""

    fp_probability: float  # 0.0 = likely true positive, 1.0 = likely false positive
    reasoning: str
    indicators: list[str] = field(default_factory=list)
    is_false_positive: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "fp_probability": round(self.fp_probability, 4),
            "reasoning": self.reasoning,
            "indicators": self.indicators,
            "is_false_positive": self.is_false_positive,
        }


# ---------------------------------------------------------------------------
# LLM call (lightweight, self-contained)
# ---------------------------------------------------------------------------

_RATE_WINDOW = 60.0
_MAX_REQUESTS = 10
_timestamps: list[float] = []


def _rate_limit() -> None:
    now = time.monotonic()
    _timestamps[:] = [t for t in _timestamps if now - t < _RATE_WINDOW]
    if len(_timestamps) >= _MAX_REQUESTS:
        time.sleep(_RATE_WINDOW - (now - _timestamps[0]) + 0.1)
    _timestamps.append(time.monotonic())


def _call_llm(prompt: str, api_key: str, model: str = "gpt-4o-mini") -> str:
    if not api_key:
        return ""

    _rate_limit()

    payload = json.dumps({
        "model": model,
        "temperature": 0.1,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()

    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )

    retries = 3
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
            return data["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt < retries - 1:
                time.sleep(2 ** attempt)
                continue
            raise


# ---------------------------------------------------------------------------
# Rule-based heuristic analysis
# ---------------------------------------------------------------------------

def _rule_based_classify(finding: dict[str, Any]) -> FPClassification:
    """Score a finding for false-positive likelihood using deterministic rules."""
    indicators: list[str] = []
    score = 0.0

    port = finding.get("port")
    if port and int(port) not in (80, 443, 8080, 8443):
        indicators.append("unusual_port")
        score += 0.15

    body = finding.get("response_body", "")
    if not body or len(body.strip()) == 0:
        indicators.append("no_response_body")
        score += 0.25

    server_header = str(finding.get("server_header", "")).lower()
    default_servers = ("apache/2.4", "nginx/1.18", "microsoft-iis/10.0")
    if any(server_header.startswith(s) for s in default_servers):
        indicators.append("default_header")
        score += 0.10

    title = str(finding.get("title", "")).lower()
    fp_titles = ("default page", "test page", "example page", "welcome")
    if any(fp in title for fp in fp_titles):
        indicators.append("known_fingerprint")
        score += 0.30

    confidence = float(finding.get("confidence", 0.5))
    if confidence < 0.3:
        score += 0.20

    severity = str(finding.get("severity", "info")).lower()
    if severity == "info":
        score += 0.10

    score = min(score, 1.0)
    reasoning_parts = (
        [FP_INDICATORS[ind] for ind in indicators]
        if indicators
        else ["No strong FP indicators detected."]
    )

    return FPClassification(
        fp_probability=score,
        reasoning=" ".join(reasoning_parts),
        indicators=indicators,
        is_false_positive=score >= 0.6,
    )


# ---------------------------------------------------------------------------
# LLM-based classification
# ---------------------------------------------------------------------------

_FP_PROMPT = (
    "You are a security analyst reviewing vulnerability scan results. "
    "Analyze the following finding and estimate the probability that it is "
    "a false positive. Respond with JSON: {{\"fp_probability\": <0-1>, "
    "\"reasoning\": \"...\", \"indicators\": [\"...\"]}}\n\nFinding:\n{finding_json}"
)


def _llm_classify(finding: dict[str, Any], api_key: str) -> FPClassification:
    """Use an LLM to classify a finding as potential false positive."""
    prompt = _FP_PROMPT.format(finding_json=json.dumps(finding, indent=2, default=str))
    try:
        raw = _call_llm(prompt, api_key)
        data = json.loads(raw)
        fp_prob = float(data.get("fp_probability", 0.5))
        reasoning = data.get("reasoning", "LLM analysis")
        indicators = data.get("indicators", [])
        return FPClassification(
            fp_probability=fp_prob,
            reasoning=reasoning,
            indicators=indicators,
            is_false_positive=fp_prob >= 0.6,
        )
    except Exception:
        return _rule_based_classify(finding)


# ---------------------------------------------------------------------------
# Batch processing helpers
# ---------------------------------------------------------------------------

def classify_finding(finding: dict[str, Any], api_key: str | None = None) -> dict[str, Any]:
    """Classify a single finding. Returns a dict with fp_probability, reasoning, indicators."""
    if api_key:
        return _llm_classify(finding, api_key).to_dict()
    return _rule_based_classify(finding).to_dict()


def filter_findings(
    findings_batch: list[dict[str, Any]],
    api_key: str | None = None,
    threshold: float = 0.6,
) -> list[dict[str, Any]]:
    """Filter out likely false positives from a batch of findings.

    Findings whose ``fp_probability >= threshold`` are removed.
    Batched in groups of 10 for efficiency when an LLM is used.
    """
    filtered: list[dict[str, Any]] = []
    batch_size = 10

    for i in range(0, len(findings_batch), batch_size):
        chunk = findings_batch[i : i + batch_size]

        for finding in chunk:
            result = classify_finding(finding, api_key=api_key)
            fp_prob = result.get("fp_probability", 0.0)

            if fp_prob < threshold:
                finding["_fp_analysis"] = result
                filtered.append(finding)

    return filtered


def explain_classification(finding: dict[str, Any]) -> str:
    """Return a human-readable explanation of why a finding was classified as it was."""
    result = classify_finding(finding)
    fp_prob = result.get("fp_probability", 0.0)
    indicators = result.get("indicators", [])
    reasoning = result.get("reasoning", "")

    title = finding.get("title", "Unknown")
    severity = finding.get("severity", "N/A")

    lines = [
        f"Classification for: {title}",
        f"Severity: {severity}",
        f"False-positive probability: {fp_prob:.1%}",
        "",
    ]

    if indicators:
        lines.append("Detected indicators:")
        for ind in indicators:
            desc = FP_INDICATORS.get(ind, ind)
            lines.append(f"  - {ind}: {desc}")
    else:
        lines.append("No significant false-positive indicators detected.")

    if reasoning:
        lines.extend(["", "Reasoning:", reasoning])

    verdict = "likely false positive" if fp_prob >= 0.6 else "likely true positive"
    lines.extend(["", f"Verdict: {verdict}"])

    return "\n".join(lines)
