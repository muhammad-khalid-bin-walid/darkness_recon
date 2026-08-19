"""lib/ml_triage.py — ML-assisted triage classifier (plan Phase 157)"""

from __future__ import annotations

import json
import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import numpy as np
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.model_selection import cross_val_score
    from sklearn.pipeline import Pipeline

    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


SEVERITY_MAP: dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
    "info": 0.05,
}

TOOL_RELIABILITY: dict[str, float] = {
    "nuclei": 0.92,
    "nmap": 0.88,
    "burpsuite": 0.95,
    "nikto": 0.85,
    "sqlmap": 0.90,
    "wpscan": 0.87,
    "subfinder": 0.83,
    "httpx": 0.86,
    "gobuster": 0.84,
    "ffuf": 0.89,
}


@dataclass
class TriageResult:
    """Outcome of a triage classification decision."""

    verdict: str  # "accept" | "reject" | "needs_review"
    confidence: float  # 0.0 – 1.0
    reasoning: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "confidence": round(self.confidence, 4),
            "reasoning": self.reasoning,
        }


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def _extract_features(finding: dict[str, Any]) -> list[float]:
    """Return a numeric feature vector for a single finding dict."""
    severity_num = SEVERITY_MAP.get(
        str(finding.get("severity", "info")).lower(), 0.05
    )
    phase = float(finding.get("phase", 1))
    has_screenshot = 1.0 if finding.get("screenshot") else 0.0
    confidence = float(finding.get("confidence", 0.5))
    vuln_class = len(str(finding.get("vuln_class", "")))  # proxy encoding

    return [severity_num, phase, has_screenshot, confidence, vuln_class]


def _extract_text_feature(finding: dict[str, Any]) -> str:
    """Concatenate text fields used for TF-IDF when sklearn is available."""
    parts = [
        str(finding.get("title", "")),
        str(finding.get("vuln_class", "")),
        str(finding.get("tool", "")),
        str(finding.get("description", "")),
    ]
    return " ".join(parts)


def _label(finding: dict[str, Any]) -> int:
    """Return a numeric label for a labelled finding (1 = accept, 0 = reject)."""
    severity = str(finding.get("severity", "info")).lower()
    confidence = float(finding.get("confidence", 0.5))
    score = SEVERITY_MAP.get(severity, 0.05) * confidence
    return 1 if score >= 0.3 else 0


# ---------------------------------------------------------------------------
# Model training
# ---------------------------------------------------------------------------

def train_model(findings_data: list[dict[str, Any]]) -> Any:
    """Train and return a triage model.

    When scikit-learn is installed a GradientBoosting pipeline is used.
    Otherwise a ``None`` sentinel is returned so callers fall back to rules.
    """
    if not HAS_SKLEARN:
        return None

    X_numeric = np.array([_extract_features(f) for f in findings_data])
    y = np.array([_label(f) for f in findings_data])

    if len(np.unique(y)) < 2:
        return None  # need both classes to train

    X_text = [_extract_text_feature(f) for f in findings_data]
    tfidf = TfidfVectorizer(max_features=256, stop_words="english")
    X_tfidf = tfidf.fit_transform(X_text).toarray()

    X = np.hstack([X_numeric, X_tfidf])

    model = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=256, stop_words="english")),
        ("clf", GradientBoostingClassifier(n_estimators=100, random_state=42)),
    ])

    model.fit(X_text, y)
    return model


# ---------------------------------------------------------------------------
# Prediction
# ---------------------------------------------------------------------------

def predict(finding: dict[str, Any], model: Any = None) -> TriageResult:
    """Classify a finding into accept / reject / needs_review."""
    if model is not None and HAS_SKLEARN:
        try:
            text = _extract_text_feature(finding)
            proba = model.predict_proba([text])[0]
            accept_prob = proba[1]
            reject_prob = proba[0]

            if accept_prob > 0.7:
                verdict = "accept"
            elif reject_prob > 0.7:
                verdict = "reject"
            else:
                verdict = "needs_review"

            confidence = max(accept_prob, reject_prob)
            reasoning = (
                f"ML model confidence {confidence:.2f}; "
                f"P(accept)={accept_prob:.2f}, P(reject)={reject_prob:.2f}"
            )
            return TriageResult(verdict=verdict, confidence=confidence, reasoning=reasoning)
        except Exception:
            pass  # fall through to rule-based

    # --- rule-based fallback ---
    return _rule_based_triage(finding)


def _rule_based_triage(finding: dict[str, Any]) -> TriageResult:
    """Deterministic scoring fallback when no trained model is available."""
    severity = str(finding.get("severity", "info")).lower()
    severity_weight = SEVERITY_MAP.get(severity, 0.05)
    confidence = float(finding.get("confidence", 0.5))
    tool = str(finding.get("tool", "")).lower()
    tool_reliability = TOOL_RELIABILITY.get(tool, 0.75)

    score = severity_weight * confidence * tool_reliability

    if score > 0.7:
        verdict = "accept"
        reasoning = (
            f"High automated score ({score:.2f}) — severity={severity}, "
            f"confidence={confidence:.2f}, tool_reliability={tool_reliability:.2f}"
        )
    elif score < 0.3:
        verdict = "reject"
        reasoning = (
            f"Low automated score ({score:.2f}) — likely false positive or "
            f"informational finding"
        )
    else:
        verdict = "needs_review"
        reasoning = (
            f"Ambiguous score ({score:.2f}) — manual review recommended"
        )

    return TriageResult(verdict=verdict, confidence=score, reasoning=reasoning)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def evaluate_model(test_data: list[dict[str, Any]], model: Any = None) -> dict[str, Any]:
    """Evaluate triage accuracy on a labelled test set.

    Returns a dict with accuracy, precision, recall, f1, and per-class counts.
    """
    tp = fp = tn = fn = 0

    for finding in test_data:
        expected = _label(finding)
        result = predict(finding, model=model)
        predicted = 1 if result.verdict == "accept" else 0

        if predicted == 1 and expected == 1:
            tp += 1
        elif predicted == 1 and expected == 0:
            fp += 1
        elif predicted == 0 and expected == 0:
            tn += 1
        else:
            fn += 1

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "total": total,
        "sklearn_available": HAS_SKLEARN,
    }


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_model(model: Any, path: str | Path) -> None:
    """Persist a trained model to *path* via pickle."""
    if model is None:
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("wb") as fh:
        pickle.dump(model, fh)


def load_model(path: str | Path) -> Any:
    """Load a previously saved model. Returns ``None`` on any error."""
    try:
        with open(path, "rb") as fh:
            return pickle.load(fh)  # noqa: S301 — trusted local artefact
    except Exception:
        return None
