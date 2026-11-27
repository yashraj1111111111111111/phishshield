"""Shared scan execution pipeline used by both the FastAPI API and Streamlit UI."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.database.repository import save_scan
from app.detectors.scanner import scan
from app.ml.predictor import predict_url_probability
from app.services.abuse_protection import enforce_rate_limit
from app.services.campaign_detector import detect_campaign
from app.services.explainer import plain_language_explanation


@dataclass
class ScanOutcome:
    scan_reference: str
    risk_score: int
    risk_level: str
    content_type: str
    reasons: list[str]
    explanation: str
    ml_probability: float | None
    campaign_detected: bool
    technical_details: dict[str, Any] = field(default_factory=dict)


def run_scan_pipeline(content: str, language: str, client_ip: str) -> ScanOutcome:
    """Enforce rate limits, score content without fetching URLs, persist, and explain."""
    enforce_rate_limit(client_ip)
    result = scan(content)
    ml_probability = predict_url_probability(content, result.content_type)
    campaign_reasons = detect_campaign(content, result.content_type, result.score, client_ip)
    reasons = [*result.reasons, *campaign_reasons]
    campaign_detected = bool(campaign_reasons)
    technical_details = dict(result.technical_details)
    if campaign_reasons:
        technical_details["triggered_rules"] = [
            *technical_details.get("triggered_rules", []),
            *(
                {"rule_id": "campaign_pattern", "category": "campaign", "score": 0, "reason": reason}
                for reason in campaign_reasons
            ),
        ]
    reference = save_scan(
        content,
        result.content_type,
        result.score,
        result.level,
        reasons,
        language,
        ml_probability=ml_probability,
    )
    explanation = plain_language_explanation(result.level, reasons, language)
    return ScanOutcome(
        scan_reference=reference,
        risk_score=result.score,
        risk_level=result.level,
        content_type=result.content_type,
        reasons=reasons,
        explanation=explanation,
        ml_probability=ml_probability,
        campaign_detected=campaign_detected,
        technical_details=technical_details,
    )
