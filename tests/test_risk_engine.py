"""Unit tests for the Deterministic Risk Engine."""
import pytest
from app.backend.services.risk_engine import RiskEngine
from detection.url.detector import Finding


def test_clean_input_assessment():
    assessment = RiskEngine.calculate_risk(
        input_type="url",
        target="https://example.com/about",
        detector_signals={"has_credentials": False, "is_ip_address": False},
        laya_signals={},
        qwen_signals={},
        external_intel_signals={},
        all_findings=[Finding(severity="low", title="Clean Inspection", description="No flags")],
    )
    assert assessment.classification == "Safe"
    assert assessment.score < 45
    assert len(assessment.signals) == 4
    assert "No major malicious indicators" in assessment.summary


def test_suspicious_input_assessment():
    assessment = RiskEngine.calculate_risk(
        input_type="url",
        target="https://login.verify.update.account-secure.com",
        detector_signals={
            "subdomain_count": 3,
            "matched_keywords": ["login", "verify"],
            "entropy": 3.8,
        },
        laya_signals={"laya_phishing_probability": 0.50},
        qwen_signals={},
        external_intel_signals={},
        all_findings=[
            Finding(severity="medium", title="Deep Subdomains", description="3 levels"),
            Finding(severity="medium", title="Keywords", description="login, verify"),
        ],
    )
    assert assessment.classification in ("Suspicious", "High Risk")
    assert assessment.score >= 45


def test_compound_high_risk_assessment():
    assessment = RiskEngine.calculate_risk(
        input_type="email",
        target="PayPal Account Alert",
        detector_signals={
            "free_webmail_impersonation": True,
            "reply_to_mismatch": True,
            "credential_matches": 1,
            "urgency_matches": 2,
        },
        laya_signals={},
        qwen_signals={
            "qwen_credential_intent": True,
            "qwen_social_engineering": True,
            "qwen_urgency": "high",
            "qwen_suspicion_score": 0.95,
        },
        external_intel_signals={},
        all_findings=[
            Finding(severity="high", title="Display Name Spoofing", description="PayPal via gmail"),
            Finding(severity="high", title="Credential Harvesting", description="Directs user to input pass"),
        ],
    )
    assert assessment.classification == "High Risk"
    assert assessment.score >= 75
    assert "Critical security threats detected" in assessment.summary


def test_ssrf_critical_floor():
    assessment = RiskEngine.calculate_risk(
        input_type="url",
        target="http://169.254.169.254/latest/meta-data/",
        detector_signals={"is_ssrf_risk": True, "is_ip_address": True},
        laya_signals={},
        qwen_signals={},
        external_intel_signals={},
        all_findings=[Finding(severity="high", title="SSRF Target", description="Metadata IP")],
    )
    assert assessment.classification == "High Risk"
    assert assessment.score >= 75
