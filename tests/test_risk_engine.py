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


def test_official_bank_domain_is_safe_with_login_path():
    assessment = RiskEngine.calculate_risk(
        input_type="URL",
        target="https://hdfc.bank.in/login/verify",
        detector_signals={
            "is_official_domain": True,
            "has_sensitive_path": True,
            "matched_keywords": ["login", "verify"],
        },
        laya_signals={},
        qwen_signals={"qwen_verdict": "likely_legitimate"},
        external_intel_signals={},
        all_findings=[
            Finding(severity="low", title="Verified Official Domain (HDFC Bank)", description="Legitimate bank domain"),
        ],
        qwen_verdict="likely_legitimate",
    )
    assert assessment.classification == "Safe"
    assert assessment.score <= 15


def test_lookalike_domain_with_sensitive_path_triggers_high_risk():
    assessment = RiskEngine.calculate_risk(
        input_type="URL",
        target="https://hdfc-bank-kyc-update.com/login/verify?customer=827491",
        detector_signals={
            "is_lookalike_domain": True,
            "has_sensitive_path": True,
            "matched_keywords": ["login", "verify"],
        },
        laya_signals={"laya_phishing_probability": 0.9},
        qwen_signals={"qwen_verdict": "likely_phishing"},
        external_intel_signals={},
        all_findings=[
            Finding(severity="high", title="Unauthorized Brand Lookalike Domain (HDFC Bank)", description="Lookalike domain"),
            Finding(severity="high", title="Credential Harvest Path on Lookalike Domain", description="/login on lookalike"),
        ],
        qwen_verdict="likely_phishing",
        qwen_reasoning="Identity mismatch: domain is hdfc-bank-kyc-update.com instead of hdfc.bank.in.",
        qwen_what_would_change_my_mind="If domain resolved to hdfc.bank.in.",
    )
    assert assessment.classification == "High Risk"
    assert assessment.score >= 85
    assert "Calibration Criteria" in assessment.explanation

