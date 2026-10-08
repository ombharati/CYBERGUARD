"""Unit tests for the Response Recommendation Layer and response_rules.json."""
import pytest
from app.backend.services.recommendation import (
    load_response_rules,
    get_recommended_actions,
    normalize_threat_category,
    RULES_PATH,
)


def test_response_rules_json_exists_and_valid():
    """Verify response_rules.json exists and is valid JSON."""
    assert RULES_PATH.is_file(), f"Expected rules file at {RULES_PATH}"
    rules = load_response_rules()
    assert isinstance(rules, dict)
    assert len(rules) >= 10


def test_prompt_required_example_mappings():
    """Verify the 5 explicit example mappings specified in the requirements."""
    # 1. phishing_url + lookalike_domain
    actions_url = get_recommended_actions(
        classification="High Risk",
        top_signal_type="lookalike_domain",
        input_type="url",
    )
    assert "Block the URL at the gateway" in actions_url
    assert "Quarantine related emails" in actions_url
    assert "Warn the user" in actions_url
    assert "Report to brand protection" in actions_url

    # 2. phishing_email + credential_request
    actions_email = get_recommended_actions(
        classification="High Risk",
        top_signal_type="credential_request",
        input_type="email",
    )
    assert "Quarantine the email" in actions_email
    assert "Force password reset for the recipient" in actions_email
    assert "Revoke active sessions" in actions_email
    assert "Notify the SOC" in actions_email

    # 3. identity_spoof + spf_fail
    actions_identity = get_recommended_actions(
        classification="High Risk",
        top_signal_type="spf_fail",
        input_type="identity",
    )
    assert "Block the sender domain" in actions_identity
    assert "Warn the recipient" in actions_identity
    assert "Escalate to SOC if repeated" in actions_identity

    # 4. log_anomaly + brute_force
    actions_log_brute = get_recommended_actions(
        classification="High Risk",
        top_signal_type="brute_force",
        input_type="logs",
    )
    assert "Lock the targeted account" in actions_log_brute
    assert "Block the source IP" in actions_log_brute
    assert "Force MFA re-enrollment" in actions_log_brute
    assert "Notify the SOC" in actions_log_brute

    # 5. log_anomaly + impossible_travel
    actions_log_travel = get_recommended_actions(
        classification="High Risk",
        top_signal_type="impossible_travel",
        input_type="logs",
    )
    assert "Revoke active sessions" in actions_log_travel
    assert "Require MFA" in actions_log_travel
    assert "Notify the user and SOC" in actions_log_travel


def test_fallback_actions_on_unknown_signals():
    """Verify graceful fallback for unknown combinations."""
    actions = get_recommended_actions(
        classification="Safe",
        top_signal_type="unknown_signal_xyz",
        input_type="url",
    )
    assert len(actions) > 0
    assert any("legitimate" in a.lower() or "baseline" in a.lower() or "no immediate" in a.lower() for a in actions)


def test_merge_existing_finding_actions():
    """Verify that custom finding actions are merged cleanly without duplicates."""
    actions = get_recommended_actions(
        classification="High Risk",
        top_signal_type="lookalike_domain",
        input_type="url",
        existing_finding_actions=["Block the URL at the gateway", "Custom Analyst Triage Note"]
    )
    assert "Block the URL at the gateway" in actions
    assert "Custom Analyst Triage Note" in actions
    # Ensure no duplicates
    assert len(actions) == len(set(actions))
