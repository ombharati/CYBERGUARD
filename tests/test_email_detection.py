"""Unit tests for Email Parsing and Deterministic Detection."""
import pytest
from detection.email.parser import parse_email, extract_urls_from_text
from detection.email.heuristics import analyze_email_heuristics


def test_parse_structured_email():
    payload = {
        "sender": "Security Desk <alert@company.com>",
        "subject": "Action Required: Verify Account",
        "body": "Please login to your account at https://secure-login.com to confirm credentials.",
    }
    parsed = parse_email(payload)
    assert parsed.is_valid is True
    assert parsed.sender == "alert@company.com"
    assert parsed.sender_name == "Security Desk"
    assert parsed.sender_domain == "company.com"
    assert "https://secure-login.com" in parsed.extracted_urls


def test_parse_raw_rfc822_email():
    raw_email = (
        "From: \"PayPal Support\" <service@gmail.com>\r\n"
        "To: victim@example.com\r\n"
        "Subject: Urgent Account Suspension\r\n"
        "Reply-To: attacker@evil-stealer.xyz\r\n"
        "Received-SPF: softfail (domain does not designate IP)\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
        "Your account has been suspended within 24 hours. Click here to confirm your password: http://192.168.1.100/verify"
    )
    parsed = parse_email(raw_email)
    assert parsed.is_valid is True
    assert parsed.sender == "service@gmail.com"
    assert parsed.sender_name == "PayPal Support"
    assert parsed.reply_to == "attacker@evil-stealer.xyz"
    assert parsed.reply_to_domain == "evil-stealer.xyz"
    assert len(parsed.extracted_urls) >= 1

    heuristics = analyze_email_heuristics(parsed)
    signals = heuristics["signals"]
    findings = heuristics["findings"]

    assert signals["free_webmail_impersonation"] is True
    assert signals["reply_to_mismatch"] is True
    assert signals["auth_failure"] is True
    assert signals["credential_matches"] >= 1
    assert any("Display Name Spoofing" in f.title for f in findings)
    assert any("Reply-To Domain Mismatch" in f.title for f in findings)
    assert any("Credential Harvesting" in f.title for f in findings)


def test_malformed_email_graceful():
    parsed = parse_email("")
    assert parsed.is_valid is False
    assert parsed.error_message is not None


def test_extract_urls_limits():
    long_text = " ".join([f"https://link-{i}.com/test" for i in range(50)])
    urls = extract_urls_from_text(long_text)
    assert len(urls) <= 25  # Limit enforced
