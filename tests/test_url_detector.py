"""Unit tests for Deterministic URL Detection and SSRF Protection."""
import pytest
from detection.url.detector import analyze_url, normalize_url, calculate_shannon_entropy
from detection.url.ssrf import validate_hostname_ssrf, is_ip_private_or_restricted


def test_clean_legitimate_url():
    res = analyze_url("https://example.com/about")
    assert res.is_valid is True
    assert res.is_ssrf_risk is False
    assert res.signals["has_credentials"] is False
    assert res.signals["is_ip_address"] is False
    assert len(res.findings) == 1
    assert "Clean Structural Inspection" in res.findings[0].title


def test_ssrf_detection():
    # Localhost
    res = analyze_url("http://localhost:8080/admin")
    assert res.is_ssrf_risk is True
    assert any("SSRF" in f.title for f in res.findings)

    # 127.0.0.1
    res2 = analyze_url("http://127.0.0.1/status")
    assert res2.is_ssrf_risk is True

    # 169.254.169.254 (Cloud metadata)
    res3 = analyze_url("http://169.254.169.254/latest/meta-data/")
    assert res3.is_ssrf_risk is True

    # Private 10.0.0.0/8
    res4 = analyze_url("http://10.1.2.3:8000/api")
    assert res4.is_ssrf_risk is True


def test_embedded_credentials():
    res = analyze_url("https://admin:secret123@phish-target.com/login")
    assert res.signals["has_credentials"] is True
    assert any("Credentials" in f.title for f in res.findings)


def test_punycode_detection():
    res = analyze_url("https://xn--e1afmkfd.xn--p1ai")
    assert res.signals["has_punycode"] is True
    assert any("Punycode" in f.title for f in res.findings)


def test_deep_subdomain_and_keywords():
    res = analyze_url("https://login.verify.security.account.banking.paypal.com.evil-server.xyz/auth")
    assert res.signals["subdomain_count"] >= 3
    assert res.signals["suspicious_tld"] is True
    assert len(res.signals["matched_keywords"]) >= 2
    assert any("Subdomain" in f.title for f in res.findings)
    assert any("Keywords" in f.title for f in res.findings)


def test_dangerous_extension():
    res = analyze_url("https://files-cloud.com/downloads/invoice_2026.pdf.exe")
    assert res.signals["dangerous_file_extension"] is True
    assert any("Executable Download" in f.title for f in res.findings)


def test_malformed_url_handling():
    res = analyze_url("")
    assert res.is_valid is False
    assert res.error_message is not None

    res2 = analyze_url("   ")
    assert res2.is_valid is False


def test_shannon_entropy():
    # Repetitive string has low entropy
    low = calculate_shannon_entropy("aaaaaaa")
    # Random characters have higher entropy
    high = calculate_shannon_entropy("x8q9z2w1p4m7")
    assert high > low
