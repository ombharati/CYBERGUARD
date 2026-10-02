"""Tests for large inputs, resource boundaries, and malformed edge cases."""
import pytest
from detection.url.detector import analyze_url, normalize_url
from detection.email.parser import parse_email, extract_urls_from_text


def test_huge_url_truncated_safely():
    huge_url = "https://example.com/search?q=" + ("A" * 10000)
    result = analyze_url(huge_url)
    assert result.is_valid is True
    # URL was analyzed and bounded
    assert result.signals["url_length"] == len(huge_url)
    assert any("Long URL" in f.title for f in result.findings)


def test_huge_email_body_truncated_safely():
    huge_body = "Warning: Urgent account issue. " * 5000  # ~150,000 characters
    parsed = parse_email({
        "sender": "alert@example.com",
        "subject": "Urgent",
        "body": huge_body,
    })
    assert parsed.is_valid is True
    assert len(parsed.plain_body) <= 20000  # Truncated to safe boundary limit


def test_deeply_nested_url_query_parameters():
    param_string = "&".join([f"key_{i}=val_{i}" for i in range(500)])
    url = f"https://example.com/api?{param_string}"
    result = analyze_url(url)
    assert result.is_valid is True
    assert result.signals["hostname"] == "example.com"


def test_lots_of_urls_in_email():
    body = "\n".join([f"Link {i}: http://phish-test-{i}.xyz/verify" for i in range(200)])
    parsed = parse_email({
        "sender": "test@domain.com",
        "subject": "Many links",
        "body": body,
    })
    assert len(parsed.extracted_urls) <= 25  # Capped to 25 URLs
