"""Unit and integration tests for Scenario 2: Email Header & Identity Impersonation Detection."""
import pytest
from detection.identity.detector import (
    analyze_identity_headers,
    extract_email_address_and_domain,
    parse_auth_results,
    IdentityAnalysisResult,
)


LEGIT_HEADERS = """Received: from mail.google.com (mail.google.com [209.85.220.41])
    by mx.destination.com with ESMTPS id abc123
    for <victim@example.com>; Wed, 08 Oct 2026 10:00:00 +0000
Authentication-Results: mx.destination.com;
    spf=pass (google.com: domain of alice@google.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=alice@google.com;
    dkim=pass header.i=@google.com header.s=20230601;
    dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
From: "Google Cloud Support" <support@google.com>
Reply-To: support@google.com
Return-Path: <support@google.com>
Subject: Your Cloud Platform Monthly Summary
Date: Wed, 08 Oct 2026 10:00:00 +0000
"""

SPOOFED_HEADERS = """Received: from badserver.attacker.com (badserver.attacker.com [198.51.100.22])
    by mx.destination.com with ESMTP id zyx987
    for <victim@example.com>; Wed, 08 Oct 2026 10:05:00 +0000
Authentication-Results: mx.destination.com;
    spf=fail (sender IP 198.51.100.22 is not permitted by domain microsoft.com);
    dkim=fail;
    dmarc=fail (p=REJECT)
From: "Microsoft Security Center" <alert@microsoft-security-verify.com>
Reply-To: phisher@attacker.org
Return-Path: <bounce@unrelated-server.net>
Subject: Critical Security Notice: Verify your Microsoft 365 Account Immediately
Date: Wed, 08 Oct 2026 10:05:00 +0000
"""

BEC_MISMATCHED_REPLYTO_HEADERS = """Received: from mail.legitcorp.com (mail.legitcorp.com [192.0.2.10])
    by mx.destination.com with ESMTPS id bec111
    for <treasury@example.com>; Wed, 08 Oct 2026 10:10:00 +0000
Authentication-Results: mx.destination.com;
    spf=pass (legitcorp.com: domain designates 192.0.2.10);
    dkim=pass header.i=@legitcorp.com;
    dmarc=pass header.from=legitcorp.com
From: "John Doe - Director of Finance" <john.doe@legitcorp.com>
Reply-To: john.doe.offshore.account@consultant-invoicing.net
Return-Path: <john.doe@legitcorp.com>
Subject: Urgent: Updated Vendor Wire Routing Instructions
Date: Wed, 08 Oct 2026 10:10:00 +0000
"""

FREE_MAIL_EXECUTIVE_HEADERS = """Received: from mail-relay.yahoo.com (mail-relay.yahoo.com [98.138.219.1])
    by mx.destination.com with ESMTPS id free001;
    Wed, 08 Oct 2026 10:15:00 +0000
Authentication-Results: mx.destination.com; spf=pass; dkim=pass
From: "Chase Bank CEO Executive Office" <chase.executive.office@gmail.com>
Reply-To: chase.executive.office@gmail.com
Subject: Notice from JPMorgan Chase CEO Regarding Your Private Account
Date: Wed, 08 Oct 2026 10:15:00 +0000
"""

MULTIPLE_HOPS_HEADERS = """Received: from hop6.relay.net by dest.com; Wed, 08 Oct 2026 10:06:00 +0000
Received: from hop5.relay.net by hop6.relay.net; Wed, 08 Oct 2026 10:05:00 +0000
Received: from hop4.relay.net by hop5.relay.net; Wed, 08 Oct 2026 10:04:00 +0000
Received: from hop3.relay.net by hop4.relay.net; Wed, 08 Oct 2026 10:03:00 +0000
Received: from hop2.relay.net by hop3.relay.net; Wed, 08 Oct 2026 10:02:00 +0000
Received: from hop1.relay.net by hop2.relay.net; Wed, 08 Oct 2026 10:01:00 +0000
Authentication-Results: dest.com; spf=pass; dkim=pass
From: "Newsletter" <news@updates.example.com>
Subject: Weekly Digest
"""


def test_legitimate_header_low_confidence():
    """Requirement: One legitimate header with low impersonation confidence."""
    result = analyze_identity_headers(LEGIT_HEADERS)
    assert result.is_valid is True
    assert result.impersonation_confidence == "low"
    assert result.sender_domain == "google.com"
    assert result.signals["auth_failure"] is False
    assert result.signals["brand_mismatch"] is False
    assert result.signals["reply_to_mismatch"] is False
    assert len(result.recommended_actions) >= 1


def test_spoofed_header_high_confidence():
    """Requirement: One spoofed header with high impersonation confidence (SPF fail + brand mismatch)."""
    result = analyze_identity_headers(SPOOFED_HEADERS)
    assert result.is_valid is True
    assert result.impersonation_confidence == "high"
    assert result.signals["auth_failure"] is True
    assert result.signals["brand_mismatch"] is True
    assert result.signals["reply_to_mismatch"] is True
    assert any("SPF" in f.title or "Authentication" in f.title for f in result.findings)
    assert any("Microsoft" in f.title or "Lookalike" in f.title for f in result.findings)
    assert len(result.recommended_actions) >= 2


def test_bec_mismatched_reply_to_medium_confidence():
    """Requirement: One BEC-style header with matching domain but mismatched Reply-To (medium confidence)."""
    result = analyze_identity_headers(BEC_MISMATCHED_REPLYTO_HEADERS)
    assert result.is_valid is True
    assert result.impersonation_confidence == "medium"
    assert result.signals["auth_failure"] is False
    assert result.signals["reply_to_mismatch"] is True
    assert any(f.signal_type == "reply_to_mismatch" for f in result.findings)
    assert any("Reply-To" in act for act in result.recommended_actions)


def test_free_mail_for_corporate_role():
    """Requirement: Free webmail claiming corporate / executive role."""
    result = analyze_identity_headers(FREE_MAIL_EXECUTIVE_HEADERS)
    assert result.is_valid is True
    assert result.impersonation_confidence == "high"
    assert result.signals["free_webmail_impersonation"] is True
    assert any("Free Webmail" in f.title for f in result.findings)


def test_multiple_received_hops():
    """Requirement: Count Received headers, flag chains longer than 5."""
    result = analyze_identity_headers(MULTIPLE_HOPS_HEADERS)
    assert result.is_valid is True
    assert result.received_hops == 6
    assert result.signals["excessive_hops"] is True
    assert any("Suspicious Relay Chain" in f.title for f in result.findings)


def test_empty_and_malformed_headers():
    """Test handling of empty or blank header blocks."""
    res_empty = analyze_identity_headers("")
    assert res_empty.is_valid is False
    assert res_empty.impersonation_confidence == "low"
    assert len(res_empty.findings) >= 1

    res_spaces = analyze_identity_headers("   \n\t  ")
    assert res_spaces.is_valid is False


def test_header_helpers():
    """Test parsing utilities for address extraction and auth results."""
    name, addr, dom = extract_email_address_and_domain('Alice Smith <alice@company.com>')
    assert name == "Alice Smith"
    assert addr == "alice@company.com"
    assert dom == "company.com"

    auth = parse_auth_results("spf=fail (ip 1.2.3.4) dkim=pass dmarc=fail")
    assert auth["spf"] == "fail"
    assert auth["dkim"] == "pass"
    assert auth["dmarc"] == "fail"
