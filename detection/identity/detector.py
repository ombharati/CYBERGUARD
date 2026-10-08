"""Deterministic Email Header & Identity Impersonation Detection Engine.

Covers Scenario 2: Spoofed headers, brand impersonation, SPF/DKIM/DMARC failures,
display name deception, Reply-To mismatches, and routing anomalies.
"""
import re
import email
from email import policy
from email.parser import HeaderParser
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Set

from detection.url.detector import Finding
from detection.url.brand_registry import find_claimed_brand, is_official_domain

# Free webmail providers often abused for BEC and executive spoofing
FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "icloud.com", "protonmail.com", "mail.com", "zoho.com",
    "yandex.com", "gmx.com"
}

# Executive, institutional, and high-privilege corporate titles
CORPORATE_ROLES = {
    "ceo", "cfo", "cto", "coo", "cio", "president", "director", "manager",
    "executive", "payroll", "human resources", "hr", "accounting", "treasury",
    "billing", "it support", "helpdesk", "administrator", "admin", "security",
    "bank", "banking", "finance", "legal", "compliance"
}


@dataclass
class IdentityAnalysisResult:
    is_valid: bool
    impersonation_confidence: str  # "low", "medium", "high"
    sender_name: str = ""
    sender_address: str = ""
    sender_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    received_hops: int = 0
    signals: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    error_message: Optional[str] = None


def extract_email_address_and_domain(header_val: str) -> Tuple[str, str, str]:
    """Extract (display_name, email_address, domain) from a header string."""
    if not header_val:
        return "", "", ""
    name, addr = email.utils.parseaddr(header_val.strip())
    domain = addr.split("@")[-1].strip().lower() if "@" in addr else ""
    return name.strip(), addr.strip().lower(), domain


def parse_auth_results(auth_header: str) -> Dict[str, str]:
    """Extract SPF, DKIM, and DMARC verdicts from Authentication-Results or Received-SPF."""
    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    if not auth_header:
        return results

    lower = auth_header.lower()

    # SPF verdict
    spf_match = re.search(r"\bspf=(pass|fail|softfail|neutral|none|permerror|temperror)\b", lower)
    if spf_match:
        results["spf"] = spf_match.group(1)
    elif "pass" in lower and "spf" in lower:
        results["spf"] = "pass"
    elif "fail" in lower and "spf" in lower:
        results["spf"] = "fail"

    # DKIM verdict
    dkim_match = re.search(r"\bdkim=(pass|fail|none|permerror|temperror)\b", lower)
    if dkim_match:
        results["dkim"] = dkim_match.group(1)

    # DMARC verdict
    dmarc_match = re.search(r"\bdmarc=(pass|fail|none|permerror|temperror)\b", lower)
    if dmarc_match:
        results["dmarc"] = dmarc_match.group(1)

    return results


def analyze_identity_headers(raw_headers: str) -> IdentityAnalysisResult:
    """
    Perform deterministic analysis on email headers to detect spoofing and impersonation:
    1. SPF/DKIM/DMARC alignment
    2. Display name vs From domain mismatch
    3. Reply-To vs From mismatch
    4. Return-Path vs From mismatch
    5. Free webmail for corporate / executive role
    6. Brand lookalike domain
    7. Newly registered domain (WHOIS check or unchecked note)
    8. Multiple Received hops (> 5)
    """
    if not raw_headers or not isinstance(raw_headers, str) or not raw_headers.strip():
        return IdentityAnalysisResult(
            is_valid=False,
            impersonation_confidence="low",
            error_message="Header input is empty",
            findings=[Finding(
                severity="low",
                title="Empty Header Input",
                description="No email headers provided for identity analysis.",
                category="identity",
                signal_type="empty_headers",
                source="deterministic"
            )]
        )

    parser = HeaderParser()
    msg = parser.parsestr(raw_headers)

    from_header = msg.get("From", "")
    reply_to_header = msg.get("Reply-To", "")
    return_path_header = msg.get("Return-Path", "")
    auth_results_header = msg.get("Authentication-Results", "")
    received_spf_header = msg.get("Received-SPF", "")
    subject_header = msg.get("Subject", "")
    received_headers = msg.get_all("Received", []) or []

    sender_name, sender_addr, sender_domain = extract_email_address_and_domain(from_header)
    reply_to_name, reply_to_addr, reply_to_domain = extract_email_address_and_domain(reply_to_header)
    _, return_path_addr, return_path_domain = extract_email_address_and_domain(return_path_header)

    findings: List[Finding] = []
    recommended_actions: List[str] = []

    # Combined Auth Results
    combined_auth_text = f"{auth_results_header} {received_spf_header}"
    auth_results = parse_auth_results(combined_auth_text)

    signals: Dict[str, Any] = {
        "from": from_header,
        "sender_name": sender_name,
        "sender_domain": sender_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "spf_status": auth_results["spf"],
        "dkim_status": auth_results["dkim"],
        "dmarc_status": auth_results["dmarc"],
        "received_hops": len(received_headers),
        "auth_failure": False,
        "brand_mismatch": False,
        "reply_to_mismatch": False,
        "return_path_mismatch": False,
        "free_webmail_impersonation": False,
        "lookalike_domain": False,
        "newly_registered_domain": False,
        "whois_checked": False,
        "excessive_hops": False,
    }

    # 1. SPF / DKIM / DMARC Alignment
    has_auth_header = bool(auth_results_header or received_spf_header)
    if has_auth_header:
        problem_auths = []
        for protocol in ("spf", "dkim", "dmarc"):
            verdict = auth_results[protocol]
            if verdict in ("fail", "softfail", "permerror"):
                problem_auths.append(f"{protocol.upper()}={verdict}")

        if problem_auths:
            signals["auth_failure"] = True
            findings.append(Finding(
                severity="high" if any("fail" in p for p in problem_auths) else "medium",
                title=f"Email Authentication Failure ({', '.join(problem_auths)})",
                description=f"Inbound authentication checks failed to verify sending server authenticity: {', '.join(problem_auths)}.",
                category="identity",
                signal_type="spf_fail" if "SPF=fail" in problem_auths else "auth_failure",
                evidence=combined_auth_text.strip()[:200],
                source="deterministic",
                recommended_actions=[
                    "Block sender domain or IP at email gateway",
                    "Quarantine email and warn recipient of potential forgery",
                    "Verify DMARC enforcement policy with domain owner"
                ]
            ))
            recommended_actions.append("Block sender domain or IP at email gateway")
            recommended_actions.append("Quarantine email and warn recipient")

    # 2. Display Name vs Domain Mismatch & Claimed Brand Lookalike
    brand_match = find_claimed_brand(sender_name)
    if brand_match and sender_domain:
        brand_key, brand_info = brand_match
        is_official = is_official_domain(sender_domain, brand_key)

        if not is_official:
            signals["brand_mismatch"] = True
            # Check if domain itself looks like brand or generic lookalike
            if brand_key in sender_domain or any(a in sender_domain for a in brand_info.get("aliases", [])):
                signals["lookalike_domain"] = True
                signals["is_lookalike_domain"] = True
                findings.append(Finding(
                    severity="high",
                    title=f"Brand Lookalike Domain Impersonation ({brand_info['name']})",
                    description=f"Sender domain '{sender_domain}' mimics authorized domain of {brand_info['name']} without matching official registration.",
                    category="identity",
                    signal_type="lookalike_domain",
                    evidence=f"From: {from_header}",
                    source="deterministic",
                    recommended_actions=[
                        f"Quarantine messages from '{sender_domain}'",
                        f"Report typosquat domain '{sender_domain}' to {brand_info['name']} brand protection",
                        "Force credential reset if users clicked embedded links"
                    ]
                ))
            else:
                findings.append(Finding(
                    severity="high",
                    title=f"Display Name Spoofing ({brand_info['name']})",
                    description=f"Display name claims '{sender_name}' ({brand_info['name']}), but email originates from unrelated domain '{sender_domain}'.",
                    category="identity",
                    signal_type="display_name_spoofing",
                    evidence=f"From: {from_header}",
                    source="deterministic",
                    recommended_actions=[
                        "Reject or tag message with external display name warning",
                        "Warn user not to trust sender identity"
                    ]
                ))
            recommended_actions.append(f"Quarantine messages claiming {brand_info['name']}")

    # 3. Reply-To vs From Mismatch
    if reply_to_domain and sender_domain and reply_to_domain != sender_domain:
        signals["reply_to_mismatch"] = True
        findings.append(Finding(
            severity="medium",
            title="Reply-To Routing Mismatch",
            description=f"Sender claims domain '{sender_domain}', but replies are diverted to different domain '{reply_to_domain}'.",
            category="identity",
            signal_type="reply_to_mismatch",
            evidence=f"From: {from_header}\nReply-To: {reply_to_header}",
            source="deterministic",
            recommended_actions=[
                f"Verify recipient did not send replies to {reply_to_addr}",
                "Quarantine related emails across mailboxes",
                "Alert SOC to possible Business Email Compromise (BEC)"
            ]
        ))
        recommended_actions.append("Warn recipient of diverted Reply-To destination")

    # 4. Return-Path vs From Mismatch
    if return_path_domain and sender_domain and return_path_domain != sender_domain:
        signals["return_path_mismatch"] = True
        findings.append(Finding(
            severity="low",
            title="Return-Path Envelope Mismatch",
            description=f"Envelope Return-Path domain '{return_path_domain}' differs from visible header From domain '{sender_domain}'.",
            category="identity",
            signal_type="return_path_mismatch",
            evidence=f"From: {from_header}\nReturn-Path: {return_path_header}",
            source="deterministic",
            recommended_actions=[
                "Inspect bounce handling routing and SPF alignment"
            ]
        ))

    # 5. Free Mail for Corporate / Executive Role
    if sender_domain in FREE_WEBMAIL_DOMAINS:
        combined_text = f"{sender_name} {subject_header}".lower()
        role_found = next((role for role in CORPORATE_ROLES if re.search(rf"\b{role}\b", combined_text)), None)
        if role_found:
            signals["free_webmail_impersonation"] = True
            findings.append(Finding(
                severity="high",
                title=f"Free Webmail Used for Corporate Role ('{role_found.upper()}')",
                description=f"Sender uses free consumer webmail provider '{sender_domain}' while claiming institutional/executive role '{role_found}'.",
                category="identity",
                signal_type="free_webmail_impersonation",
                evidence=f"From: {from_header}\nSubject: {subject_header}",
                source="deterministic",
                recommended_actions=[
                    "Block sender address",
                    "Warn recipient against financial requests or wire transfers",
                    "Conduct out-of-band verification with executive"
                ]
            ))
            recommended_actions.append("Conduct out-of-band identity verification")

    # 6. Newly Registered Domain / WHOIS Check
    # In local-first mode without live WHOIS network dependency, mark as unchecked
    findings.append(Finding(
        severity="low",
        title="Domain Age Inspection (Local Baseline)",
        description=f"Domain age for '{sender_domain or 'unknown'}' not verified via local WHOIS cache (marked unchecked).",
        category="identity",
        signal_type="domain_age_unchecked",
        evidence=f"Domain: {sender_domain}",
        source="deterministic"
    ))

    # 7. Multiple Received Hops (> 5)
    hop_count = len(received_headers)
    if hop_count > 5:
        signals["excessive_hops"] = True
        findings.append(Finding(
            severity="medium",
            title=f"Suspicious Relay Chain ({hop_count} Hops)",
            description=f"Email traversed {hop_count} intermediate MTA Received hops, which is characteristic of open proxies, compromised relays, or evasion chaining.",
            category="identity",
            signal_type="excessive_hops",
            evidence=f"{hop_count} Received headers found in sequence",
            source="deterministic",
            recommended_actions=[
                "Trace originating client IP from earliest Received header",
                "Audit relay MTA reputations in spam blacklists"
            ]
        ))
        recommended_actions.append("Audit relay MTA path and block upstream open relay")

    # Determine overall impersonation confidence
    has_high = any(f.severity == "high" for f in findings)
    has_medium = any(f.severity == "medium" for f in findings)

    if has_high:
        confidence = "high"
    elif has_medium:
        confidence = "medium"
    else:
        confidence = "low"
        if not any(f.severity in ("high", "medium") for f in findings):
            findings.insert(0, Finding(
                severity="low",
                title="Verified Identity Alignment",
                description="Sender headers, authentication records, and routing paths align consistently with legitimate messaging standards.",
                category="identity",
                signal_type="clean_identity",
                source="deterministic"
            ))

    # Deduplicate recommended actions
    clean_actions = []
    for act in recommended_actions:
        if act not in clean_actions:
            clean_actions.append(act)
    if not clean_actions:
        clean_actions = ["No immediate containment action required; sender identity aligns."]

    return IdentityAnalysisResult(
        is_valid=True,
        impersonation_confidence=confidence,
        sender_name=sender_name,
        sender_address=sender_addr,
        sender_domain=sender_domain,
        reply_to=reply_to_addr,
        return_path=return_path_addr,
        received_hops=hop_count,
        signals=signals,
        findings=findings,
        recommended_actions=clean_actions
    )
