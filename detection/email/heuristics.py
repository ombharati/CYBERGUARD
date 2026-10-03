"""Deterministic Email Heuristic Detection.

Contextual Threat Analysis:
- IDENTITY: Does the sending domain match the claimed brand?
- BEHAVIOR: Is this action expected in context?
- REQUEST: Is something being asked that a real service wouldn't ask?
"""
import re
from typing import List, Dict, Any
from detection.email.parser import ParsedEmail
from detection.url.detector import Finding
from detection.url.brand_registry import find_claimed_brand, is_official_domain

FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "icloud.com", "protonmail.com", "mail.com", "zoho.com",
    "yandex.com", "gmx.com"
}

INSTITUTIONAL_KEYWORDS = {
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "chase", "wellsfargo", "bankofamerica", "citi", "security",
    "support", "helpdesk", "administrator", "it support", "billing",
    "account verification", "payroll", "human resources", "hdfc", "sbi", "icici", "axis"
}

URGENCY_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\baction\s+required\b",
    r"\baccount\s+suspended\b",
    r"\bsuspended\s+within\b",
    r"\bwithin\s+24\s+hours\b",
    r"\bwithin\s+48\s+hours\b",
    r"\bdeadline\b",
    r"\bfailure\s+to\s+respond\b",
    r"\bfinal\s+warning\b",
    r"\bsecurity\s+alert\b",
    r"\bunauthorized\s+access\b",
]

CREDENTIAL_HARVESTING_PATTERNS = [
    r"\bconfirm\s+your\s+password\b",
    r"\bverify\s+your\s+identity\b",
    r"\bupdate\s+your\s+credentials\b",
    r"\blogin\s+to\s+verify\b",
    r"\bclick\s+here\s+to\s+(?:verify|login|restore|unlock)\b",
    r"\benter\s+your\s+(?:pin|password|ssn|otp)\b",
    r"\breset\s+your\s+password\b",
]

SECRECY_PATTERNS = [
    r"\bkeep\s+(?:this\s+)?confidential\b",
    r"\bdo\s+not\s+(?:tell|disclose|share)\b",
    r"\bstrictly\s+confidential\b",
    r"\bprivate\s+matter\b",
]

UNUSUAL_PAYMENT_PATTERNS = [
    r"\bgift\s*card\b",
    r"\bitunes\b",
    r"\bbitcoin\b|\bcrypto\b|\beth\b|\busdt\b",
    r"\bwire\s+transfer\s+to\s+new\b",
]

GENERIC_GREETING_PATTERNS = [
    r"\bdear\s+customer\b",
    r"\bdear\s+user\b",
    r"\bdear\s+client\b",
    r"\bdear\s+account\s+holder\b",
    r"\bvalued\s+customer\b",
]


def analyze_email_heuristics(parsed: ParsedEmail) -> Dict[str, Any]:
    """
    Run deterministic heuristic rules on a parsed email.
    Evaluates identity consistency, behavior expectation, and request safety.
    """
    findings: List[Finding] = []
    signals: Dict[str, Any] = {
        "display_name_spoofing": False,
        "free_webmail_impersonation": False,
        "brand_mismatch": False,
        "reply_to_mismatch": False,
        "urgency_matches": 0,
        "credential_matches": 0,
        "secrecy_demanded": False,
        "unusual_payment": False,
        "auth_failure": False,
        "url_count": len(parsed.extracted_urls),
    }

    sender_lower = parsed.sender.lower()
    sender_name_lower = parsed.sender_name.lower()
    domain_lower = parsed.sender_domain.lower()
    subject_lower = parsed.subject.lower()
    body_lower = parsed.plain_body.lower()
    combined_content = f"{subject_lower} {body_lower}"

    # 1. Identity Verification (Claimed Brand vs Actual Domain)
    claimed_brand = find_claimed_brand(parsed.sender_name + " " + parsed.subject)
    if claimed_brand:
        brand_key, brand_info = claimed_brand
        official = is_official_domain(domain_lower, brand_key)
        if not official:
            signals["brand_mismatch"] = True
            if domain_lower in FREE_WEBMAIL_DOMAINS:
                signals["free_webmail_impersonation"] = True
                findings.append(Finding(
                    severity="high",
                    title=f"Display Name Spoofing: Brand Impersonation via Free Webmail ({brand_info['name']})",
                    description=f"Sender claims to be '{parsed.sender_name}' ({brand_info['name']}) but sends from a free public webmail address (@{domain_lower}).",
                    category="deterministic_email"
                ))
            else:
                signals["display_name_spoofing"] = True
                findings.append(Finding(
                    severity="high",
                    title=f"Display Name Spoofing: Brand Domain Mismatch ({brand_info['name']})",
                    description=f"Message claims to originate from {brand_info['name']}, but sending domain '@{domain_lower}' is not an authorized official domain.",
                    category="deterministic_email"
                ))
        else:
            findings.append(Finding(
                severity="low",
                title=f"Verified Official Sender Domain ({brand_info['name']})",
                description=f"The email originates from an official authorized domain (@{domain_lower}) for {brand_info['name']}.",
                category="deterministic_email"
            ))
    elif parsed.sender_name:
        for inst_kw in INSTITUTIONAL_KEYWORDS:
            if inst_kw in sender_name_lower:
                if domain_lower in FREE_WEBMAIL_DOMAINS:
                    signals["free_webmail_impersonation"] = True
                    findings.append(Finding(
                        severity="high",
                        title="Display Name Spoofing with Free Webmail",
                        description=f"The sender display name claims to be '{parsed.sender_name}', but uses a free public webmail service (@{domain_lower}).",
                        category="deterministic_email"
                    ))
                    break
                elif inst_kw.replace(" ", "") not in domain_lower and domain_lower:
                    signals["display_name_spoofing"] = True
                    findings.append(Finding(
                        severity="medium",
                        title="Potential Sender Impersonation",
                        description=f"Sender display name references '{parsed.sender_name}', but message originates from an unrelated domain (@{domain_lower}).",
                        category="deterministic_email"
                    ))
                    break

    # 2. Reply-To Mismatch
    if parsed.reply_to and parsed.reply_to_domain and parsed.sender_domain:
        if parsed.reply_to_domain != parsed.sender_domain:
            signals["reply_to_mismatch"] = True
            findings.append(Finding(
                severity="high",
                title="Reply-To Domain Mismatch",
                description=f"Replies are directed to an external domain (@{parsed.reply_to_domain}) differing from the sender (@{parsed.sender_domain}).",
                category="deterministic_email"
            ))

    # 3. Request Checks: Credential Asks, Secrecy, Unusual Payments
    matched_cred = [p for p in CREDENTIAL_HARVESTING_PATTERNS if re.search(p, combined_content)]
    signals["credential_matches"] = len(matched_cred)
    if signals["credential_matches"] > 0:
        findings.append(Finding(
            severity="high",
            title="Credential Harvesting Language",
            description=f"Detected {signals['credential_matches']} pattern(s) soliciting sensitive credentials, passwords, or authentication verification.",
            category="deterministic_email"
        ))

    has_secrecy = any(re.search(p, combined_content) for p in SECRECY_PATTERNS)
    signals["secrecy_demanded"] = has_secrecy
    if has_secrecy:
        findings.append(Finding(
            severity="high",
            title="Coercive Secrecy / Confidentiality Demand",
            description="The message demands the recipient keep the communication secret or not disclose it to colleagues/advisors.",
            category="deterministic_email"
        ))

    has_unusual_payment = any(re.search(p, combined_content) for p in UNUSUAL_PAYMENT_PATTERNS)
    signals["unusual_payment"] = has_unusual_payment
    if has_unusual_payment:
        findings.append(Finding(
            severity="high",
            title="Unusual Payment Method Requested",
            description="The communication requests payment via cryptocurrency, gift cards, or unconventional wiring.",
            category="deterministic_email"
        ))

    # 4. Contextual Urgency Evaluation
    matched_urgency = [p for p in URGENCY_PATTERNS if re.search(p, combined_content)]
    signals["urgency_matches"] = len(matched_urgency)

    # Urgency rule: only a strong signal when used to short-circuit a decision involving credentials, secrecy, or payment
    if len(matched_urgency) >= 1:
        if signals["credential_matches"] > 0 or signals["brand_mismatch"] or has_secrecy or has_unusual_payment:
            findings.append(Finding(
                severity="high",
                title="Urgency Used to Short-Circuit Decision",
                description="Artificial urgency or account suspension threats are combined with a credential/payment request or lookalike sender.",
                category="deterministic_email"
            ))
        else:
            findings.append(Finding(
                severity="low",
                title="Routine Time-Sensitivity Phrasing",
                description="The message contains urgency phrasing (e.g. deadline or limited-time notice) without anomalous credential or payment demands.",
                category="deterministic_email"
            ))

    # 5. Generic Greeting on Institutional Context
    has_generic_greeting = any(re.search(p, combined_content) for p in GENERIC_GREETING_PATTERNS)
    if has_generic_greeting and (signals["brand_mismatch"] or signals["display_name_spoofing"]):
        findings.append(Finding(
            severity="low",
            title="Generic Salutation on Institutional Notice",
            description="The message uses an impersonal greeting ('Dear Customer') while claiming an established institutional relationship.",
            category="deterministic_email"
        ))

    # 6. SPF / DKIM / DMARC Header Verification
    auth_header = (parsed.headers.get("authentication-results", "") + " " + parsed.headers.get("received-spf", "")).lower()
    if any(k in auth_header for k in ("spf=fail", "spf=softfail", "softfail", "dmarc=fail", "dkim=fail", "fail (")):
        signals["auth_failure"] = True
        findings.append(Finding(
            severity="high",
            title="Email Authentication Failure (SPF/DKIM/DMARC)",
            description="Email headers indicate that the sending server failed SPF, DKIM, or DMARC authentication for the claimed domain.",
            category="deterministic_email"
        ))

    # 7. Embedded URLs
    if signals["url_count"] > 0:
        findings.append(Finding(
            severity="low",
            title=f"Extracted Hyperlinks ({signals['url_count']})",
            description=f"Identified {signals['url_count']} external link(s) embedded in email content for deeper analysis.",
            category="deterministic_email"
        ))

    return {
        "signals": signals,
        "findings": findings,
    }
