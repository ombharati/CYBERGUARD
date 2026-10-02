"""Deterministic Email Heuristic Detection."""
import re
from typing import List, Dict, Any
from detection.email.parser import ParsedEmail
from detection.url.detector import Finding

FREE_WEBMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "live.com",
    "aol.com", "icloud.com", "protonmail.com", "mail.com", "zoho.com",
    "yandex.com", "gmx.com"
}

INSTITUTIONAL_KEYWORDS = {
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "chase", "wellsfargo", "bankofamerica", "citi", "security",
    "support", "helpdesk", "administrator", "it support", "billing",
    "account verification", "payroll", "human resources"
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


def analyze_email_heuristics(parsed: ParsedEmail) -> Dict[str, Any]:
    """
    Run deterministic heuristic rules on a parsed email.
    Returns extracted signals and structured findings.
    """
    findings: List[Finding] = []
    signals: Dict[str, Any] = {
        "display_name_spoofing": False,
        "free_webmail_impersonation": False,
        "reply_to_mismatch": False,
        "urgency_matches": 0,
        "credential_matches": 0,
        "auth_failure": False,
        "url_count": len(parsed.extracted_urls),
    }

    sender_lower = parsed.sender.lower()
    sender_name_lower = parsed.sender_name.lower()
    domain_lower = parsed.sender_domain.lower()
    subject_lower = parsed.subject.lower()
    body_lower = parsed.plain_body.lower()
    combined_content = f"{subject_lower} {body_lower}"

    # 1. Display Name Spoofing with Free Webmail
    if parsed.sender_name:
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

    # 3. Urgency and Coercion Patterns
    matched_urgency = [p for p in URGENCY_PATTERNS if re.search(p, combined_content)]
    signals["urgency_matches"] = len(matched_urgency)
    if len(matched_urgency) >= 2:
        findings.append(Finding(
            severity="medium",
            title="Coercive Urgency Language",
            description="The message repeatedly applies psychological pressure demanding immediate action or warning of account closure.",
            category="deterministic_email"
        ))
    elif len(matched_urgency) == 1:
        findings.append(Finding(
            severity="low",
            title="Urgency Indicators Present",
            description="The message contains urgency phrasing commonly observed in time-sensitive communications.",
            category="deterministic_email"
        ))

    # 4. Credential Harvesting Phrases
    matched_cred = [p for p in CREDENTIAL_HARVESTING_PATTERNS if re.search(p, combined_content)]
    signals["credential_matches"] = len(matched_cred)
    if len(matched_cred) >= 1:
        findings.append(Finding(
            severity="high",
            title="Credential Harvesting Call to Action",
            description="The email explicitly directs the recipient to enter authentication credentials, passwords, or account numbers.",
            category="deterministic_email"
        ))

    # 5. SPF / DKIM / DMARC Header Verification
    auth_header = (parsed.headers.get("authentication-results", "") + " " + parsed.headers.get("received-spf", "")).lower()
    if any(k in auth_header for k in ("spf=fail", "spf=softfail", "softfail", "dmarc=fail", "dkim=fail", "fail (")):
        signals["auth_failure"] = True
        findings.append(Finding(
            severity="high",
            title="Email Authentication Failure (SPF/DKIM/DMARC)",
            description="Email headers indicate that the sending server failed SPF, DKIM, or DMARC authentication for the claimed domain.",
            category="deterministic_email"
        ))

    # 6. Embedded URLs
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
