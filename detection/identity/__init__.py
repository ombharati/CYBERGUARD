"""Identity and email header impersonation detection package."""
from detection.identity.detector import (
    analyze_identity_headers,
    IdentityAnalysisResult,
    extract_email_address_and_domain,
    parse_auth_results,
    FREE_WEBMAIL_DOMAINS,
)

__all__ = [
    "analyze_identity_headers",
    "IdentityAnalysisResult",
    "extract_email_address_and_domain",
    "parse_auth_results",
    "FREE_WEBMAIL_DOMAINS",
]
