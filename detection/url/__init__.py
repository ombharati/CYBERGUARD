"""URL detection module."""
from detection.url.detector import analyze_url, normalize_url, URLAnalysisResult, Finding
from detection.url.ssrf import validate_hostname_ssrf, is_ip_private_or_restricted

__all__ = [
    "analyze_url",
    "normalize_url",
    "URLAnalysisResult",
    "Finding",
    "validate_hostname_ssrf",
    "is_ip_private_or_restricted",
]
