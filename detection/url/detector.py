"""Deterministic URL Analysis and Heuristic Detection."""
import re
import math
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from detection.url.ssrf import validate_hostname_ssrf, is_ip_private_or_restricted
from detection.url.brand_registry import evaluate_brand_identity, SENSITIVE_WORKFLOW_PATHS, find_claimed_brand


# Known high-abuse or commonly abused free/cheap top-level domains
HIGH_RISK_TLDS = {
    "top", "xyz", "tk", "ml", "ga", "cf", "gq", "buzz", "fit", "surf",
    "work", "rest", "bar", "icu", "club", "cam", "quest", "click", "live"
}

# Suspicious keywords in security, banking, and credential flows
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "verification", "account", "security",
    "update", "billing", "confirm", "confirmation", "banking", "wallet",
    "password", "credential", "auth", "authorize", "recover", "suspension",
    "support", "secure", "ebay", "paypal", "microsoft", "apple", "netflix",
    "amazon", "google", "facebook", "chase", "wellsfargo"
}

# Suspicious executable or script extensions in URL path
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".apk", ".msi", ".jar",
    ".iso", ".bin", ".dmg", ".elf", ".sh"
}


@dataclass
class Finding:
    severity: str  # "low", "medium", "high", "critical"
    title: str
    description: str
    category: str = "deterministic_url"
    signal_type: Optional[str] = None
    weight: int = 0
    evidence: Optional[str] = None
    source: str = "deterministic"
    recommended_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "signal_type": self.signal_type or self.category,
            "weight": self.weight,
            "evidence": self.evidence,
            "source": self.source,
            "recommended_actions": self.recommended_actions,
        }


@dataclass
class URLAnalysisResult:
    raw_url: str
    normalized_url: str
    is_valid: bool
    error_message: Optional[str] = None
    signals: Dict[str, Any] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    is_ssrf_risk: bool = False
    ssrf_reason: Optional[str] = None


def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy for domain randomness/DGA detection."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    counts = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def normalize_url(raw_url: str, max_length: int = 2048) -> str:
    """Normalize raw URL string for safe parsing."""
    cleaned = raw_url.strip()
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
    # Ensure scheme is present for parsing
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
        cleaned = "http://" + cleaned
    return cleaned


def analyze_url(raw_url: str) -> URLAnalysisResult:
    """
    Perform deterministic analysis on a URL.
    Extracts objective signals and structured findings without jumping to conclusions.
    """
    if not raw_url or not isinstance(raw_url, str) or not raw_url.strip():
        return URLAnalysisResult(
            raw_url=str(raw_url),
            normalized_url="",
            is_valid=False,
            error_message="Empty or invalid URL input",
            findings=[Finding(
                severity="low",
                title="Invalid URL Format",
                description="The submitted URL is empty or malformed.",
                category="deterministic_url",
                signal_type="invalid_url",
                weight=5,
                evidence=str(raw_url)[:50],
                source="deterministic",
            )]
        )

    try:
        norm_url = normalize_url(raw_url)
        parsed = urllib.parse.urlsplit(norm_url)
    except Exception as exc:
        return URLAnalysisResult(
            raw_url=raw_url,
            normalized_url="",
            is_valid=False,
            error_message=f"Failed to parse URL: {str(exc)}",
            findings=[Finding(
                severity="low",
                title="Malformed URL",
                description="The URL could not be parsed according to RFC specifications.",
                category="deterministic_url",
                signal_type="malformed_url",
                weight=5,
                evidence=str(raw_url)[:50],
                source="deterministic",
            )]
        )

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query

    if not netloc:
        return URLAnalysisResult(
            raw_url=raw_url,
            normalized_url=norm_url,
            is_valid=False,
            error_message="Missing hostname in URL",
            findings=[Finding(
                severity="low",
                title="Missing Hostname",
                description="The URL does not specify a valid host authority.",
                category="deterministic_url",
                signal_type="missing_hostname",
                weight=5,
                evidence=str(raw_url)[:50],
                source="deterministic",
            )]
        )

    # Extract userinfo if present
    username = parsed.username
    password = parsed.password
    hostname = parsed.hostname or ""
    port = parsed.port

    # 0. Brand Identity and Official Domain Verification
    brand_eval = evaluate_brand_identity(hostname, path)
    path_lower = path.lower()
    has_sensitive_path = any(
        sp in path_lower for sp in ("/login", "/signin", "/verify", "/kyc", "/wallet", "/confirm", "/account", "/reset-password", "/auth")
    )

    signals: Dict[str, Any] = {
        "scheme": scheme,
        "hostname": hostname,
        "port": port,
        "has_credentials": bool(username or password),
        "url_length": len(raw_url),
        "hostname_length": len(hostname),
        "subdomain_count": max(0, len(hostname.split(".")) - 2) if "." in hostname else 0,
        "is_ip_address": False,
        "has_punycode": "xn--" in hostname,
        "entropy": calculate_shannon_entropy(hostname),
        "matched_keywords": [],
        "suspicious_tld": False,
        "dangerous_file_extension": False,
        "brand_claimed": brand_eval["brand_name"],
        "is_official_domain": brand_eval["is_official"],
        "is_lookalike_domain": brand_eval["is_lookalike"],
        "has_sensitive_path": has_sensitive_path,
    }

    findings: List[Finding] = []

    # Identity findings
    if brand_eval["is_official"]:
        findings.append(Finding(
            severity="low",
            title=f"Verified Official Domain ({brand_eval['brand_name']})",
            description=f"Destination is the verified official domain of {brand_eval['brand_name']}. Sensitive endpoints like /login or /verify are expected.",
            category="deterministic_url",
            signal_type="official_domain",
            weight=0,
            evidence=hostname,
            source="deterministic",
        ))
    elif brand_eval["is_lookalike"]:
        findings.append(Finding(
            severity="high",
            title=f"Unauthorized Brand Lookalike Domain ({brand_eval['brand_name']})",
            description=f"Hostname '{hostname}' claims or suggests {brand_eval['brand_name']} but does not match any official authorized domain.",
            category="deterministic_url",
            signal_type="lookalike_domain",
            weight=35,
            evidence=hostname,
            source="deterministic",
        ))
        if has_sensitive_path:
            findings.append(Finding(
                severity="high",
                title="Credential Harvest Path on Lookalike Domain",
                description=f"Sensitive authentication/verification path ('{path}') hosted on an unauthorized lookalike domain.",
                category="deterministic_url",
                signal_type="credential_harvesting",
                weight=25,
                evidence=path,
                source="deterministic",
            ))

    # 1. SSRF & Reserved IP/Domain Validation
    is_ssrf, ssrf_reason = validate_hostname_ssrf(hostname)
    if is_ssrf:
        findings.append(Finding(
            severity="high",
            title="SSRF / Private Network Target",
            description=f"Destination targets a restricted or internal network address ({ssrf_reason}).",
            category="deterministic_url",
            signal_type="ssrf_target",
            weight=45,
            evidence=hostname,
            source="deterministic",
        ))

    # 2. Scheme checks
    if scheme not in ("http", "https"):
        findings.append(Finding(
            severity="medium",
            title="Non-standard Web Protocol",
            description=f"The URL uses a non-standard web protocol ('{scheme}://') rather than HTTP/HTTPS.",
            category="deterministic_url",
            signal_type="non_standard_protocol",
            weight=15,
            evidence=scheme,
            source="deterministic",
        ))

    # 3. Direct IP Usage
    # Check if hostname is an IPv4 or IPv6 address
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname) or ":" in hostname:
        signals["is_ip_address"] = True
        findings.append(Finding(
            severity="medium",
            title="Direct IP Address Destination",
            description="The URL directly connects to an IP address instead of a registered domain name.",
            category="deterministic_url",
            signal_type="ip_literal",
            weight=20,
            evidence=hostname,
            source="deterministic",
        ))

    # 4. Embedded Credentials
    if username or password:
        findings.append(Finding(
            severity="high",
            title="Embedded Credentials in URL",
            description="The URL embeds authentication credentials in the authority component (user:pass@host).",
            category="deterministic_url",
            signal_type="embedded_credentials",
            weight=30,
            evidence=f"{username}:***@{hostname}",
            source="deterministic",
        ))

    # 5. Punycode / IDN Homograph
    if signals["has_punycode"]:
        try:
            decoded = hostname.encode("ascii").decode("idna")
            findings.append(Finding(
                severity="medium",
                title="Internationalized Domain Name (Punycode)",
                description=f"The domain uses Punycode encoding (resolves to '{decoded}'), often utilized in visual homograph attacks.",
                category="deterministic_url",
                signal_type="punycode_domain",
                weight=20,
                evidence=f"{hostname} ({decoded})",
                source="deterministic",
            ))
        except Exception:
            findings.append(Finding(
                severity="medium",
                title="Punycode Encoded Domain",
                description="The domain uses Punycode encoding which can disguise deceptive domain spelling.",
                category="deterministic_url",
                signal_type="punycode_domain",
                weight=20,
                evidence=hostname,
                source="deterministic",
            ))

    # 6. Deep Subdomain Hierarchy
    if signals["subdomain_count"] >= 3:
        findings.append(Finding(
            severity="medium",
            title="Deep Subdomain Hierarchy",
            description=f"The hostname contains {signals['subdomain_count']} nested subdomains, which can mask the true root authority.",
            category="deterministic_url",
            signal_type="deep_subdomains",
            weight=15,
            evidence=hostname,
            source="deterministic",
        ))

    # 7. Length Analysis
    if len(raw_url) > 120:
        findings.append(Finding(
            severity="low",
            title="Unusually Long URL",
            description=f"The URL length ({len(raw_url)} characters) is significantly longer than typical navigation targets.",
            category="deterministic_url",
            signal_type="url_length",
            weight=5,
            evidence=raw_url[:60] + "...",
            source="deterministic",
        ))
    if len(hostname) > 45:
        findings.append(Finding(
            severity="low",
            title="Unusually Long Hostname",
            description=f"The hostname is {len(hostname)} characters long, which can be an indicator of obfuscation or DGA.",
            category="deterministic_url",
            signal_type="hostname_length",
            weight=5,
            evidence=hostname,
            source="deterministic",
        ))

    # 8. High-Entropy Hostname (DGA / Obfuscation)
    if signals["entropy"] > 4.2 and len(hostname) > 15:
        findings.append(Finding(
            severity="medium",
            title="High Character Entropy in Domain",
            description=f"Domain entropy ({signals['entropy']}) suggests randomly generated or algorithmically generated naming.",
            category="deterministic_url",
            signal_type="high_entropy",
            weight=15,
            evidence=hostname,
            source="deterministic",
        ))

    # 9. Suspicious TLD (Overrepresented in abuse, but not standalone proof)
    tld = hostname.split(".")[-1] if "." in hostname else ""
    if tld in HIGH_RISK_TLDS:
        signals["suspicious_tld"] = True
        # Only treat as a warning finding when combined with brand lookalike, sensitive path, or raw IP
        if brand_eval["is_lookalike"] or has_sensitive_path or signals["is_ip_address"]:
            findings.append(Finding(
                severity="medium" if brand_eval["is_lookalike"] else "low",
                title=f"High-Abuse TLD Combined with Sensitive Context (.{tld})",
                description=f"The top-level domain '.{tld}' is overrepresented in phishing and paired with a brand lookalike or sensitive path.",
                category="deterministic_url",
                signal_type="suspicious_tld",
                weight=15,
                evidence=f".{tld}",
                source="deterministic",
            ))

    # 10. Keyword & Brand Analysis in Hostname and Path
    # On verified official domains, sensitive keywords (/login, /account) are routine and expected.
    full_target_lower = (hostname + path + query).lower()
    matched = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_target_lower]
    signals["matched_keywords"] = matched
    if not brand_eval["is_official"]:
        if len(matched) >= 2:
            findings.append(Finding(
                severity="medium",
                title="Multiple Security-Sensitive Keywords",
                description=f"The URL contains keywords often targeted by phishing kits: {', '.join(matched[:5])}.",
                category="deterministic_url",
                signal_type="sensitive_keywords",
                weight=20,
                evidence=", ".join(matched[:5]),
                source="deterministic",
            ))
        elif len(matched) == 1 and signals["subdomain_count"] >= 2:
            findings.append(Finding(
                severity="low",
                title="Security-Sensitive Keyword in Subdomain",
                description=f"The subdomain contains an authentication-related keyword ('{matched[0]}').",
                category="deterministic_url",
                signal_type="subdomain_keyword",
                weight=10,
                evidence=matched[0],
                source="deterministic",
            ))

    # 11. Dangerous Extensions
    path_lower = path.lower()
    for ext in DANGEROUS_EXTENSIONS:
        if path_lower.endswith(ext) or f"{ext}?" in path_lower:
            signals["dangerous_file_extension"] = True
            findings.append(Finding(
                severity="high",
                title=f"Direct Executable Download ({ext})",
                description=f"The URL targets a direct download of an executable or script file format ({ext}).",
                category="deterministic_url",
                signal_type="dangerous_extension",
                weight=35,
                evidence=ext,
                source="deterministic",
            ))
            break

    # 12. At Symbol in Path/Query (often used to obscure destination)
    if "@" in path or "@" in query:
        findings.append(Finding(
            severity="medium",
            title="At-Symbol (@) in URL Path or Query",
            description="The '@' character appears in the URL path/query, which is frequently used to mislead browser visual parsing.",
            category="deterministic_url",
            signal_type="at_symbol_obfuscation",
            weight=15,
            evidence="@",
            source="deterministic",
        ))

    # 13. Default benign finding if clean
    if not findings:
        findings.append(Finding(
            severity="low",
            title="Clean Structural Inspection",
            description="First-pass deterministic URL inspection found no overt structural red flags.",
            category="deterministic_url",
            signal_type="clean_url",
            weight=0,
            evidence=raw_url,
            source="deterministic",
        ))

    return URLAnalysisResult(
        raw_url=raw_url,
        normalized_url=norm_url,
        is_valid=True,
        signals=signals,
        findings=findings,
        is_ssrf_risk=is_ssrf,
        ssrf_reason=ssrf_reason,
    )
