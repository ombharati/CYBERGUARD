"""Brand and Official Domain Registry.

Maintains canonical reference of official domains for high-target institutions
(including post-RBI .bank.in migration for Indian banks and major global brands).

Used to perform accurate IDENTITY checks:
- Is a claimed brand operating on its official domain?
- Is a sensitive path (/login, /kyc, /verify) on an official domain (neutral/benign)
  or a lookalike domain (strong phishing signal)?
"""
from typing import Dict, List, Optional, Tuple, Set, Any


# Canonical registry of high-profile institutions and their authorized domains.
# Post-2025 RBI migration introduces official *.bank.in domains alongside legacy domains.
OFFICIAL_BRAND_DOMAINS: Dict[str, Dict[str, Any]] = {
    # --- Indian Banks (Post-RBI .bank.in Migration, 2025/2026) ---
    "sbi": {
        "name": "State Bank of India",
        "aliases": ["sbi", "state bank of india", "onlinesbi"],
        "official_domains": {"sbi.bank.in", "sbi.co.in", "onlinesbi.com", "onlinesbi.sbi"},
    },
    "hdfc": {
        "name": "HDFC Bank",
        "aliases": ["hdfc", "hdfc bank", "hdfcbank"],
        "official_domains": {"hdfc.bank.in", "hdfcbank.com", "hdfcbank.net"},
    },
    "icici": {
        "name": "ICICI Bank",
        "aliases": ["icici", "icici bank", "icicibank"],
        "official_domains": {"icici.bank.in", "icicibank.com", "icicibank.co.in"},
    },
    "axis": {
        "name": "Axis Bank",
        "aliases": ["axis", "axis bank", "axisbank"],
        "official_domains": {"axis.bank.in", "axisbank.com", "axisbank.co.in"},
    },
    "pnb": {
        "name": "Punjab National Bank",
        "aliases": ["pnb", "punjab national bank", "pnbindia"],
        "official_domains": {"pnb.bank.in", "pnbindia.in", "pnbindia.com"},
    },
    "bankofindia": {
        "name": "Bank of India",
        "aliases": ["bank of india", "bankofindia", "boi"],
        "official_domains": {"bankofindia.bank.in", "bankofindia.co.in"},
    },
    "indianbank": {
        "name": "Indian Bank",
        "aliases": ["indian bank", "indianbank"],
        "official_domains": {"indianbank.bank.in", "indianbank.in"},
    },
    "kotak": {
        "name": "Kotak Mahindra Bank",
        "aliases": ["kotak", "kotak mahindra bank", "kotakbank"],
        "official_domains": {"kotak.bank.in", "kotak.com"},
    },

    # --- Global Financial & Payment Brands ---
    "paypal": {
        "name": "PayPal",
        "aliases": ["paypal", "paypa1"],
        "official_domains": {"paypal.com", "paypal.me", "paypal-communication.com"},
    },
    "chase": {
        "name": "Chase Bank",
        "aliases": ["chase", "chase bank", "jpmorgan chase"],
        "official_domains": {"chase.com", "jpmorganchase.com"},
    },
    "bankofamerica": {
        "name": "Bank of America",
        "aliases": ["bank of america", "bankofamerica", "bofa"],
        "official_domains": {"bankofamerica.com", "bofa.com"},
    },
    "wellsfargo": {
        "name": "Wells Fargo",
        "aliases": ["wells fargo", "wellsfargo"],
        "official_domains": {"wellsfargo.com"},
    },
    "citibank": {
        "name": "Citibank",
        "aliases": ["citi", "citibank"],
        "official_domains": {"citi.com", "citibank.com"},
    },

    # --- Major Tech & Service Platforms ---
    "apple": {
        "name": "Apple",
        "aliases": ["apple", "appleid", "icloud"],
        "official_domains": {"apple.com", "icloud.com", "me.com"},
    },
    "microsoft": {
        "name": "Microsoft",
        "aliases": ["microsoft", "office365", "outlook", "live", "msn"],
        "official_domains": {"microsoft.com", "live.com", "office.com", "outlook.com", "office365.com", "msn.com"},
    },
    "google": {
        "name": "Google",
        "aliases": ["google", "gmail"],
        "official_domains": {"google.com", "gmail.com", "accounts.google.com", "googleapis.com", "gstatic.com", "googleusercontent.com"},
    },
    "amazon": {
        "name": "Amazon",
        "aliases": ["amazon", "aws"],
        "official_domains": {"amazon.com", "amazon.in", "amazon.co.uk", "aws.amazon.com", "amazonaws.com"},
    },
    "netflix": {
        "name": "Netflix",
        "aliases": ["netflix"],
        "official_domains": {"netflix.com"},
    },
    "meta": {
        "name": "Meta / Facebook",
        "aliases": ["facebook", "meta", "instagram", "whatsapp"],
        "official_domains": {"facebook.com", "meta.com", "instagram.com", "whatsapp.com"},
    },
}

# Sensitive workflow endpoints that are neutral on official domains
# but suspicious when paired with brand mismatches or lookalike domains.
SENSITIVE_WORKFLOW_PATHS: Set[str] = {
    "/login", "/signin", "/sign-in", "/log-in",
    "/verify", "/verification", "/kyc",
    "/wallet/connect", "/connect-wallet",
    "/confirm", "/confirmation",
    "/account/update", "/account/verify", "/account/security",
    "/password/reset", "/reset-password",
    "/auth", "/authorize",
    "/billing", "/payment",
}


def find_claimed_brand(text_or_url: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """
    Check if a URL or text string mentions or references a known high-profile brand.
    Returns (brand_key, brand_info) or None.
    """
    clean_text = text_or_url.lower()
    for brand_key, brand_info in OFFICIAL_BRAND_DOMAINS.items():
        for alias in brand_info["aliases"]:
            # Check for alias as distinct token or hyphenated segment
            if alias in clean_text:
                return brand_key, brand_info
    return None


def is_official_domain(hostname: str, brand_key: str) -> bool:
    """
    Check whether a given hostname belongs to the official domain list of the brand.
    Supports subdomains (e.g. 'netbanking.hdfcbank.com' or 'retail.onlinesbi.sbi').
    """
    clean_host = hostname.lower().strip(".")
    brand_info = OFFICIAL_BRAND_DOMAINS.get(brand_key)
    if not brand_info:
        return False

    for official in brand_info["official_domains"]:
        if clean_host == official or clean_host.endswith("." + official):
            return True
    return False


def evaluate_brand_identity(hostname: str, url_path: str = "") -> Dict[str, Any]:
    """
    Perform a complete IDENTITY check for a hostname:
    1. Does the URL claim or suggest a known brand?
    2. Does the hostname match the official domain for that brand?
    3. Is this a lookalike / typosquat domain?
    """
    claimed = find_claimed_brand(hostname + url_path)
    if not claimed:
        return {
            "has_brand_claim": False,
            "brand_key": None,
            "brand_name": None,
            "is_official": False,
            "is_lookalike": False,
        }

    brand_key, brand_info = claimed
    official = is_official_domain(hostname, brand_key)

    # If it claims a brand but is NOT the official domain, it's a lookalike domain!
    is_lookalike = not official

    return {
        "has_brand_claim": True,
        "brand_key": brand_key,
        "brand_name": brand_info["name"],
        "is_official": official,
        "is_lookalike": is_lookalike,
    }
