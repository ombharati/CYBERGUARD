"""Response Recommendation Layer.

Loads response_rules.json to map (classification + top signal type) into
prescriptive containment and remediation actions without hardcoding.
"""
import json
import logging
from pathlib import Path
from typing import List, Optional, Any, Dict

logger = logging.getLogger(__name__)

# Path to rules file
RULES_PATH = Path(__file__).resolve().parent.parent.parent.parent / "detection" / "rules" / "response_rules.json"

_CACHED_RULES: Optional[Dict[str, List[str]]] = None


def load_response_rules(rules_path: Optional[Path] = None) -> Dict[str, List[str]]:
    """Load response recommendation rules from JSON file."""
    global _CACHED_RULES
    path = rules_path or RULES_PATH
    try:
        if path.is_file():
            with open(path, "r", encoding="utf-8") as f:
                _CACHED_RULES = json.load(f)
                return _CACHED_RULES
        else:
            logger.warning("response_rules.json not found at %s. Falling back to defaults.", path)
    except Exception as exc:
        logger.error("Failed to load response_rules.json: %s", exc)

    return _CACHED_RULES or {}


def normalize_threat_category(input_type: str, classification: str) -> str:
    """Normalize input_type and classification to standard threat category prefix."""
    inp = (input_type or "").strip().lower()
    cls_clean = (classification or "").strip().lower().replace(" ", "_")

    if inp in ("url",) and cls_clean in ("high_risk", "critical", "suspicious", "high", "medium"):
        return "phishing_url"
    if inp in ("email",) and cls_clean in ("high_risk", "critical", "suspicious", "high", "medium"):
        return "phishing_email"
    if inp in ("identity", "headers") and cls_clean in ("high_risk", "critical", "suspicious", "high", "medium"):
        return "identity_spoof"
    if inp in ("logs",) and cls_clean in ("high_risk", "critical", "suspicious", "high", "medium"):
        return "log_anomaly"

    return cls_clean


def get_recommended_actions(
    classification: str,
    top_signal_type: Optional[str] = None,
    input_type: Optional[str] = None,
    existing_finding_actions: Optional[List[str]] = None,
    rules_path: Optional[Path] = None,
) -> List[str]:
    """
    Resolve list of recommended actions for a scan using response_rules.json.

    Supports candidate key formats:
    - classification + top signal type (e.g., 'phishing_url+lookalike_domain', 'log_anomaly+brute_force')
    - tier + signal type (e.g., 'high_risk+lookalike_domain')
    - fallback defaults (e.g., 'high_risk+default', 'safe+default')
    """
    rules = load_response_rules(rules_path)
    threat_category = normalize_threat_category(input_type or "", classification)
    tier_key = (classification or "safe").strip().lower().replace(" ", "_")
    signal_key = (top_signal_type or "").strip().lower().replace(" ", "_")

    candidate_keys = []
    if threat_category and signal_key:
        candidate_keys.append(f"{threat_category}+{signal_key}")
    if tier_key and signal_key:
        candidate_keys.append(f"{tier_key}+{signal_key}")
    if threat_category:
        candidate_keys.append(f"{threat_category}+default")
    if tier_key:
        candidate_keys.append(f"{tier_key}+default")

    resolved_actions: List[str] = []
    for candidate in candidate_keys:
        if candidate in rules:
            resolved_actions.extend(rules[candidate])
            break

    # Merge any finding-level actions
    if existing_finding_actions:
        for act in existing_finding_actions:
            if act not in resolved_actions:
                resolved_actions.append(act)

    # Safe fallback if nothing matched
    if not resolved_actions:
        resolved_actions = [
            "Log security event for baseline monitoring",
            "No immediate containment action required"
        ]

    # Deduplicate while preserving order
    deduped = []
    for item in resolved_actions:
        if item not in deduped:
            deduped.append(item)

    return deduped
