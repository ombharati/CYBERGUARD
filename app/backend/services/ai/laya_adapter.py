"""Laya AI Adapter for compact URL analysis.

Laya is an RL-calibrated System 1 decision engine (ModernBERT-large backbone).
Architectural constraints:
- URL analysis only.
- Compact URL inputs only (never entire emails).
- Produces structured signals, never determines the final risk score.
- Runs strictly on CPU to protect RTX 3050 VRAM for Qwen.
- Singleton model instance: prevents duplicate model allocations in production.
- Allows test-level dependency injection for fast mocking.
- Graceful degradation if unavailable.
"""
import sys
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path
from app.backend.core.config import settings
from detection.url.detector import Finding

logger = logging.getLogger(__name__)

# Module-level singleton instance for Laya Agent to prevent duplicate model loads
_shared_laya_agent = None
_laya_initialized = False
_laya_available = False
_laya_init_error = None


def _get_laya_url_questions() -> Dict[str, Any]:
    """Compact typed decision questions for Laya URL analysis."""
    return {
        "phishing_intent": {
            "type": "noul",
            "instructions": "Does `url` appear to be a phishing, scam, credential harvesting, or deceptive link?",
            "criteria": {"true": "phishing or deceptive", "false": "legitimate link"},
        },
        "brand_impersonation": {
            "type": "noul",
            "instructions": "Does `url` appear to impersonate, typosquat, or spoof an established brand, login portal, or institution?",
        },
        "suspicion_level": {
            "type": "score",
            "instructions": "How suspicious is `url`?",
            "criteria": [
                "ordinary benign website",
                "mildly unusual or obscure domain",
                "suspicious patterns or misleading name",
                "dangerous credential harvesting or malware portal",
            ],
        },
    }


class LayaAdapter:
    """Adapter for local Laya model inference on CPU."""

    def __init__(self, agent: Optional[Any] = None, available: Optional[bool] = None):
        self._custom_agent = agent
        self._custom_available = available

    def _ensure_laya_in_sys_path(self):
        """Add Laya's virtualenv site-packages to sys.path if not already present."""
        laya_path = settings.resolve_laya_path()
        if not laya_path:
            return

        candidate_site_packages = [
            laya_path / "lib64" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages",
            laya_path / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages",
            laya_path / "site-packages",
        ]
        for sp in candidate_site_packages:
            sp_str = str(sp)
            if sp.exists() and sp_str not in sys.path:
                sys.path.insert(0, sp_str)
                logger.info("Added Laya site-packages to sys.path: %s", sp_str)
                break

    def initialize(self) -> bool:
        """Attempt to load Laya on CPU as a singleton."""
        global _shared_laya_agent, _laya_initialized, _laya_available, _laya_init_error

        if self._custom_available is not None:
            return self._custom_available

        if _laya_initialized:
            return _laya_available

        _laya_initialized = True
        try:
            self._ensure_laya_in_sys_path()
            import os
            os.environ.setdefault("HF_HUB_OFFLINE", "1")
            os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
            from laya import Agent

            logger.info("Initializing singleton Laya Agent on device: %s", settings.LAYA_DEVICE)
            _shared_laya_agent = Agent(
                "convaiinnovations/laya",
                device=settings.LAYA_DEVICE,
            )
            _laya_available = True
            logger.info("Laya Agent initialized successfully (singleton cached in CPU RAM).")
            return True
        except Exception as exc:
            _laya_available = False
            _laya_init_error = str(exc)
            logger.warning("Laya Agent is unavailable: %s. Scans will proceed using deterministic heuristics.", exc)
            return False

    def is_available(self) -> bool:
        if self._custom_available is not None:
            return self._custom_available
        global _laya_initialized, _laya_available
        if not _laya_initialized:
            self.initialize()
        return _laya_available

    def analyze_url(self, compact_url: str) -> Dict[str, Any]:
        """
        Analyze a compact URL string with Laya.
        Returns validated structured signals and findings.
        """
        global _shared_laya_agent, _laya_init_error

        if not self.is_available():
            return {
                "available": False,
                "error": _laya_init_error or "Laya not available",
                "signals": {},
                "findings": [],
            }

        agent_instance = self._custom_agent or _shared_laya_agent
        if agent_instance is None:
            return {
                "available": False,
                "error": "Laya agent instance is None",
                "signals": {},
                "findings": [],
            }

        # Strict input limiting: URLs only, capped length
        clean_url = compact_url.strip()[:settings.MAX_URL_LENGTH]

        try:
            questions = _get_laya_url_questions()
            result = agent_instance.predict(
                {"url": clean_url},
                questions=questions,
            )
            answers = result.get("answers", {})

            # Extract calibrated probabilities and scores
            phishing_ans = answers.get("phishing_intent", {})
            phishing_score = float(phishing_ans.get("noul", 0.0))
            phishing_conf = float(phishing_ans.get("answer_confidence", 0.5))

            brand_ans = answers.get("brand_impersonation", {})
            brand_score = float(brand_ans.get("noul", 0.0))

            suspicion_ans = answers.get("suspicion_level", {})
            suspicion_level = float(suspicion_ans.get("score", 0.0))

            signals = {
                "laya_phishing_probability": round(phishing_score, 3),
                "laya_brand_impersonation": round(brand_score, 3),
                "laya_suspicion_score": round(suspicion_level, 2),
                "laya_confidence": round(phishing_conf, 3),
            }

            findings: List[Finding] = []

            if phishing_score >= 0.70:
                findings.append(Finding(
                    severity="high",
                    title="AI Detected High Phishing Probability (Laya)",
                    description=f"Laya neural classification evaluated this URL with a {phishing_score:.1%} phishing probability.",
                    category="laya_ai",
                ))
            elif phishing_score >= 0.45:
                findings.append(Finding(
                    severity="medium",
                    title="AI Suspicious Link Pattern (Laya)",
                    description=f"Laya evaluated this URL with elevated suspicion ({phishing_score:.1%} probability of deception).",
                    category="laya_ai",
                ))

            if brand_score >= 0.65:
                findings.append(Finding(
                    severity="medium",
                    title="Potential Brand Spoofing Detected by AI (Laya)",
                    description="Laya identified language and structural patterns characteristic of brand impersonation.",
                    category="laya_ai",
                ))

            return {
                "available": True,
                "signals": signals,
                "confidence": phishing_conf,
                "findings": findings,
            }

        except Exception as exc:
            logger.warning("Laya inference failed for URL %s: %s", clean_url, exc)
            return {
                "available": False,
                "error": f"Inference failure: {str(exc)}",
                "signals": {},
                "findings": [],
            }
