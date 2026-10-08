"""Deterministic and Explainable Risk Engine.

Reasoning-First Scoring Philosophy:
- Sensitive paths (/login, /verify, /kyc) on verified official domains are routine and neutral.
- Threats require evaluating IDENTITY (domain vs claimed brand), BEHAVIOR (expected context),
  and REQUEST (illegitimate asks like OTP, PIN, gift cards, secrecy).
- Replaces uncalibrated confidence floats with structured observation strengths and verdicts.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple, Optional
from detection.url.detector import Finding


@dataclass
class RiskAssessment:
    score: int
    classification: str  # "Safe", "Suspicious", "High Risk"
    summary: str
    explanation: str
    signals: List[Dict[str, Any]]
    findings: List[Finding] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)


class RiskEngine:
    """Deterministic scoring engine combining contextual heuristics and reasoning-first AI."""

    @staticmethod
    def calculate_risk(
        input_type: str,
        target: str,
        detector_signals: Dict[str, Any],
        laya_signals: Dict[str, Any],
        qwen_signals: Dict[str, Any],
        external_intel_signals: Dict[str, Any],
        all_findings: List[Finding],
        qwen_summary: str = "",
        qwen_reasoning: str = "",
        qwen_verdict: str = "",
        qwen_legitimate_explanations: Optional[List[str]] = None,
        qwen_what_would_change_my_mind: str = "",
        meta: Optional[Dict[str, Any]] = None,
    ) -> RiskAssessment:
        """
        Evaluate all collected evidence and calculate the final risk score.
        Completely isolated from I/O.
        """
        # Deduplicate and sort findings by severity (high -> medium -> low) early
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        unique_findings: List[Finding] = []
        seen_titles = set()
        for f in all_findings:
            if f.title not in seen_titles:
                seen_titles.add(f.title)
                unique_findings.append(f)
        unique_findings.sort(key=lambda x: severity_order.get(x.severity, 4))

        # Assign explicit points to findings to make the arithmetic honest and verifiable
        for f in unique_findings:
            if not getattr(f, "weight", 0):
                if getattr(f, "source", "") in ("ai", "qwen", "laya"):
                    f.weight = 45 if f.severity in ("high", "critical") else (20 if f.severity == "medium" else 5)
                elif getattr(f, "source", "") == "external":
                    f.weight = 40
                else:
                    f.weight = 35 if f.severity in ("high", "critical") else (20 if f.severity == "medium" else 5)

        raw_sum = sum(f.weight for f in unique_findings)
        
        # Calculate base final_score from raw_sum, with baseline minimums
        if raw_sum == 0:
            final_score = 10
        else:
            final_score = min(98, max(12, raw_sum))

        is_official = detector_signals.get("is_official_domain", False)
        is_lookalike = detector_signals.get("is_lookalike_domain", False)
        has_sensitive_path = detector_signals.get("has_sensitive_path", False)
        verdict = qwen_verdict or qwen_signals.get("qwen_verdict", "")
        laya_phishing = laya_signals.get("laya_phishing_probability", 0.0)
        external_points = 40 if (external_intel_signals.get("virustotal_malicious", 0) > 0 or external_intel_signals.get("urlscan_malicious")) else 0

        # --- 6. Calibrated Verdict-Driven Rules & Severity Floors ---
        # Critical malicious infrastructure overrides
        is_critical_infra = (
            detector_signals.get("is_ssrf_risk")
            or detector_signals.get("dangerous_file_extension")
            or external_points >= 40
        )

        high_count = sum(1 for f in unique_findings if f.severity in ("high", "critical"))
        medium_count = sum(1 for f in unique_findings if f.severity == "medium")

        # Apply floors
        if high_count >= 2:
            final_score = max(final_score, 81)
        elif high_count == 1:
            final_score = max(final_score, 61)
        
        if medium_count >= 1:
            final_score = max(final_score, 41)

        if is_critical_infra:
            final_score = max(final_score, 88)
        elif is_official and not is_critical_infra:
            final_score = min(final_score, 12)
        elif verdict == "likely_phishing":
            final_score = max(final_score, 88)
        elif verdict == "likely_legitimate" and not is_lookalike:
            final_score = min(final_score, 18)
        elif verdict == "suspicious":
            final_score = min(74, max(50, final_score))
        elif is_lookalike and has_sensitive_path:
            final_score = max(final_score, 85)
        elif is_lookalike:
            final_score = max(final_score, 75)
        elif laya_phishing >= 0.88:
            final_score = max(final_score, 80)

        # Classification mapping
        if final_score >= 81:
            classification = "Critical"
        elif final_score >= 61:
            classification = "High"
        elif final_score >= 41:
            classification = "Medium"
        elif final_score >= 21:
            classification = "Low"
        else:
            classification = "Safe"

        # Log the arithmetic
        import logging
        logger = logging.getLogger(__name__)
        logger.info("[risk_engine] signals=%d sum=%d multiplier=1.0 cap=%d final=%d tier=%s", len(unique_findings), raw_sum, raw_sum, final_score, classification)

        if meta is None:
            meta = {}
        meta["raw_sum"] = raw_sum


        # Format visual signal counts for frontend (no decorative percentages)
        det_count = sum(1 for f in unique_findings if getattr(f, "source", "deterministic") == "deterministic")
        ai_count = sum(1 for f in unique_findings if getattr(f, "source", "") in ("ai", "qwen", "laya"))
        ext_count = sum(1 for f in unique_findings if getattr(f, "source", "") == "external")

        signals_payload = [
            {"name": "Deterministic Rules Triggered", "value": det_count},
            {"name": "AI Reasoning Flags", "value": ai_count},
            {"name": "External Threat Intel Hits", "value": ext_count},
            {"name": "Total Correlated Signals", "value": len(unique_findings)},
        ]

        # Generate reasoning-first summary and explanation
        summary, explanation = RiskEngine._build_narratives(
            input_type=input_type,
            classification=classification,
            score=final_score,
            findings=unique_findings,
            qwen_summary=qwen_summary,
            qwen_reasoning=qwen_reasoning,
            qwen_verdict=verdict,
            qwen_legitimate_explanations=qwen_legitimate_explanations or [],
            qwen_what_would_change_my_mind=qwen_what_would_change_my_mind,
        )

        return RiskAssessment(
            score=final_score,
            classification=classification,
            summary=summary,
            explanation=explanation,
            signals=signals_payload,
            findings=unique_findings,
            meta=meta or {},
        )

    @staticmethod
    def _build_narratives(
        input_type: str,
        classification: str,
        score: int,
        findings: List[Finding],
        qwen_summary: str = "",
        qwen_reasoning: str = "",
        qwen_verdict: str = "",
        qwen_legitimate_explanations: Optional[List[str]] = None,
        qwen_what_would_change_my_mind: str = "",
    ) -> Tuple[str, str]:
        high_findings = [f.title for f in findings if f.severity == "high"]
        med_findings = [f.title for f in findings if f.severity == "medium"]

        # Base summary
        if classification in ("Critical", "High", "High Risk"):
            if qwen_summary:
                summary = f"Critical threat identified: {qwen_summary}"
            else:
                summary = f"High-risk security threats detected in this {input_type}. Primary indicators: {', '.join((high_findings + med_findings)[:2])}."
        elif classification in ("Medium", "Suspicious"):
            if qwen_summary:
                summary = f"Suspicious activity: {qwen_summary}"
            else:
                summary = f"Anomalous patterns warranting caution in this {input_type}. Notable indicators: {', '.join((high_findings + med_findings)[:2]) or 'Contextual inconsistency'}."
        elif classification == "Low":
            if qwen_summary:
                summary = f"Low risk: {qwen_summary}"
            else:
                summary = f"Minor indicators noted in this {input_type}, but overall posture remains low risk."
        else:
            if qwen_summary:
                summary = qwen_summary
            else:
                summary = f"No major malicious indicators detected for this {input_type}. Verified as likely legitimate."

        # Reasoning-first detailed explanation
        parts = []
        if qwen_reasoning:
            parts.append(f"Analysis Reasoning: {qwen_reasoning}")

        if qwen_what_would_change_my_mind:
            parts.append(f"Calibration Criteria: {qwen_what_would_change_my_mind}")

        if qwen_legitimate_explanations:
            valid_expls = [e for e in qwen_legitimate_explanations if e and "none found" not in e.lower()]
            if valid_expls:
                parts.append(f"Benign Alternative: {'; '.join(valid_expls[:2])}")

        if not parts:
            if classification in ("Critical", "High", "High Risk"):
                parts.append("Multi-engine inspection confirmed deceptive patterns or malicious mechanisms. Do NOT input credentials or interact with this resource.")
            elif classification in ("Medium", "Suspicious"):
                parts.append("Elevated risk signals detected. While not definitively hostile, caution is advised before proceeding.")
            elif classification == "Low":
                parts.append("Minor informational flags observed without active compromise indicators.")
            else:
                parts.append("Identity, behavior, and request criteria evaluated as clean. Standard security vigilance is recommended.")

        explanation = " ".join(parts)
        return summary, explanation
