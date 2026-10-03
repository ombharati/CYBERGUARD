"""Deterministic and Explainable Risk Engine.

Architectural constraints:
- Deterministic, explainable, testable.
- Combines signals from detectors, Laya, Qwen, and optional external intelligence.
- Produces final 0–100 score and classification (Safe, Suspicious, High Risk).
- Must NOT make HTTP requests, call models, or access the database directly.
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


class RiskEngine:
    """Pure, deterministic scoring engine combining heterogeneous security signals."""

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
    ) -> RiskAssessment:
        """
        Evaluate all collected evidence and calculate the final risk score.
        Completely isolated from I/O.
        """
        heuristic_points = 0
        ai_points = 0
        external_points = 0

        # --- 1. Deterministic URL Signals ---
        if detector_signals.get("has_credentials"):
            heuristic_points += 30
        if detector_signals.get("dangerous_file_extension"):
            heuristic_points += 35
        if detector_signals.get("is_ip_address"):
            heuristic_points += 20
        if detector_signals.get("has_punycode"):
            heuristic_points += 20
        if detector_signals.get("subdomain_count", 0) >= 3:
            heuristic_points += 15
        if detector_signals.get("suspicious_tld"):
            heuristic_points += 15
        matched_kw_count = len(detector_signals.get("matched_keywords", []))
        if matched_kw_count >= 2:
            heuristic_points += 20
        elif matched_kw_count == 1:
            heuristic_points += 10
        if detector_signals.get("entropy", 0.0) > 4.2:
            heuristic_points += 15

        # SSRF flag
        if detector_signals.get("is_ssrf_risk"):
            heuristic_points += 45

        # --- 2. Deterministic Email Signals ---
        if detector_signals.get("free_webmail_impersonation"):
            heuristic_points += 35
        if detector_signals.get("reply_to_mismatch"):
            heuristic_points += 30
        if detector_signals.get("auth_failure"):
            heuristic_points += 25
        if detector_signals.get("credential_matches", 0) >= 1:
            heuristic_points += 25
        urgency_matches = detector_signals.get("urgency_matches", 0)
        if urgency_matches >= 2:
            heuristic_points += 20
        elif urgency_matches == 1:
            heuristic_points += 10

        # --- 3. Laya AI Signals (URL System 1 Decision Engine) ---
        laya_phishing = laya_signals.get("laya_phishing_probability", 0.0)
        if laya_phishing >= 0.75:
            ai_points += 35
        elif laya_phishing >= 0.45:
            ai_points += 20

        laya_brand = laya_signals.get("laya_brand_impersonation", 0.0)
        if laya_brand >= 0.65:
            ai_points += 20

        # --- 4. Qwen AI Signals (Semantic / Email / URL Deep Reasoning) ---
        if qwen_signals.get("qwen_is_phishing"):
            ai_points += 35
        if qwen_signals.get("qwen_credential_intent"):
            ai_points += 30
        if qwen_signals.get("qwen_brand_impersonation"):
            ai_points += 20
        if qwen_signals.get("qwen_social_engineering"):
            ai_points += 20
        qwen_urgency = qwen_signals.get("qwen_urgency", "none")
        if qwen_urgency == "high":
            ai_points += 15
        elif qwen_urgency == "medium":
            ai_points += 10
        qwen_suspicion = qwen_signals.get("qwen_suspicion_score", 0.0)
        if qwen_suspicion >= 0.70:
            ai_points += 20
        elif qwen_suspicion >= 0.40:
            ai_points += 10

        # --- 5. External Threat Intel Signals ---
        if external_intel_signals.get("virustotal_malicious", 0) > 0:
            external_points += 40
        if external_intel_signals.get("urlscan_malicious"):
            external_points += 40

        # --- Caps and Normalization ---
        # Cap heuristic contribution at 65, AI at 75 (allowing consensus to establish High Risk), external at 40
        capped_heuristics = min(heuristic_points, 65)
        capped_ai = min(ai_points, 75)
        capped_external = min(external_points, 40)

        raw_sum = capped_heuristics + capped_ai + capped_external

        # Base noise floor for analyzed inputs
        if raw_sum == 0:
            final_score = 10
        else:
            final_score = min(98, max(12, raw_sum))

        # Check for critical compound severity rules
        # 1. Multi-model AI consensus: Laya + Qwen in agreement on phishing/credential harvesting
        ai_consensus_phishing = (
            (laya_phishing >= 0.70 and (qwen_signals.get("qwen_is_phishing") or qwen_signals.get("qwen_credential_intent") or qwen_suspicion >= 0.70))
            or (qwen_signals.get("qwen_credential_intent") and qwen_signals.get("qwen_social_engineering"))
        )

        # 2. AI + Deterministic compound triggers
        compound_heuristic_phishing = (
            (laya_phishing >= 0.75 and (laya_brand >= 0.65 or matched_kw_count >= 1 or detector_signals.get("suspicious_tld")))
            or (qwen_signals.get("qwen_credential_intent") and (matched_kw_count >= 1 or detector_signals.get("free_webmail_impersonation") or detector_signals.get("reply_to_mismatch")))
            or (qwen_signals.get("qwen_is_phishing") and (matched_kw_count >= 1 or laya_brand >= 0.65))
        )

        # 3. High standalone certainty
        standalone_high_certainty = (
            laya_phishing >= 0.88
            or qwen_suspicion >= 0.90
        )

        # Apply floors
        if ai_consensus_phishing:
            final_score = max(final_score, 88)
        elif compound_heuristic_phishing:
            final_score = max(final_score, 82)
        elif standalone_high_certainty:
            final_score = max(final_score, 78)

        # 4. Critical infrastructure overrides (SSRF, malicious downloads, external intel)
        is_critical_infra = (
            detector_signals.get("is_ssrf_risk")
            or detector_signals.get("dangerous_file_extension")
            or external_points >= 40
        )
        if is_critical_infra:
            final_score = max(final_score, 85)

        # 5. Benign safeguard: if zero heuristics triggered and all AIs report low suspicion, keep Safe
        is_benign = (
            heuristic_points == 0
            and laya_phishing < 0.25
            and qwen_suspicion < 0.25
            and not qwen_signals.get("qwen_is_phishing")
            and not qwen_signals.get("qwen_credential_intent")
            and not qwen_signals.get("qwen_social_engineering")
        )
        if is_benign:
            final_score = min(final_score, 15)

        # Classification mapping (matching frontend thresholds)
        if final_score >= 75:
            classification = "High Risk"
        elif final_score >= 45:
            classification = "Suspicious"
        else:
            classification = "Safe"

        # Deduplicate and sort findings by severity (high -> medium -> low)
        severity_order = {"high": 0, "medium": 1, "low": 2}
        unique_findings: List[Finding] = []
        seen_titles = set()
        for f in all_findings:
            if f.title not in seen_titles:
                seen_titles.add(f.title)
                unique_findings.append(f)
        unique_findings.sort(key=lambda x: severity_order.get(x.severity, 3))

        # Format visual signal bars for frontend
        pattern_value = min(100, max(final_score, int(capped_heuristics * 1.5)))
        content_value = min(100, max(final_score - 5, int(capped_ai * 1.2))) if capped_ai > 0 else max(8, final_score - 10)
        reputation_val = max(10, external_points * 2) if external_points > 0 else max(10, final_score - 20)

        signals_payload = [
            {"name": "Pattern analysis", "value": pattern_value},
            {"name": "Content indicators", "value": content_value},
            {"name": "Risk aggregation", "value": final_score},
            {"name": "Reputation signals", "value": reputation_val},
        ]

        # Generate human-readable summary and explanation
        summary, explanation = RiskEngine._build_narratives(
            input_type, classification, final_score, unique_findings, qwen_summary, qwen_reasoning
        )

        return RiskAssessment(
            score=final_score,
            classification=classification,
            summary=summary,
            explanation=explanation,
            signals=signals_payload,
            findings=unique_findings,
        )

    @staticmethod
    def _build_narratives(
        input_type: str,
        classification: str,
        score: int,
        findings: List[Finding],
        qwen_summary: str = "",
        qwen_reasoning: str = "",
    ) -> Tuple[str, str]:
        high_findings = [f.title for f in findings if f.severity == "high"]
        med_findings = [f.title for f in findings if f.severity == "medium"]

        if classification == "High Risk":
            if qwen_summary:
                summary = f"Critical security threat: {qwen_summary}"
            else:
                summary = (
                    f"Critical security threats detected in this {input_type}. "
                    f"Primary indicators include: {', '.join((high_findings + med_findings)[:2])}."
                )

            if qwen_reasoning:
                explanation = f"{qwen_reasoning} Automated multi-engine inspection confirmed severe threat indicators. Do NOT input credentials or interact with this resource."
            else:
                explanation = (
                    "The automated multi-engine inspection identified verified deceptive patterns or malicious mechanisms. "
                    "Immediate defensive precautions are advised. Do not input credentials, execute downloads, or reply."
                )
        elif classification == "Suspicious":
            if qwen_summary:
                summary = f"Suspicious activity detected: {qwen_summary}"
            else:
                summary = (
                    f"The analyzed {input_type} exhibits anomalous patterns warranting caution. "
                    f"Notable warning signs: {', '.join((high_findings + med_findings)[:2]) or 'Elevated structural anomalies'}."
                )

            if qwen_reasoning:
                explanation = f"{qwen_reasoning} Multiple security indicators were triggered during heuristic and neural analysis."
            else:
                explanation = (
                    "Multiple security indicators were triggered during heuristic and neural analysis. "
                    "While not confirmed actively destructive, the input deviates from verified benign patterns."
                )
        else:
            summary = (
                f"No major malicious indicators were detected for this {input_type} in baseline analysis."
            )
            explanation = (
                "First-pass deterministic rules and local neural models found no overt indicators of phishing, "
                "deception, or active exploitation. Routine security vigilance is still advised."
            )

        return summary, explanation
