"""CYBERGUARD Scan Orchestration Service.

Coordinates:
Input Validation → Deterministic Detection → Laya (URL System 1) → Qwen (Semantic System 2)
→ Optional Threat Intel → Risk Engine → Database Persistence.
"""
import logging
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.backend.models.scan import Scan, ScanFinding
from detection.url.detector import analyze_url, Finding
from detection.email.parser import parse_email, extract_urls_from_text
from detection.email.heuristics import analyze_email_heuristics
from app.backend.services.ai.laya_adapter import LayaAdapter
from app.backend.services.ai.qwen_adapter import QwenAdapter
from app.backend.services.external_intel import ExternalThreatIntelAdapter
from app.backend.services.risk_engine import RiskEngine

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Orchestrates end-to-end multi-engine cybersecurity analysis."""

    def __init__(
        self,
        laya_adapter: Optional[LayaAdapter] = None,
        qwen_adapter: Optional[QwenAdapter] = None,
        threat_intel_adapter: Optional[ExternalThreatIntelAdapter] = None,
    ):
        self.laya = laya_adapter or LayaAdapter()
        self.qwen = qwen_adapter or QwenAdapter()
        self.threat_intel = threat_intel_adapter or ExternalThreatIntelAdapter()

    async def execute_scan(self, db: Session, scan_id: str) -> Scan:
        """Execute a queued scan by ID and record all findings and risk results."""
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError(f"Scan ID {scan_id} not found in database.")

        scan.status = "processing"
        db.commit()

        try:
            input_type = scan.input_type.lower()
            raw_data = scan.raw_input

            if input_type == "url":
                assessment = await self._analyze_url_pipeline(str(raw_data))
            elif input_type == "email":
                assessment = await self._analyze_email_pipeline(raw_data)
            else:  # content / text
                assessment = await self._analyze_content_pipeline(str(raw_data))

            # Update scan with risk results
            scan.risk_score = assessment.score
            scan.classification = assessment.classification
            scan.summary = assessment.summary
            scan.explanation = assessment.explanation
            scan.signals = assessment.signals
            scan.status = "completed"

            # Persist findings
            # Clear any previous findings (e.g. from retries)
            db.query(ScanFinding).filter(ScanFinding.scan_id == scan.id).delete()
            for finding in assessment.findings:
                db_finding = ScanFinding(
                    scan_id=scan.id,
                    severity=finding.severity,
                    title=finding.title,
                    description=finding.description,
                    category=finding.category,
                )
                db.add(db_finding)

            db.commit()
            db.refresh(scan)
            logger.info("Scan %s completed with score %s (%s)", scan.id, scan.risk_score, scan.classification)
            return scan

        except Exception as exc:
            logger.error("Scan %s failed during execution: %s", scan_id, exc, exc_info=True)
            scan.status = "failed"
            scan.error_message = str(exc)
            scan.retries += 1
            db.commit()
            db.refresh(scan)
            return scan

    async def _analyze_url_pipeline(self, raw_url: str):
        """Pipeline for standalone URL analysis."""
        all_findings: List[Finding] = []

        # 1. Deterministic URL Analysis
        det_result = analyze_url(raw_url)
        all_findings.extend(det_result.findings)

        # 2. Laya Neural Decision (URL only, CPU)
        laya_res = self.laya.analyze_url(det_result.normalized_url or raw_url)
        all_findings.extend(laya_res.get("findings", []))

        # 3. Optional External Threat Intel
        intel_res = await self.threat_intel.query_url_intel(det_result.normalized_url or raw_url)
        all_findings.extend(intel_res.get("findings", []))

        # 4. Optional Qwen context check (if URL has suspicious paths or parameters)
        qwen_signals: Dict[str, Any] = {}
        if det_result.signals.get("matched_keywords") or laya_res.get("signals", {}).get("laya_phishing_probability", 0) > 0.4:
            qwen_res = await self.qwen.analyze_content(
                f"Analyze URL: {raw_url}. Host: {det_result.signals.get('hostname')}",
                context_hints=det_result.signals
            )
            qwen_signals = qwen_res.get("signals", {})
            all_findings.extend(qwen_res.get("findings", []))

        # 5. Risk Engine
        return RiskEngine.calculate_risk(
            input_type="URL",
            target=det_result.normalized_url or raw_url,
            detector_signals=det_result.signals,
            laya_signals=laya_res.get("signals", {}),
            qwen_signals=qwen_signals,
            external_intel_signals=intel_res.get("signals", {}),
            all_findings=all_findings,
        )

    async def _analyze_email_pipeline(self, raw_email_input: Any):
        """Pipeline for email analysis (Heuristics → URLs/Laya → Qwen → Risk Engine)."""
        all_findings: List[Finding] = []

        # 1. Parse Email
        parsed = parse_email(raw_email_input)
        if not parsed.is_valid:
            all_findings.append(Finding(
                severity="low",
                title="Malformed Email Format",
                description=parsed.error_message or "Email content could not be cleanly parsed.",
                category="parser"
            ))

        # 2. Deterministic Email Heuristics
        heuristics = analyze_email_heuristics(parsed)
        all_findings.extend(heuristics["findings"])
        email_detector_signals = heuristics["signals"]

        # 3. URL Extraction & Laya URL Analysis
        # Laya receives compact URLs only (never entire email body!)
        laya_combined_signals: Dict[str, Any] = {}
        top_urls = parsed.extracted_urls[:3]  # Resource conscious: inspect top extracted URLs
        for url in top_urls:
            url_det = analyze_url(url)
            all_findings.extend(url_det.findings)

            # Laya URL-only scan
            laya_res = self.laya.analyze_url(url)
            all_findings.extend(laya_res.get("findings", []))
            for k, v in laya_res.get("signals", {}).items():
                laya_combined_signals[k] = max(laya_combined_signals.get(k, 0), v)

        # 4. Qwen Semantic Analysis
        # Qwen receives relevant email content and structured URL/Laya indicators
        context_hints = {
            "sender": parsed.sender,
            "sender_name": parsed.sender_name,
            "subject": parsed.subject,
            "heuristic_signals": email_detector_signals,
            "url_signals": laya_combined_signals,
        }
        content_for_qwen = f"From: {parsed.sender}\nSubject: {parsed.subject}\n\n{parsed.plain_body}"
        qwen_res = await self.qwen.analyze_content(content_for_qwen, context_hints=context_hints)
        all_findings.extend(qwen_res.get("findings", []))

        # 5. Risk Engine
        target_display = f"{parsed.subject or 'Email'} ({parsed.sender or 'Unknown'})"
        return RiskEngine.calculate_risk(
            input_type="Email",
            target=target_display,
            detector_signals=email_detector_signals,
            laya_signals=laya_combined_signals,
            qwen_signals=qwen_res.get("signals", {}),
            external_intel_signals={},
            all_findings=all_findings,
        )

    async def _analyze_content_pipeline(self, raw_text: str):
        """Pipeline for raw text / snippet content analysis."""
        all_findings: List[Finding] = []

        # 1. Check for any embedded URLs
        extracted_urls = extract_urls_from_text(raw_text)[:3]
        laya_combined_signals: Dict[str, Any] = {}
        for url in extracted_urls:
            url_det = analyze_url(url)
            all_findings.extend(url_det.findings)
            laya_res = self.laya.analyze_url(url)
            all_findings.extend(laya_res.get("findings", []))
            for k, v in laya_res.get("signals", {}).items():
                laya_combined_signals[k] = max(laya_combined_signals.get(k, 0), v)

        # 2. Qwen Semantic Analysis
        qwen_res = await self.qwen.analyze_content(raw_text, context_hints={"urls": extracted_urls})
        all_findings.extend(qwen_res.get("findings", []))

        # 3. Simple text indicators
        lower = raw_text.lower()
        signals = {
            "has_urls": bool(extracted_urls),
            "content_length": len(raw_text),
            "urgent_keywords": any(k in lower for k in ("urgent", "immediately", "account suspended")),
            "credential_keywords": any(k in lower for k in ("password", "credential", "verify login")),
        }
        if signals["urgent_keywords"]:
            all_findings.append(Finding(
                severity="low",
                title="Urgency Indicators",
                description="The text content communicates pressure or tight deadlines.",
                category="content"
            ))
        if signals["credential_keywords"]:
            all_findings.append(Finding(
                severity="medium",
                title="Credential References",
                description="The text mentions authentication credentials, account passwords, or login access.",
                category="content"
            ))

        # 4. Risk Engine
        target_display = (raw_text.strip()[:60] + "...") if len(raw_text) > 60 else raw_text.strip()
        return RiskEngine.calculate_risk(
            input_type="Content",
            target=target_display,
            detector_signals=signals,
            laya_signals=laya_combined_signals,
            qwen_signals=qwen_res.get("signals", {}),
            external_intel_signals={},
            all_findings=all_findings,
        )
