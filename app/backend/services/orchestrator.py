"""CYBERGUARD Scan Orchestration Service.

Coordinates:
Input Validation → Deterministic Detection → Laya (URL System 1) → Qwen (Semantic System 2)
→ Optional Threat Intel → Risk Engine → Database Persistence.
"""
import asyncio
import logging
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.backend.models.scan import Scan, ScanFinding
from detection.url.detector import analyze_url, Finding
from detection.email.parser import parse_email, extract_urls_from_text
from detection.email.heuristics import analyze_email_heuristics
from app.backend.services.ai.laya_adapter import LayaAdapter
from app.backend.services.ai.qwen_adapter import QwenAdapter, build_deterministic_report
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
            logger.info("[orchestrator_start] Starting scan pipeline for %s (type: %s)", scan.id, input_type)

            if input_type == "url":
                assessment = await self._analyze_url_pipeline(str(raw_data))
            elif input_type == "email":
                assessment = await self._analyze_email_pipeline(raw_data)
            elif input_type == "logs":
                assessment = await self._analyze_logs_pipeline(str(raw_data))
            else:  # content / text
                assessment = await self._analyze_content_pipeline(str(raw_data))

            # Update scan with risk results
            scan.risk_score = assessment.score
            scan.classification = assessment.classification
            scan.summary = assessment.summary
            scan.explanation = assessment.explanation
            scan.signals = assessment.signals

            # Extract recommended actions from findings or response rules
            rec_actions: List[str] = []
            for f in assessment.findings:
                for act in getattr(f, "recommended_actions", []):
                    if act not in rec_actions:
                        rec_actions.append(act)
            scan.recommended_actions = rec_actions

            # Instant deterministic 7-section report baseline
            meta = getattr(assessment, "meta", {})
            scan.report_text = build_deterministic_report(
                input_type=scan.input_type,
                target=scan.target,
                risk_score=scan.risk_score or 0,
                classification=scan.classification or "Safe",
                findings=assessment.findings,
                providers_used=meta.get("providers_used", []),
                providers_not_used=meta.get("providers_not_used", []),
            )
            scan.report_generated_by = "template"
            scan.status = "completed"

            # Persist findings with weights and evidence
            db.query(ScanFinding).filter(ScanFinding.scan_id == scan.id).delete()
            for finding in assessment.findings:
                db_finding = ScanFinding(
                    scan_id=scan.id,
                    severity=finding.severity,
                    title=finding.title,
                    description=finding.description,
                    category=finding.category,
                    signal_type=finding.signal_type or finding.category,
                    weight=getattr(finding, "weight", 0),
                    evidence=getattr(finding, "evidence", None),
                    source=getattr(finding, "source", "deterministic"),
                    recommended_actions=getattr(finding, "recommended_actions", []),
                )
                db.add(db_finding)

            db.commit()
            db.refresh(scan)
            logger.info("[orchestrator_complete] Scan %s completed with score %s (%s) [Initial report: %s]", scan.id, scan.risk_score, scan.classification, scan.report_generated_by)

            # Trigger narrative report upgrade asynchronously in the background
            asyncio.create_task(
                self._background_generate_report(
                    scan_id=scan.id,
                    input_type=scan.input_type,
                    target=scan.target,
                    risk_score=scan.risk_score or 0,
                    classification=scan.classification or "Safe",
                    findings=assessment.findings,
                    meta=meta,
                )
            )

            return scan

        except Exception as exc:
            logger.error("[orchestrator_error] Scan %s failed during execution: %s", scan_id, exc, exc_info=True)
            scan.status = "failed"
            scan.error_message = str(exc)
            scan.retries += 1
            db.commit()
            db.refresh(scan)
            return scan

    async def _background_generate_report(
        self,
        scan_id: str,
        input_type: str,
        target: str,
        risk_score: int,
        classification: str,
        findings: List[Finding],
        meta: Dict[str, Any],
    ) -> None:
        """Asynchronously upgrades the scan report with Qwen's plain-English narrative without blocking scan finalization."""
        try:
            report_res = await self.qwen.generate_narrative_report(
                input_type=input_type,
                target=target,
                risk_score=risk_score,
                classification=classification,
                findings=findings,
                detector_signals=meta.get("detector_signals", {}),
                laya_signals=meta.get("laya_signals", {}),
                qwen_signals=meta.get("qwen_signals", {}),
                providers_used=meta.get("providers_used", []),
                providers_not_used=meta.get("providers_not_used", []),
            )
            report_text = report_res.get("report_text")
            generated_by = report_res.get("generated_by", "template")

            from app.backend.core.database import SessionLocal
            with SessionLocal() as db:
                db_scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if db_scan and report_text:
                    db_scan.report_text = report_text
                    db_scan.report_generated_by = generated_by
                    db.commit()
                    logger.info("[orchestrator_narrative] Scan %s narrative report upgraded [generated_by: %s]", scan_id, generated_by)
        except Exception as exc:
            logger.warning("[orchestrator_narrative_error] Background narrative report generation for scan %s failed: %s", scan_id, exc)

    async def _analyze_url_pipeline(self, raw_url: str):
        """Pipeline for standalone URL analysis (Heuristics → Laya → Qwen → Intel → Risk Engine)."""
        all_findings: List[Finding] = []

        # 1. Deterministic URL Analysis
        det_result = analyze_url(raw_url)
        all_findings.extend(det_result.findings)

        # 2. Laya Neural Decision (URL only, CPU System 1)
        laya_res = self.laya.analyze_url(det_result.normalized_url or raw_url)
        all_findings.extend(laya_res.get("findings", []))

        # 3. Qwen Deep Semantic Analysis (GPU System 2)
        qwen_res = await self.qwen.analyze_url(
            det_result.normalized_url or raw_url,
            deterministic_signals=det_result.signals,
            laya_signals=laya_res.get("signals", {}),
        )
        all_findings.extend(qwen_res.get("findings", []))

        # 4. Optional External Threat Intel
        intel_res = await self.threat_intel.query_url_intel(det_result.normalized_url or raw_url)
        all_findings.extend(intel_res.get("findings", []))

        # Providers accounting for honest reporting
        providers_used = ["Deterministic URL Heuristics Detector"]
        providers_not_used = []

        if laya_res.get("available"):
            providers_used.append("Laya Neural Decision Engine (CPU ModernBERT)")
        else:
            providers_not_used.append("Laya Neural Decision Engine (unavailable)")

        if qwen_res.get("available"):
            providers_used.append("Qwen Semantic Threat Reasoner (GPU Ollama)")
        else:
            providers_not_used.append("Qwen Semantic Threat Reasoner (unavailable)")

        if intel_res.get("enabled") and intel_res.get("providers_queried"):
            providers_used.extend(intel_res.get("providers_queried"))
        else:
            providers_not_used.append("External Threat Intel (VirusTotal / URLScan: disabled in local mode)")
        providers_not_used.append("WHOIS Domain Registration Records (not configured)")

        meta = {
            "detector_signals": det_result.signals,
            "laya_signals": laya_res.get("signals", {}),
            "qwen_signals": qwen_res.get("signals", {}),
            "providers_used": providers_used,
            "providers_not_used": providers_not_used,
        }

        # 5. Pure Risk Engine Scoring
        return RiskEngine.calculate_risk(
            input_type="URL",
            target=det_result.normalized_url or raw_url,
            detector_signals=det_result.signals,
            laya_signals=laya_res.get("signals", {}),
            qwen_signals=qwen_res.get("signals", {}),
            external_intel_signals=intel_res.get("signals", {}),
            all_findings=all_findings,
            qwen_summary=qwen_res.get("summary", ""),
            qwen_reasoning=qwen_res.get("reasoning", ""),
            qwen_verdict=qwen_res.get("verdict", ""),
            qwen_legitimate_explanations=qwen_res.get("legitimate_explanations", []),
            qwen_what_would_change_my_mind=qwen_res.get("what_would_change_my_mind", ""),
            meta=meta,
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

        # Providers accounting for honest reporting
        providers_used = ["Email Format & Header Parser", "Deterministic Email Heuristics Engine"]
        providers_not_used = []
        if top_urls:
            providers_used.append("Laya Neural URL Engine (CPU ModernBERT)")
        if qwen_res.get("available"):
            providers_used.append("Qwen Semantic Content Reasoner (GPU Ollama)")
        else:
            providers_not_used.append("Qwen Semantic Content Reasoner (unavailable)")
        providers_not_used.append("External Threat Intel (VirusTotal / URLScan: disabled in local mode)")
        providers_not_used.append("Live DNS MX/SPF/DKIM Records (not configured)")

        meta = {
            "detector_signals": email_detector_signals,
            "laya_signals": laya_combined_signals,
            "qwen_signals": qwen_res.get("signals", {}),
            "providers_used": providers_used,
            "providers_not_used": providers_not_used,
        }

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
            qwen_summary=qwen_res.get("summary", ""),
            qwen_reasoning=qwen_res.get("reasoning", ""),
            qwen_verdict=qwen_res.get("verdict", ""),
            qwen_legitimate_explanations=qwen_res.get("legitimate_explanations", []),
            qwen_what_would_change_my_mind=qwen_res.get("what_would_change_my_mind", ""),
            meta=meta,
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

        # Providers accounting for honest reporting
        providers_used = ["Deterministic Content & Keyword Detector"]
        providers_not_used = []
        if extracted_urls:
            providers_used.append("Laya Neural URL Engine (CPU ModernBERT)")
        if qwen_res.get("available"):
            providers_used.append("Qwen Semantic Content Reasoner (GPU Ollama)")
        else:
            providers_not_used.append("Qwen Semantic Content Reasoner (unavailable)")
        providers_not_used.append("External Threat Intel (not applicable to raw text)")

        meta = {
            "detector_signals": signals,
            "laya_signals": laya_combined_signals,
            "qwen_signals": qwen_res.get("signals", {}),
            "providers_used": providers_used,
            "providers_not_used": providers_not_used,
        }

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
            qwen_summary=qwen_res.get("summary", ""),
            qwen_reasoning=qwen_res.get("reasoning", ""),
            qwen_verdict=qwen_res.get("verdict", ""),
            qwen_legitimate_explanations=qwen_res.get("legitimate_explanations", []),
            qwen_what_would_change_my_mind=qwen_res.get("what_would_change_my_mind", ""),
            meta=meta,
        )

    async def _analyze_logs_pipeline(self, raw_logs: str):
        """Pipeline for raw authentication & system log analysis."""
        from detection.logs.detector import analyze_logs

        det_result = analyze_logs(raw_logs)
        all_findings: List[Finding] = list(det_result.findings)

        providers_used = ["Deterministic Auth & Syslog Analyzer"]
        providers_not_used = [
            "Laya Neural Decision Engine (URL/Email only)",
            "External Threat Intel (VirusTotal/URLScan: not applicable to system logs)",
            "Qwen Deep Semantic Reasoner (GPU Ollama: bypassed for deterministic log stream)"
        ]

        meta = {
            "detector_signals": det_result.signals,
            "providers_used": providers_used,
            "providers_not_used": providers_not_used,
        }

        total_lines = det_result.signals.get("total_lines_analyzed", 0)
        target_display = f"Log Stream ({total_lines} lines)"

        return RiskEngine.calculate_risk(
            input_type="Logs",
            target=target_display,
            detector_signals=det_result.signals,
            laya_signals={},
            qwen_signals={},
            external_intel_signals={},
            all_findings=all_findings,
            meta=meta,
        )
