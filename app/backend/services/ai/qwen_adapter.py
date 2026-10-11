"""Qwen AI Adapter with Reasoning-First Threat Analysis (System 2 on GPU).

Core Architectural Philosophy:
- "The /login path exists on every real bank. It only matters if the domain isn't
  the real bank, or the user didn't expect this, or the request doesn't match
  what that service actually does."
- Replaces numeric confidence floats with calibrated step-by-step reasoning.
- Operates under three fundamental threat questions:
  1. IDENTITY: Does the sending/hosting domain match the claimed brand?
  2. BEHAVIOR: Is the action expected in this context?
  3. REQUEST: Is something being asked that a real service would never ask?
- Two or more problematic -> 'likely_phishing'
- One problematic and two clean -> 'suspicious'
- All three clean -> 'likely_legitimate'
"""
import asyncio
import json
import logging
import re
import time
from typing import Dict, Any, List, Optional, Literal
import httpx
from pydantic import BaseModel, Field
from app.backend.core.config import settings
from detection.url.detector import Finding

logger = logging.getLogger(__name__)

# Serialize GPU calls so concurrent scans or background reports do not starve Ollama
_gpu_lock = asyncio.Lock()


class QwenSignal(BaseModel):
    type: str
    severity: Literal["low", "medium", "high"]
    evidence: str

class QwenResponse(BaseModel):
    signals: List[QwenSignal] = Field(default_factory=list)
    confidence: float
    notes: str

def _validate_qwen_response(structured: QwenResponse, text_content: str) -> bool:
    if structured.confidence < 0.0 or structured.confidence > 1.0:
        logger.warning("[qwen_adapter] Invalid confidence value: %s", structured.confidence)
        return False
    if len(structured.signals) > 10:
        logger.warning("[qwen_adapter] Too many signals generated: %d", len(structured.signals))
        return False
    for sig in structured.signals:
        if sig.evidence not in text_content:
            logger.warning("[qwen_adapter] Hallucinated evidence rejected: '%s'", sig.evidence)
            return False
    return True

def _repair_json_structure(candidate: str) -> str:
    """Repair unterminated strings and unclosed braces/brackets in truncated JSON."""
    in_quote = False
    escape = False
    for ch in candidate:
        if escape:
            escape = False
        elif ch == "\\":
            escape = True
        elif ch == '"':
            in_quote = not in_quote

    repaired = candidate
    if in_quote:
        repaired += '"'

    open_brackets = []
    in_quote = False
    escape = False
    for ch in repaired:
        if escape:
            escape = False
        elif ch == "\\":
            escape = True
        elif ch == '"':
            in_quote = not in_quote
        elif not in_quote:
            if ch in "{[":
                open_brackets.append(ch)
            elif ch in "}]":
                if open_brackets:
                    last = open_brackets[-1]
                    if (last == "{" and ch == "}") or (last == "[" and ch == "]"):
                        open_brackets.pop()

    for br in reversed(open_brackets):
        if br == "{":
            repaired += "}"
        elif br == "[":
            repaired += "]"

    return repaired


def _safe_parse_qwen_json(raw: str) -> Dict[str, Any]:
    """Parse JSON output with fallback repair for truncated or markdown-wrapped responses."""
    text = raw.strip()
    if "```" in text:
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
        text = text.strip()

    try:
        return json.loads(text)
    except Exception:
        pass

    start = text.find("{")
    if start == -1:
        raise ValueError("No JSON object found in model response")
    candidate = text[start:]

    try:
        return json.loads(candidate)
    except Exception:
        pass

    repaired = _repair_json_structure(candidate)
    try:
        return json.loads(repaired)
    except Exception:
        pass

    # Basic regex extraction fallback for the new schema
    extracted: Dict[str, Any] = {"signals": [], "confidence": 0.0, "notes": ""}
    
    notes_match = re.search(r'"notes"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"', candidate)
    if notes_match:
        extracted["notes"] = notes_match.group(1)
        
    conf_match = re.search(r'"confidence"\s*:\s*([\d\.]+)', candidate)
    if conf_match:
        try:
            extracted["confidence"] = float(conf_match.group(1))
        except ValueError:
            pass

    # We do not attempt complex regex extraction of signals to avoid false positives.
    if extracted.get("notes") or extracted.get("confidence") > 0.0:
        return extracted

    raise ValueError(f"Could not parse or repair valid JSON: {text[:120]}")


SYSTEM_PROMPT = """You are a Senior Cybersecurity Threat Intelligence Analyst.

Output valid JSON only. No prose. No markdown. No code fences.
Only use information present in the input. Do not invent domains, IPs, file hashes, or behaviors that are not explicitly in the text.
If the input does not contain enough information to conclude, return an empty signals array and set confidence to 0.
Every signal must include an evidence field containing a literal substring copied from the input that supports it.

Output schema EXACTLY:
{
  "signals": [
    {"type": "string", "severity": "low|medium|high", "evidence": "string"}
  ],
  "confidence": 0.0,
  "notes": "string"
}
"""


class QwenAdapter:
    """Adapter for querying local Qwen model through Ollama with reasoning-first analysis."""

    def __init__(self):
        self.base_url = settings.OLLAMA_BASE_URL.rstrip("/")
        self.model = settings.OLLAMA_MODEL
        self.timeout = settings.OLLAMA_TIMEOUT_SECONDS

    async def is_available(self) -> bool:
        """Check if Ollama server is responding and has models."""
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                res = await client.get(f"{self.base_url}/api/tags")
                return res.status_code == 200
        except httpx.TimeoutException:
            logger.info("[qwen_ping] Ollama ping timed out after 2.0s")
            return False
        except Exception as exc:
            logger.info("[qwen_ping] Ollama ping failed: %s", exc)
            return False

    async def warmup(self) -> bool:
        """Pre-load Qwen weights into GPU VRAM and keep active for 24h to eliminate cold start."""
        if not await self.is_available():
            logger.info("[qwen_warmup] Skipping warmup; Ollama is currently unavailable.")
            return False
        try:
            payload = {
                "model": self.model,
                "prompt": "ping",
                "stream": False,
                "think": False,
                "keep_alive": "24h",
                "options": {"num_ctx": 2048, "num_predict": 1},
            }
            logger.info("[qwen_warmup] Warming up model '%s' in GPU VRAM (timeout=20.0s)", self.model)
            async with httpx.AsyncClient(timeout=20.0) as client:
                res = await client.post(f"{self.base_url}/api/generate", json=payload)
                if res.status_code == 200:
                    logger.info("[qwen_warmup] Model '%s' successfully warmed up in GPU VRAM (keep_alive: 24h).", self.model)
                    return True
        except httpx.TimeoutException:
            logger.warning("[qwen_warmup] Model warmup timed out after 20.0s")
        except Exception as exc:
            logger.warning("[qwen_warmup] Model warmup failed: %s", exc)
        return False

    async def analyze_url(
        self,
        url: str,
        deterministic_signals: Optional[Dict[str, Any]] = None,
        laya_signals: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Reason over URL structure, brand identity, and behavior context.
        """
        clean_url = url.strip()[:settings.MAX_URL_LENGTH]

        user_prompt = (
            f"Analyze the following URL under the IDENTITY, BEHAVIOR, and REQUEST rules:\n"
            f"TARGET URL: {clean_url}\n\n"
            f"DETERMINISTIC HEURISTIC TELEMETRY:\n{json.dumps(deterministic_signals or {}, default=str, indent=2)}\n\n"
            f"SYSTEM 1 LAYA NEURAL CLASSIFIER OUTPUT:\n{json.dumps(laya_signals or {}, default=str, indent=2)}\n\n"
            "Keep observations concise (maximum 3 key observations) and reasoning succinct to ensure complete output.\n"
            "Respond ONLY with a JSON object matching the exact schema."
        )

        return await self._query_qwen(prompt=user_prompt, tag="QWEN URL", target_label=clean_url)

    async def analyze_content(
        self,
        text_content: str,
        context_hints: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Reason over email or text content under identity, behavior, and request rules.
        """
        lines = text_content.splitlines()
        MAX_LINES = 50
        MAX_BYTES = 4096
        
        if len(lines) > MAX_LINES:
            logger.info("[qwen_adapter] Truncating input from %d lines to %d lines to prevent context overflow", len(lines), MAX_LINES)
            text_content = "\n".join(lines[:MAX_LINES]) + "\n...[TRUNCATED]"
            
        if len(text_content) > MAX_BYTES:
            logger.info("[qwen_adapter] Truncating input from %d chars to %d chars to prevent context overflow", len(text_content), MAX_BYTES)
            text_content = text_content[:MAX_BYTES] + "...[TRUNCATED]"
            
        truncated_text = text_content.strip()
        hints_str = ""
        if context_hints:
            hints_str = f"\nEXTRACTED CONTEXT & SIGNALS:\n{json.dumps(context_hints, default=str, indent=2)}\n"

        user_prompt = (
            f"Analyze the following email/text communication under the IDENTITY, BEHAVIOR, and REQUEST rules:\n"
            f"COMMUNICATION CONTENT:\n\"\"\"\n{truncated_text}\n\"\"\"\n"
            f"{hints_str}\n"
            "Keep observations concise (maximum 3 key observations) and reasoning succinct to ensure complete output.\n"
            "Respond ONLY with a JSON object matching the exact schema."
        )

        return await self._query_qwen(prompt=user_prompt, tag="QWEN CONTENT", target_label=truncated_text[:60])

    async def _query_qwen(self, prompt: str, tag: str, target_label: str) -> Dict[str, Any]:
        """Execute request against Ollama and validate reasoning-first structured output."""
        payload = {
            "model": self.model,
            "system": SYSTEM_PROMPT,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "think": False,
            "keep_alive": "24h",
            "options": {
                "temperature": 0.1,
                "num_ctx": 2048,
                "num_predict": 600,
            },
        }

        start_time = time.perf_counter()
        logger.info("[%s] Request sent to Ollama model='%s' for '%s'", tag, self.model, target_label)

        try:
            async with _gpu_lock:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.post(
                        f"{self.base_url}/api/generate",
                        json=payload,
                    )
            latency_ms = (time.perf_counter() - start_time) * 1000

            if response.status_code != 200:
                logger.warning("[%s] Ollama HTTP %s after %.2fms: %s", tag, response.status_code, latency_ms, response.text)
                return {
                    "available": False,
                    "error": f"Ollama HTTP {response.status_code}",
                    "signals": {},
                    "findings": [],
                }

            data = response.json()
            raw_response = data.get("response", "{}")
            logger.info("[%s] Response received in %.2fms: %s", tag, latency_ms, raw_response)

            try:
                parsed_json = _safe_parse_qwen_json(raw_response)
                structured = QwenResponse.model_validate(parsed_json)
            except Exception as parse_err:
                logger.warning("[%s] Malformed output: %s (raw: %s)", tag, parse_err, raw_response)
                return {
                    "available": True,
                    "provider_status": "qwen_invalid",
                    "error": f"Malformed model response: {parse_err}",
                    "signals": {},
                    "findings": [],
                }

            if not _validate_qwen_response(structured, prompt):
                return {
                    "available": True,
                    "provider_status": "qwen_invalid",
                    "error": "Validation failed: Hallucinated evidence or invalid confidence.",
                    "signals": {},
                    "findings": [],
                }

            # Confidence capping
            if structured.confidence > 0.85 and not any(s.severity == "high" for s in structured.signals):
                structured.confidence = 0.85

            findings: List[Finding] = []
            for sig in structured.signals:
                findings.append(Finding(
                    severity=sig.severity,
                    title=sig.type,
                    description=sig.evidence,
                    category="qwen_ai",
                ))

            # Simulate verdict for RiskEngine based on new confidence mapping
            if structured.confidence > 0.85 and any(s.severity == "high" for s in structured.signals):
                verdict = "likely_phishing"
            elif structured.confidence > 0.5:
                verdict = "suspicious"
            else:
                verdict = "likely_legitimate"

            signals = {
                "qwen_verdict": verdict,
                "qwen_is_phishing": verdict == "likely_phishing",
                "qwen_suspicious": verdict == "suspicious",
                "qwen_legitimate": verdict == "likely_legitimate",
                "qwen_confidence": structured.confidence,
                "qwen_signals_count": len(structured.signals),
            }

            return {
                "available": True,
                "signals": signals,
                "verdict": verdict,
                "reasoning": structured.notes,
                "legitimate_explanations": [],
                "what_would_change_my_mind": "",
                "observations": [],
                "findings": findings,
            }

        except httpx.TimeoutException:
            logger.warning("[%s] Ollama inference timed out after %ss", tag, self.timeout)
            return {
                "available": False,
                "error": "Model inference timeout",
                "signals": {},
                "findings": [],
            }
        except Exception as exc:
            logger.warning("[%s] Inference failed: %s", tag, exc)
            return {
                "available": False,
                "error": str(exc),
                "signals": {},
                "findings": [],
            }

    async def generate_narrative_report(
        self,
        input_type: str,
        target: str,
        risk_score: int,
        classification: str,
        findings: List[Finding],
        detector_signals: Optional[Dict[str, Any]] = None,
        laya_signals: Optional[Dict[str, Any]] = None,
        qwen_signals: Optional[Dict[str, Any]] = None,
        providers_used: Optional[List[str]] = None,
        providers_not_used: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Generate a one-page plain-English narrative report via Qwen or fallback template."""
        providers_used = providers_used or []
        providers_not_used = providers_not_used or []
        detector_signals = detector_signals or {}
        laya_signals = laya_signals or {}
        qwen_signals = qwen_signals or {}

        # Default deterministic template report (used as fallback)
        template_text = build_deterministic_report(
            input_type=input_type,
            target=target,
            risk_score=risk_score,
            classification=classification,
            findings=findings,
            providers_used=providers_used,
            providers_not_used=providers_not_used,
        )

        # Check if Ollama is accessible
        if not await self.is_available():
            logger.info("[qwen_report] Ollama unavailable. Using deterministic report template.")
            return {
                "report_text": template_text,
                "generated_by": "template",
            }

        # Build bounded JSON payload for Qwen
        summarized_findings = [
            {
                "severity": f.severity.upper(),
                "title": f.title,
                "description": f.description[:200],
            }
            for f in findings[:12]
        ]
        report_input = {
            "input_type": input_type,
            "target": target[:200],
            "risk_score": risk_score,
            "classification": classification,
            "findings": summarized_findings,
            "detector_signals": {k: v for k, v in detector_signals.items() if not str(k).startswith("_")},
            "laya_signals": {k: v for k, v in laya_signals.items() if not str(k).startswith("_")},
            "qwen_signals": {k: v for k, v in qwen_signals.items() if not str(k).startswith("_")},
            "providers_used": providers_used,
            "providers_not_used": providers_not_used,
        }

        payload = {
            "model": self.model,
            "system": REPORT_SYSTEM_PROMPT,
            "prompt": f"Write the 7-section security report for this scan:\n{json.dumps(report_input, indent=2)}",
            "stream": False,
            "think": False,
            "keep_alive": "24h",
            "options": {
                "temperature": 0.2,
                "num_ctx": 2048,
                "num_predict": 500,
            },
        }

        tag = "qwen_report"
        start_time = time.perf_counter()
        report_timeout = max(self.timeout, 75.0)
        try:
            logger.info("[%s] Requesting narrative report from Ollama for target '%s'", tag, target[:80])
            async with _gpu_lock:
                async with httpx.AsyncClient(timeout=report_timeout) as client:
                    resp = await client.post(f"{self.base_url}/api/generate", json=payload)
            
            latency_ms = (time.perf_counter() - start_time) * 1000
            if resp.status_code == 200:
                raw_response = resp.json().get("response", "")
                cleaned = clean_report_text(raw_response)
                words = cleaned.split()
                logger.info("[%s] Received response in %.2fms (%d words)", tag, latency_ms, len(words))
                if is_valid_report(cleaned):
                    return {
                        "report_text": cleaned,
                        "generated_by": "qwen",
                    }
                logger.warning("[%s] Report failed validation (%d words). Retrying once...", tag, len(words))

            # Retry once with explicit concise prompt
            retry_payload = {
                "model": self.model,
                "system": REPORT_SYSTEM_PROMPT,
                "prompt": (
                    f"Please write a concise 7-section plain text security report under 500 words for:\n"
                    f"{json.dumps(report_input)}"
                ),
                "stream": False,
                "think": False,
                "keep_alive": "24h",
                "options": {
                    "temperature": 0.1,
                    "num_ctx": 2048,
                    "num_predict": 500,
                },
            }
            async with _gpu_lock:
                async with httpx.AsyncClient(timeout=report_timeout) as client:
                    retry_resp = await client.post(f"{self.base_url}/api/generate", json=retry_payload)
            if retry_resp.status_code == 200:
                cleaned_retry = clean_report_text(retry_resp.json().get("response", ""))
                if is_valid_report(cleaned_retry):
                    logger.info("[%s] Retry succeeded (%d words)", tag, len(cleaned_retry.split()))
                    return {
                        "report_text": cleaned_retry,
                        "generated_by": "qwen",
                    }
                logger.warning("[%s] Retry rejected. Falling back to deterministic template.", tag)

        except httpx.TimeoutException as timeout_exc:
            logger.warning("[%s] Narrative report generation timed out after %ss: %s. Falling back to template.", tag, report_timeout, timeout_exc)
        except Exception as exc:
            logger.warning("[%s] Report generation exception: %s. Falling back to template.", tag, exc)

        return {
            "report_text": template_text,
            "generated_by": "template",
        }


# =====================================================================
# Narrative Report Prompts & Deterministic Fallback Logic
# =====================================================================

REPORT_SYSTEM_PROMPT = (
    "You are a Senior Cybersecurity Analyst writing a clear, one-page executive security report for an end user.\n"
    "Write in plain, factual, and calm English. Avoid alarmism, jargon, and marketing language.\n"
    "Do NOT use emoji.\n"
    "Do NOT use markdown headers (#) or markdown bold (**). Output plain text only.\n"
    "Do NOT output JSON or code fences. Output plain text report only.\n\n"
    "Your report must contain exactly the following six numbered section headings in this exact order:\n\n"
    "1. What was analyzed\n"
    "2. Verdict\n"
    "3. Key findings\n"
    "4. Why this verdict\n"
    "5. What was checked\n"
    "6. Recommendation\n\n"
    "Section rules:\n"
    "- 1. What was analyzed: State the input type and a short factual description of the target. Do not invent details or include secrets.\n"
    "- 2. Verdict: State the classification and score in exactly one line (e.g., 'Verdict: High Risk (Risk Score: 98/100)'). Do not repeat the score anywhere else in the report.\n"
    "- 3. Key findings: Group findings by severity (High, Medium, Low). Explain each key finding in 1-2 plain sentences. If no findings were detected, state that.\n"
    "- 4. Why this verdict: Short reasoning, referencing the strongest signals observed.\n"
    "- 5. What was checked: List the detectors and intelligence providers that actually ran.\n"
    "- 6. Recommendation: One or two calm sentences advising what the user should do.\n\n"
    "Keep the total length between 250 and 550 words. Plain text with section labels only."
)


def clean_report_text(raw_text: str) -> str:
    """Strip markdown code blocks, headers, bold/italics, and emojis from report text."""
    text = raw_text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    # Strip markdown bold and italics
    text = text.replace("**", "").replace("*", "")

    # Strip markdown header hashes at start of lines
    clean_lines = []
    for line in text.splitlines():
        clean_lines.append(re.sub(r"^#+\s*", "", line))
    text = "\n".join(clean_lines).strip()

    # Strip unicode emojis
    emoji_pattern = re.compile(
        "[\U00010000-\U0010ffff\u2600-\u26ff\u2700-\u27bf]",
        flags=re.UNICODE,
    )
    text = emoji_pattern.sub("", text)
    return text.strip()


def is_valid_report(text: str) -> bool:
    """Check if report has required sections and falls within bounded word count."""
    words = text.split()
    if len(words) < 20 or len(words) > 700:
        return False
    lower = text.lower()
    has_sec1 = "what was analyzed" in lower or "1. what" in lower
    has_sec2 = "verdict" in lower or "2. verdict" in lower
    has_sec7 = "recommendation" in lower or "7. recommendation" in lower
    return has_sec1 and has_sec2 and has_sec7


def build_deterministic_report(
    input_type: str,
    target: str,
    risk_score: int,
    classification: str,
    findings: List[Finding],
    providers_used: List[str],
    providers_not_used: List[str],
) -> str:
    """Generates a structured, deterministic one-page plain text report when AI is unavailable."""
    # 1. What was analyzed
    clean_target = target.strip()[:180]
    sec1 = (
        "1. What was analyzed\n"
        f"Input type: {input_type.upper()}\n"
        f"Target inspected: {clean_target}"
    )

    # 2. Verdict
    sec2 = f"2. Verdict\nVerdict: {classification} (Risk Score: {risk_score}/100)"

    # 3. Key findings
    high_f = [f for f in findings if f.severity.lower() == "high"]
    med_f = [f for f in findings if f.severity.lower() == "medium"]
    low_f = [f for f in findings if f.severity.lower() == "low"]

    finding_parts = []
    if high_f:
        finding_parts.append("High Severity:")
        for f in high_f[:4]:
            finding_parts.append(f"- {f.title}: {f.description}")
    if med_f:
        finding_parts.append("Medium Severity:")
        for f in med_f[:4]:
            finding_parts.append(f"- {f.title}: {f.description}")
    if low_f:
        finding_parts.append("Low Severity:")
        for f in low_f[:3]:
            finding_parts.append(f"- {f.title}: {f.description}")
    if not finding_parts:
        finding_parts.append("No suspicious indicators or anomalies detected during analysis.")
    sec3 = "3. Key findings\n" + "\n".join(finding_parts)

    # 4. Why this verdict
    if classification == "High Risk":
        reasons = [f.title for f in high_f[:3]]
        reason_str = ", ".join(reasons) if reasons else "multiple high-risk indicators were detected"
        sec4 = (
            "4. Why this verdict\n"
            f"This verdict was reached because critical threat indicators were identified: {reason_str}. "
            "These signals deviate substantially from verified safe behavior and strongly indicate active deception or credential harvesting."
        )
    elif classification == "Suspicious":
        reasons = [f.title for f in med_f[:3]]
        reason_str = ", ".join(reasons) if reasons else "anomalous or unusual patterns were detected"
        sec4 = (
            "4. Why this verdict\n"
            f"This verdict reflects elevated caution due to anomalous patterns: {reason_str}. "
            "While not definitively confirmed malicious, these indicators warrant independent verification."
        )
    else:
        sec4 = (
            "4. Why this verdict\n"
            "This verdict was reached because no significant risk indicators, deceptive lookalike domains, "
            "or unauthorized credential harvesting paths were observed. The target matches standard expected patterns."
        )

    # 5. What was checked
    checked = [f"- {p}" for p in providers_used] if providers_used else ["- Deterministic heuristics engine"]
    sec5 = "5. What was checked\n" + "\n".join(checked)

    # 6. Recommendation
    if classification == "High Risk":
        rec = "Do not open, click, or enter any credentials or sensitive information into this target. Treat it as hostile and delete or report it to your security team."
    elif classification == "Suspicious":
        rec = "Exercise caution before taking action or submitting credentials. Verify the sender or domain authenticity through an independent, trusted channel."
    else:
        rec = "The target appears safe for standard use based on local analysis. Standard cybersecurity vigilance is still recommended."
    sec6 = f"6. Recommendation\n{rec}"

    return f"{sec1}\n\n{sec2}\n\n{sec3}\n\n{sec4}\n\n{sec5}\n\n{sec6}"

