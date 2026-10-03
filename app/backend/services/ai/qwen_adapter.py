"""Qwen AI Adapter for semantic, email, and URL threat analysis via local Ollama.

Architectural constraints:
- System 2 deep reasoning and reporting (qwen3:8b on GPU via Ollama).
- Operates on emails, content snippets, and URLs synthesized with Laya and deterministic findings.
- Produces structured findings and signals, never directly overrides deterministic scoring in isolation.
- Strict timeout and context size limits.
- Validates structured JSON responses via Pydantic. Malformed output is treated as inference failure.
- Graceful degradation if Ollama or model is unreachable.
"""
import json
import logging
import time
from typing import Dict, Any, List, Optional
import httpx
from pydantic import BaseModel, Field
from app.backend.core.config import settings
from detection.url.detector import Finding

logger = logging.getLogger(__name__)


class QwenSemanticAnalysis(BaseModel):
    is_social_engineering: bool = False
    urgency_level: str = "none"  # "none", "low", "medium", "high"
    credential_harvesting_intent: bool = False
    suspicion_score: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    key_indicators: List[str] = Field(default_factory=list)
    threat_summary: str = ""
    technical_reasoning: str = ""


class QwenURLAnalysis(BaseModel):
    is_phishing: bool = False
    brand_impersonated: Optional[str] = "None"
    credential_theft: bool = False
    suspicion_score: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    key_indicators: List[str] = Field(default_factory=list)
    threat_summary: str = ""
    technical_reasoning: str = ""


class QwenAdapter:
    """Adapter for querying local Qwen model through Ollama."""

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
        except Exception:
            return False

    async def analyze_url(
        self,
        url: str,
        deterministic_signals: Optional[Dict[str, Any]] = None,
        laya_signals: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze a URL for phishing, brand impersonation, deceptive structure,
        and credential harvesting, synthesizing deterministic and Laya System 1 signals.
        """
        clean_url = url.strip()[:settings.MAX_URL_LENGTH]

        system_prompt = (
            "You are a Senior Cybersecurity Threat Intelligence Analyst and Phishing Detection Expert. "
            "Your objective is to evaluate whether a destination URL is a phishing attack, brand impersonation portal, "
            "credential theft harvesting site, or deceptive scam.\n"
            "Operating Rules:\n"
            "1. Temporal grounding: The current year is 2026.\n"
            "2. Anti-hallucination constraint: You must ONLY reason based on the observable URL string, structural indicators, "
            "and detector telemetry. Do NOT fabricate external registrar data, whois creation dates, or blacklists you cannot verify.\n"
            "3. Phishing indicators to look for: Brand names in domain or subdomains (typosquatting/homographs), deceptive subdomains masking true authority, "
            "credential paths (/login, /signin, /verify, /account, /update), suspicious high-abuse TLDs, and incongruence between target domain and brand.\n"
            "4. Synthesize the provided System 1 Laya neural probability and deterministic URL signals.\n"
            "5. Respond STRICTLY with a single valid JSON object matching the requested schema and nothing else."
        )

        user_prompt = (
            f"Analyze the following URL for cybersecurity threats and phishing intent:\n"
            f"TARGET URL: {clean_url}\n\n"
            f"DETERMINISTIC HEURISTIC SIGNALS:\n{json.dumps(deterministic_signals or {}, default=str, indent=2)}\n\n"
            f"LAYA SYSTEM 1 NEURAL SIGNALS:\n{json.dumps(laya_signals or {}, default=str, indent=2)}\n\n"
            "Respond ONLY with a JSON object matching this schema exactly:\n"
            "{\n"
            '  "is_phishing": boolean,\n'
            '  "brand_impersonated": "Name of brand spoofed, or None",\n'
            '  "credential_theft": boolean,\n'
            '  "suspicion_score": float between 0.0 and 1.0,\n'
            '  "confidence": float between 0.0 and 1.0,\n'
            '  "key_indicators": ["concrete", "observed", "warning", "signals"],\n'
            '  "threat_summary": "one clear sentence summarizing the assessment",\n'
            '  "technical_reasoning": "two to three sentences of technical security reasoning"\n'
            "}"
        )

        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": user_prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.1,
                "num_predict": 250,
            },
        }

        start_time = time.perf_counter()
        logger.info(
            "[QWEN URL] Request sent to Ollama: model='%s', url='%s'",
            self.model,
            clean_url,
        )

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                )
            latency_ms = (time.perf_counter() - start_time) * 1000

            if response.status_code != 200:
                logger.warning(
                    "[QWEN URL] Ollama returned status %s after %.2fms: %s",
                    response.status_code,
                    latency_ms,
                    response.text,
                )
                return {
                    "available": False,
                    "error": f"Ollama HTTP {response.status_code}",
                    "signals": {},
                    "findings": [],
                }

            data = response.json()
            raw_response = data.get("response", "{}")
            logger.info(
                "[QWEN URL] Response received in %.2fms from model '%s': %s",
                latency_ms,
                self.model,
                raw_response,
            )

            try:
                parsed_json = json.loads(raw_response)
                structured = QwenURLAnalysis.model_validate(parsed_json)
            except Exception as parse_err:
                logger.warning("[QWEN URL] Malformed Qwen URL output: %s (raw: %s)", parse_err, raw_response)
                return {
                    "available": False,
                    "error": f"Malformed model response: {parse_err}",
                    "signals": {},
                    "findings": [],
                }

            brand_raw = structured.brand_impersonated or ""
            is_brand_spoof = bool(
                brand_raw
                and brand_raw.lower() not in ("none", "null", "false", "no", "n/a", "unknown")
            )

            signals = {
                "qwen_is_phishing": structured.is_phishing,
                "qwen_brand_impersonation": is_brand_spoof,
                "qwen_target_brand": brand_raw if is_brand_spoof else "",
                "qwen_credential_intent": structured.credential_theft,
                "qwen_suspicion_score": round(structured.suspicion_score, 3),
                "qwen_confidence": round(structured.confidence, 3),
            }

            findings: List[Finding] = []

            if structured.is_phishing:
                brand_suffix = f" targeting {brand_raw}" if is_brand_spoof else ""
                findings.append(Finding(
                    severity="high",
                    title="Phishing Link Confirmed by AI (Qwen)",
                    description=f"Deep semantic reasoning identified this destination as a phishing attack{brand_suffix}. {structured.threat_summary}",
                    category="qwen_ai",
                ))

            if structured.credential_theft:
                findings.append(Finding(
                    severity="high",
                    title="Credential Theft Intent Detected (Qwen)",
                    description="Deep neural reasoning identified malicious intent to harvest authentication credentials or passwords.",
                    category="qwen_ai",
                ))
            elif is_brand_spoof:
                findings.append(Finding(
                    severity="medium",
                    title=f"Brand Spoofing Target Identified: {brand_raw}",
                    description=f"AI analysis detected deceptive imitation of {brand_raw}.",
                    category="qwen_ai",
                ))

            if structured.suspicion_score >= 0.70 and not structured.is_phishing:
                findings.append(Finding(
                    severity="medium",
                    title="Elevated Structural Risk (Qwen)",
                    description=structured.threat_summary or "The URL displays deceptive or suspicious structural composition.",
                    category="qwen_ai",
                ))

            placeholder_terms = {"concrete", "observed", "warning", "signals", "list", "of", "signs", "none"}
            for indicator in structured.key_indicators[:3]:
                clean_ind = indicator.strip()
                if clean_ind and clean_ind.lower() not in placeholder_terms and clean_ind.lower() not in [f.description.lower() for f in findings]:
                    findings.append(Finding(
                        severity="low",
                        title="AI Identified Indicator",
                        description=clean_ind,
                        category="qwen_ai",
                    ))

            return {
                "available": True,
                "signals": signals,
                "confidence": structured.confidence,
                "summary": structured.threat_summary,
                "reasoning": structured.technical_reasoning,
                "findings": findings,
            }

        except httpx.TimeoutException:
            logger.warning("[QWEN URL] Ollama inference timed out after %ss", self.timeout)
            return {
                "available": False,
                "error": "Model inference timeout",
                "signals": {},
                "findings": [],
            }
        except Exception as exc:
            logger.warning("[QWEN URL] Inference failed: %s", exc)
            return {
                "available": False,
                "error": str(exc),
                "signals": {},
                "findings": [],
            }

    async def analyze_content(
        self,
        text_content: str,
        context_hints: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze email or raw content for social engineering, credential harvesting,
        and deceptive urgency.
        """
        truncated_text = text_content.strip()[:settings.MAX_CONTENT_LENGTH]
        hints_str = ""
        if context_hints:
            hints_str = f"\nExtracted URL / Heuristic Signals: {json.dumps(context_hints, default=str)}"

        system_prompt = (
            "You are a Senior Cybersecurity Threat Intelligence Analyst analyzing potential phishing, "
            "email deception, or social engineering.\n"
            "Operating Rules:\n"
            "1. Temporal grounding: The current year is 2026.\n"
            "2. Anti-hallucination constraint: Reason strictly on provided text and signals. Do NOT invent unverified facts.\n"
            "3. Assess psychological urgency, credential harvesting, and spoofing.\n"
            "4. Respond STRICTLY with a single valid JSON object matching the requested schema and nothing else."
        )

        user_prompt = (
            "Analyze the following text and extracted findings for cybersecurity deception:\n"
            f"TEXT TO ANALYZE:\n\"\"\"\n{truncated_text}\n\"\"\"\n"
            f"{hints_str}\n\n"
            "Respond ONLY with a JSON object matching this schema exactly:\n"
            "{\n"
            '  "is_social_engineering": boolean,\n'
            '  "urgency_level": "none" | "low" | "medium" | "high",\n'
            '  "credential_harvesting_intent": boolean,\n'
            '  "suspicion_score": float between 0.0 and 1.0,\n'
            '  "confidence": float between 0.0 and 1.0,\n'
            '  "key_indicators": ["list", "of", "concrete", "warning", "signs"],\n'
            '  "threat_summary": "one clear sentence summarizing the assessment",\n'
            '  "technical_reasoning": "two to three sentences of technical security reasoning"\n'
            "}"
        )

        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": user_prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.1,
                "num_predict": 250,
            },
        }

        start_time = time.perf_counter()
        logger.info(
            "[QWEN CONTENT] Request sent to Ollama: model='%s'",
            self.model,
        )

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                )
            latency_ms = (time.perf_counter() - start_time) * 1000

            if response.status_code != 200:
                logger.warning(
                    "[QWEN CONTENT] Ollama returned status %s after %.2fms: %s",
                    response.status_code,
                    latency_ms,
                    response.text,
                )
                return {
                    "available": False,
                    "error": f"Ollama HTTP {response.status_code}",
                    "signals": {},
                    "findings": [],
                }

            data = response.json()
            raw_response = data.get("response", "{}")
            logger.info(
                "[QWEN CONTENT] Response received in %.2fms from model '%s': %s",
                latency_ms,
                self.model,
                raw_response,
            )

            try:
                parsed_json = json.loads(raw_response)
                structured = QwenSemanticAnalysis.model_validate(parsed_json)
            except Exception as parse_err:
                logger.warning("[QWEN CONTENT] Malformed Qwen output: %s (raw: %s)", parse_err, raw_response)
                return {
                    "available": False,
                    "error": f"Malformed model response: {parse_err}",
                    "signals": {},
                    "findings": [],
                }

            signals = {
                "qwen_social_engineering": structured.is_social_engineering,
                "qwen_credential_intent": structured.credential_harvesting_intent,
                "qwen_urgency": structured.urgency_level,
                "qwen_suspicion_score": round(structured.suspicion_score, 3),
                "qwen_confidence": round(structured.confidence, 3),
            }

            findings: List[Finding] = []

            if structured.credential_harvesting_intent:
                findings.append(Finding(
                    severity="high",
                    title="Credential Theft Intent Detected (Qwen)",
                    description="AI semantic analysis identified deceptive intent to capture credentials, passwords, or authentication secrets.",
                    category="qwen_ai",
                ))

            if structured.is_social_engineering and structured.urgency_level in ("medium", "high"):
                findings.append(Finding(
                    severity="high" if structured.urgency_level == "high" else "medium",
                    title=f"Social Engineering / Urgency Pressure ({structured.urgency_level.capitalize()})",
                    description=f"Message uses psychological pressure or artificial urgency: {', '.join(structured.key_indicators[:3])}.",
                    category="qwen_ai",
                ))
            elif structured.is_social_engineering:
                findings.append(Finding(
                    severity="medium",
                    title="Social Engineering Indicators (Qwen)",
                    description="Semantic analysis detected social engineering patterns designed to manipulate the recipient.",
                    category="qwen_ai",
                ))

            placeholder_terms = {"concrete", "observed", "warning", "signals", "list", "of", "signs", "none"}
            for indicator in structured.key_indicators[:3]:
                clean_ind = indicator.strip()
                if clean_ind and clean_ind.lower() not in placeholder_terms and clean_ind.lower() not in [f.description.lower() for f in findings]:
                    findings.append(Finding(
                        severity="low",
                        title="AI Identified Indicator",
                        description=clean_ind,
                        category="qwen_ai",
                    ))

            return {
                "available": True,
                "signals": signals,
                "confidence": structured.confidence,
                "summary": structured.threat_summary,
                "reasoning": structured.technical_reasoning,
                "findings": findings,
            }

        except httpx.TimeoutException:
            logger.warning("[QWEN CONTENT] Ollama inference timed out after %ss", self.timeout)
            return {
                "available": False,
                "error": "Model inference timeout",
                "signals": {},
                "findings": [],
            }
        except Exception as exc:
            logger.warning("[QWEN CONTENT] Qwen inference failed: %s", exc)
            return {
                "available": False,
                "error": str(exc),
                "signals": {},
                "findings": [],
            }
