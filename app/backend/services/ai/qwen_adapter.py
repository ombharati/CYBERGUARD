"""Qwen AI Adapter for semantic and email threat analysis via local Ollama.

Architectural constraints:
- Semantic and email analysis.
- Analyzes email content together with structured URL/Laya findings.
- Produces structured findings, never directly determines the final risk score.
- Strict timeout and context size limits.
- Validates structured JSON responses. Malformed output is treated as inference failure.
- Graceful degradation if Ollama or model is unreachable.
"""
import json
import logging
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

    async def analyze_content(
        self,
        text_content: str,
        context_hints: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze email or raw content for social engineering, credential harvesting,
        and deceptive urgency.
        """
        # Strict input limiting to protect model context and latency
        truncated_text = text_content.strip()[:settings.MAX_CONTENT_LENGTH]
        hints_str = ""
        if context_hints:
            hints_str = f"\nExtracted URL / Heuristic Signals: {json.dumps(context_hints, default=str)}"

        prompt = (
            "You are a cybersecurity expert analyzing potential phishing, email deception, or malicious text.\n"
            "Analyze the following text and extracted findings.\n"
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
            '  "threat_summary": "one clear sentence summarizing the assessment"\n'
            "}"
        )

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0.1,
                "num_predict": 200,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                )

            if response.status_code != 200:
                logger.warning("Ollama returned status code %s", response.status_code)
                return {
                    "available": False,
                    "error": f"Ollama HTTP {response.status_code}",
                    "signals": {},
                    "findings": [],
                }

            data = response.json()
            raw_response = data.get("response", "{}")

            # Validate structured output strictly
            try:
                parsed_json = json.loads(raw_response)
                structured = QwenSemanticAnalysis.model_validate(parsed_json)
            except Exception as parse_err:
                logger.warning("Malformed Qwen output: %s (raw: %s)", parse_err, raw_response)
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

            for indicator in structured.key_indicators[:3]:
                if indicator.lower() not in [f.description.lower() for f in findings]:
                    findings.append(Finding(
                        severity="low",
                        title="AI Identified Indicator",
                        description=indicator,
                        category="qwen_ai",
                    ))

            return {
                "available": True,
                "signals": signals,
                "confidence": structured.confidence,
                "summary": structured.threat_summary,
                "findings": findings,
            }

        except httpx.TimeoutException:
            logger.warning("Ollama inference timed out after %ss", self.timeout)
            return {
                "available": False,
                "error": "Model inference timeout",
                "signals": {},
                "findings": [],
            }
        except Exception as exc:
            logger.warning("Qwen inference failed: %s", exc)
            return {
                "available": False,
                "error": str(exc),
                "signals": {},
                "findings": [],
            }
