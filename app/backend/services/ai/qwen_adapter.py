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
import json
import logging
import time
from typing import Dict, Any, List, Optional, Literal
import httpx
from pydantic import BaseModel, Field
from app.backend.core.config import settings
from detection.url.detector import Finding

logger = logging.getLogger(__name__)


class QwenObservation(BaseModel):
    what: str
    why_it_matters: str
    strength: Literal["weak", "moderate", "strong"] = "weak"


class QwenReasonedAnalysis(BaseModel):
    reasoning: str
    observations: List[QwenObservation] = Field(default_factory=list)
    legitimate_explanations: List[str] = Field(default_factory=list)
    verdict: Literal["likely_phishing", "suspicious", "likely_legitimate", "insufficient_information"]
    what_would_change_my_mind: str


SYSTEM_PROMPT = """You are a Senior Cybersecurity Threat Intelligence Analyst.

Your core philosophy:
"/login" exists on every real bank. Sensitive paths (/login, /verify, /kyc, /account/update) are neutral on their own. They only matter if the domain isn't the real bank, or the action was unprompted, or the request asks for something illegitimate.
Urgency words ("within 24 hours", "immediate action") are neutral on their own unless used to short-circuit a decision involving credentials, secrecy, or unusual payments.
High-abuse TLDs (.xyz, .top) and shorteners are not standalone proof of maliciousness. Real startups and legit marketing use them.

Before you label anything, reason through these three questions and write the answers in "reasoning":

1. IDENTITY — Does the domain match the brand or person being claimed?
   If the email/URL says "PayPal" and the domain is not paypal.com, that is a strong signal.
   If it says "PayPal" and the domain is paypal.com, the identity is clean.
   Reference Table of Official Domains:
   - State Bank of India: Official `sbi.bank.in`, Legacy/Valid `sbi.co.in`, `onlinesbi.com`
   - HDFC Bank: Official `hdfc.bank.in`, Legacy/Valid `hdfcbank.com`
   - ICICI Bank: Official `icici.bank.in`, Legacy/Valid `icicibank.com`
   - Axis Bank: Official `axis.bank.in`, Legacy/Valid `axisbank.com`
   - Punjab National Bank: Official `pnb.bank.in`, Legacy/Valid `pnbindia.in`
   - Bank of India: Official `bankofindia.bank.in`, Legacy/Valid `bankofindia.co.in`
   - Indian Bank: Official `indianbank.bank.in`, Legacy/Valid `indianbank.in`
   - PayPal: `paypal.com`
   - Chase Bank: `chase.com`
   - Bank of America: `bankofamerica.com`
   - Wells Fargo: `wellsfargo.com`
   - Apple: `apple.com`, `icloud.com`
   - Microsoft: `microsoft.com`, `live.com`, `office.com`, `outlook.com`
   - Google: `google.com`, `gmail.com`, `accounts.google.com`
   - Amazon: `amazon.com`, `aws.amazon.com`
   - Netflix: `netflix.com`

2. BEHAVIOR — Is the request expected in this context?
   A bank sending a login link is normal. A bank asking for your PIN or OTP is not.
   A password reset requested by the user is normal. A password reset unprompted with a 24h deadline is not.
   An exchange asking for KYC after signup is normal. An exchange asking for KYC on a cold email is not.

3. REQUEST — Is something being asked that a real service would never ask?
   Passwords, PINs, OTPs, full card numbers, gift cards, crypto, or demands for secrecy ("keep confidential", "do not tell anyone").
   Real services do not ask for these.

REWRITTEN RULES FOR NOISY CATEGORIES:
- Sensitive paths (/login, /verify, /kyc, /wallet/connect, /confirm, /account/update):
  These paths are NEUTRAL. Real banks, wallets, exchanges, and SaaS all use them.
  Only a signal when combined with an unauthorized lookalike domain or behavior mismatch.
  Never flag /login on an official domain.
- Urgency phrases ("within 24 hours", "immediate action", "final notice"):
  Urgency words are NEUTRAL on their own. Real alerts and renewals use them.
  Flag only when urgency short-circuits a decision involving credentials, payments, or secrecy.
  Urgency alone ("sale ends tonight", "trial ending") is NO SIGNAL.
- High-abuse TLDs (.xyz, .top, .tk, etc.):
  Overrepresented in phishing but NOT proof. Real startups and dev tools use .xyz and .io.
  Only treat as a signal when combined with a brand lookalike or a credential/payment ask.
  A .xyz domain from an actual startup or developer tool with no credential ask is NOT phishing — label "likely_legitimate".
- Shorteners (bit.ly, tinyurl, t.co):
  Legitimate marketing uses shorteners. Only a signal if impersonating a bank or asking credentials.
- Generic greeting ("Dear Customer"):
  Only a signal if sender claims an established personal banking/account relationship. In cold outreach or newsletters it is normal.

Verdict decision rules:
- Only when at least TWO of the three questions are problematic should you label "likely_phishing".
- ONE problematic and two clean = "suspicious", not phishing.
- All three clean = "likely_legitimate", even if the target uses urgency, a shortener, a .xyz domain, or a /login link.
- If information needed to evaluate is missing = "insufficient_information".

Do NOT output a confidence number (no floats, no 0.95).
Do NOT label based on a single keyword.
Mandatory: Provide "legitimate_explanations" steelmanning a benign reading, and "what_would_change_my_mind".

Worked Reference Example:
Input:
From: HDFC Bank <alerts@hdfc-bank-kyc-update.com>
Subject: Urgent: Complete your KYC within 24 hours
Body: Dear Customer, your account will be suspended. Verify now: https://hdfc-bank-kyc-update.com/login/verify?customer=827491

Output:
{
  "reasoning": "Checked identity first: email claims HDFC Bank but domain is hdfc-bank-kyc-update.com, not hdfc.bank.in or hdfcbank.com. That is a mismatch. Checked behavior: KYC requests do come from real banks, but on their own domain, and usually after the customer initiates or through the app. Checked request: the email asks the user to verify via a link with an urgency of 24 hours and a suspension threat. The link path /login/verify is normal for a bank site, so the path itself is not the signal. The domain mismatch combined with the urgency is.",
  "observations": [
    {
      "what": "Claimed HDFC Bank, domain is hdfc-bank-kyc-update.com",
      "why_it_matters": "HDFC's real domains are hdfc.bank.in and hdfcbank.com. The hyphenated variant is an unauthorized lookalike.",
      "strength": "strong"
    },
    {
      "what": "24-hour deadline and account suspension threat",
      "why_it_matters": "Used here to short-circuit a decision that involves a login link. Real KYC notices are not typically framed with sudden threats.",
      "strength": "moderate"
    },
    {
      "what": "Generic greeting 'Dear Customer'",
      "why_it_matters": "A bank that holds the user's account would typically use their registered name. Weak on its own.",
      "strength": "weak"
    },
    {
      "what": "Path /login/verify on a bank domain",
      "why_it_matters": "Normal. Every bank has this. Not a threat signal.",
      "strength": "weak"
    }
  ],
  "legitimate_explanations": [
    "Real banks do send KYC reminders. If the domain were hdfcbank.com or hdfc.bank.in and the user had an open KYC request, this would be legitimate."
  ],
  "verdict": "likely_phishing",
  "what_would_change_my_mind": "If the sending domain were hdfcbank.com or hdfc.bank.in and the link resolved to the same official domain, this would read as a routine KYC reminder even with the urgency."
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
        except Exception:
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
            "Respond ONLY with a JSON object matching this schema exactly:\n"
            "{\n"
            '  "reasoning": "step-by-step reasoning evaluating identity, behavior, and request",\n'
            '  "observations": [\n'
            '    {\n'
            '      "what": "what was observed",\n'
            '      "why_it_matters": "why it matters in context",\n'
            '      "strength": "weak" | "moderate" | "strong"\n'
            '    }\n'
            '  ],\n'
            '  "legitimate_explanations": ["steelmanned benign explanation"],\n'
            '  "verdict": "likely_phishing" | "suspicious" | "likely_legitimate" | "insufficient_information",\n'
            '  "what_would_change_my_mind": "what evidence would change the verdict"\n'
            "}"
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
        truncated_text = text_content.strip()[:settings.MAX_CONTENT_LENGTH]
        hints_str = ""
        if context_hints:
            hints_str = f"\nEXTRACTED CONTEXT & SIGNALS:\n{json.dumps(context_hints, default=str, indent=2)}\n"

        user_prompt = (
            f"Analyze the following email/text communication under the IDENTITY, BEHAVIOR, and REQUEST rules:\n"
            f"COMMUNICATION CONTENT:\n\"\"\"\n{truncated_text}\n\"\"\"\n"
            f"{hints_str}\n"
            "Respond ONLY with a JSON object matching this schema exactly:\n"
            "{\n"
            '  "reasoning": "step-by-step reasoning evaluating identity, behavior, and request",\n'
            '  "observations": [\n'
            '    {\n'
            '      "what": "what was observed",\n'
            '      "why_it_matters": "why it matters in context",\n'
            '      "strength": "weak" | "moderate" | "strong"\n'
            '    }\n'
            '  ],\n'
            '  "legitimate_explanations": ["steelmanned benign explanation"],\n'
            '  "verdict": "likely_phishing" | "suspicious" | "likely_legitimate" | "insufficient_information",\n'
            '  "what_would_change_my_mind": "what evidence would change the verdict"\n'
            "}"
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
            "options": {
                "temperature": 0.1,
                "num_predict": 450,
            },
        }

        start_time = time.perf_counter()
        logger.info("[%s] Request sent to Ollama model='%s' for '%s'", tag, self.model, target_label)

        try:
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
                parsed_json = json.loads(raw_response)
                structured = QwenReasonedAnalysis.model_validate(parsed_json)
            except Exception as parse_err:
                logger.warning("[%s] Malformed output: %s (raw: %s)", tag, parse_err, raw_response)
                return {
                    "available": False,
                    "error": f"Malformed model response: {parse_err}",
                    "signals": {},
                    "findings": [],
                }

            # Map observations into structured findings attached to specific rationale
            findings: List[Finding] = []
            for obs in structured.observations:
                severity_map = {"strong": "high", "moderate": "medium", "weak": "low"}
                findings.append(Finding(
                    severity=severity_map.get(obs.strength, "low"),
                    title=obs.what,
                    description=obs.why_it_matters,
                    category="qwen_ai",
                ))

            strong_count = sum(1 for o in structured.observations if o.strength == "strong")
            moderate_count = sum(1 for o in structured.observations if o.strength == "moderate")
            weak_count = sum(1 for o in structured.observations if o.strength == "weak")

            signals = {
                "qwen_verdict": structured.verdict,
                "qwen_is_phishing": structured.verdict == "likely_phishing",
                "qwen_suspicious": structured.verdict == "suspicious",
                "qwen_legitimate": structured.verdict == "likely_legitimate",
                "qwen_strong_observations": strong_count,
                "qwen_moderate_observations": moderate_count,
                "qwen_weak_observations": weak_count,
            }

            return {
                "available": True,
                "signals": signals,
                "verdict": structured.verdict,
                "reasoning": structured.reasoning,
                "legitimate_explanations": structured.legitimate_explanations,
                "what_would_change_my_mind": structured.what_would_change_my_mind,
                "observations": [o.model_dump() for o in structured.observations],
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
