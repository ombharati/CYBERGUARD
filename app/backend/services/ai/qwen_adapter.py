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


class QwenObservation(BaseModel):
    what: str
    why_it_matters: str
    strength: Literal["weak", "moderate", "strong"] = "weak"


class QwenReasonedAnalysis(BaseModel):
    reasoning: str = ""
    observations: List[QwenObservation] = Field(default_factory=list)
    legitimate_explanations: List[str] = Field(default_factory=list)
    verdict: Literal["likely_phishing", "suspicious", "likely_legitimate", "insufficient_information"] = "suspicious"
    what_would_change_my_mind: str = ""


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

    # Regex extraction fallback for truncated responses
    extracted: Dict[str, Any] = {}
    reasoning_match = re.search(r'"reasoning"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"', candidate)
    if reasoning_match:
        extracted["reasoning"] = reasoning_match.group(1)

    verdict_match = re.search(
        r'"verdict"\s*:\s*"(likely_phishing|suspicious|likely_legitimate|insufficient_information)"',
        candidate,
    )
    if verdict_match:
        extracted["verdict"] = verdict_match.group(1)

    change_match = re.search(r'"what_would_change_my_mind"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"', candidate)
    if change_match:
        extracted["what_would_change_my_mind"] = change_match.group(1)

    obs_matches = re.findall(
        r'\{\s*"what"\s*:\s*"([^"]+)"\s*,\s*"why_it_matters"\s*:\s*"([^"]+)"(?:\s*,\s*"strength"\s*:\s*"(weak|moderate|strong)")?',
        candidate,
    )
    if obs_matches:
        extracted["observations"] = [
            {"what": m[0], "why_it_matters": m[1], "strength": m[2] or "weak"}
            for m in obs_matches
        ]

    if extracted.get("verdict") or extracted.get("reasoning") or extracted.get("observations"):
        return extracted

    raise ValueError(f"Could not parse or repair valid JSON: {text[:120]}")



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

    async def warmup(self) -> bool:
        """Pre-load Qwen weights into GPU VRAM and keep active for 24h to eliminate cold start."""
        if not await self.is_available():
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
            async with httpx.AsyncClient(timeout=20.0) as client:
                res = await client.post(f"{self.base_url}/api/generate", json=payload)
                if res.status_code == 200:
                    logger.info("[qwen] Model '%s' successfully warmed up in GPU VRAM (keep_alive: 24h).", self.model)
                    return True
        except Exception as exc:
            logger.warning("[qwen] Model warmup failed: %s", exc)
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
            "Keep observations concise (maximum 3 key observations) and reasoning succinct to ensure complete output.\n"
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
                if structured.verdict == "likely_legitimate":
                    sev = "low"
                else:
                    severity_map = {"strong": "high", "moderate": "medium", "weak": "low"}
                    sev = severity_map.get(obs.strength, "low")

                findings.append(Finding(
                    severity=sev,
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
    "Your report must contain exactly the following seven numbered section headings in this exact order:\n\n"
    "1. What was analyzed\n"
    "2. Verdict\n"
    "3. Key findings\n"
    "4. Why this verdict\n"
    "5. What was checked\n"
    "6. What was not checked\n"
    "7. Recommendation\n\n"
    "Section rules:\n"
    "- 1. What was analyzed: State the input type and a short factual description of the target. Do not invent details or include secrets.\n"
    "- 2. Verdict: State the classification and score in exactly one line (e.g., 'Verdict: High Risk (Risk Score: 98/100)'). Do not repeat the score anywhere else in the report.\n"
    "- 3. Key findings: Group findings by severity (High, Medium, Low). Explain each key finding in 1-2 plain sentences. If no findings were detected, state that.\n"
    "- 4. Why this verdict: Short reasoning, referencing the strongest signals observed.\n"
    "- 5. What was checked: List the detectors and intelligence providers that actually ran.\n"
    "- 6. What was not checked: List providers that were unavailable, disabled, or timed out. Do not invent external data.\n"
    "- 7. Recommendation: One or two calm sentences advising what the user should do.\n\n"
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

    # 6. What was not checked
    not_checked = [f"- {p}" for p in providers_not_used] if providers_not_used else ["- All configured local analysis modules completed."]
    sec6 = "6. What was not checked\n" + "\n".join(not_checked)

    # 7. Recommendation
    if classification == "High Risk":
        rec = "Do not open, click, or enter any credentials or sensitive information into this target. Treat it as hostile and delete or report it to your security team."
    elif classification == "Suspicious":
        rec = "Exercise caution before taking action or submitting credentials. Verify the sender or domain authenticity through an independent, trusted channel."
    else:
        rec = "The target appears safe for standard use based on local analysis. Standard cybersecurity vigilance is still recommended."
    sec7 = f"7. Recommendation\n{rec}"

    return f"{sec1}\n\n{sec2}\n\n{sec3}\n\n{sec4}\n\n{sec5}\n\n{sec6}\n\n{sec7}"

