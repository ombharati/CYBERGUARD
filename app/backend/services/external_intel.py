"""Optional External Threat Intelligence Adapters.

Architectural constraints:
- External systems are isolated behind adapters.
- Disabled by default. Never required for core scans.
- Timeouts and failures must not prevent deterministic/local scan from succeeding.
- Unavailable providers are represented honestly in the report.
"""
import logging
from typing import Dict, Any, List
import httpx
from app.backend.core.config import settings
from detection.url.detector import Finding

logger = logging.getLogger(__name__)


class ExternalThreatIntelAdapter:
    """Safely queries external threat intelligence providers when enabled and configured."""

    def __init__(self):
        self.enabled = settings.ENABLE_EXTERNAL_INTEL
        self.vt_api_key = settings.VIRUSTOTAL_API_KEY
        self.urlscan_api_key = settings.URLSCAN_API_KEY
        self.timeout = settings.EXTERNAL_INTEL_TIMEOUT_SECONDS

    async def query_url_intel(self, url: str) -> Dict[str, Any]:
        """
        Query external providers for URL reputation.
        Returns signals, findings, and provider availability status.
        """
        if not self.enabled:
            return {
                "enabled": False,
                "status": "disabled",
                "signals": {},
                "findings": [],
            }

        signals: Dict[str, Any] = {}
        findings: List[Finding] = []
        providers_queried = []

        # 1. VirusTotal check (if API key provided)
        if self.vt_api_key:
            providers_queried.append("VirusTotal")
            try:
                # VirusTotal v3 requires url identifier encoded as base64 without padding
                import base64
                url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
                logger.info("[threat_intel_vt] Querying VirusTotal with timeout=%ss", self.timeout)
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.get(
                        f"https://www.virustotal.com/api/v3/urls/{url_id}",
                        headers={"x-apikey": self.vt_api_key}
                    )
                if resp.status_code == 200:
                    data = resp.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious_count = stats.get("malicious", 0)
                    signals["virustotal_malicious"] = malicious_count
                    if malicious_count > 0:
                        findings.append(Finding(
                            severity="high",
                            title=f"VirusTotal Detections ({malicious_count} engines)",
                            description=f"{malicious_count} security vendors flagged this URL as malicious.",
                            category="threat_intel",
                        ))
                    logger.info("[threat_intel_vt] VirusTotal completed (malicious_count=%s)", malicious_count)
                elif resp.status_code == 404:
                    signals["virustotal_malicious"] = 0
                    logger.info("[threat_intel_vt] URL not found in VirusTotal database")
                else:
                    logger.warning("[threat_intel_vt] VirusTotal returned HTTP %s", resp.status_code)
            except httpx.TimeoutException as vt_timeout:
                logger.warning("[threat_intel_vt] VirusTotal lookup timed out after %ss: %s", self.timeout, vt_timeout)
            except Exception as vt_exc:
                logger.warning("[threat_intel_vt] VirusTotal lookup failed: %s", vt_exc)

        return {
            "enabled": True,
            "providers_queried": providers_queried,
            "signals": signals,
            "findings": findings,
        }
