"""Unit tests for Laya and Qwen AI Adapters with mocking and fallback testing."""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from app.backend.services.ai.laya_adapter import LayaAdapter
from app.backend.services.ai.qwen_adapter import QwenAdapter
from detection.url.detector import Finding


def test_laya_adapter_fallback_when_unavailable():
    adapter = LayaAdapter(available=False)

    result = adapter.analyze_url("https://example.com")
    assert result["available"] is False
    assert result["signals"] == {}
    assert result["findings"] == []


def test_laya_adapter_successful_mock_prediction():
    mock_agent = MagicMock()
    mock_agent.predict.return_value = {
        "answers": {
            "phishing_intent": {"noul": 0.88, "answer_confidence": 0.95},
            "brand_impersonation": {"noul": 0.75},
            "suspicion_level": {"score": 2.5},
        }
    }
    adapter = LayaAdapter(agent=mock_agent, available=True)

    result = adapter.analyze_url("https://paypa1-security.com/login")
    assert result["available"] is True
    assert result["signals"]["laya_phishing_probability"] == 0.88
    assert result["signals"]["laya_brand_impersonation"] == 0.75
    assert len(result["findings"]) >= 1
    assert any("Phishing Probability" in f.title for f in result["findings"])


@pytest.mark.asyncio
async def test_qwen_adapter_fallback_on_timeout():
    adapter = QwenAdapter()
    with patch("httpx.AsyncClient.post", side_effect=Exception("Connection refused")):
        result = await adapter.analyze_content("Urgent account suspended")
        assert result["available"] is False
        assert result["signals"] == {}
        assert result["findings"] == []


@pytest.mark.asyncio
async def test_qwen_adapter_structured_parsing():
    adapter = QwenAdapter()
    mock_json_response = {
        "response": (
            '{\n'
            '  "signals": [\n'
            '    {"type": "Password solicitation", "severity": "high", "evidence": "verify your account password"}\n'
            '  ],\n'
            '  "confidence": 0.90,\n'
            '  "notes": "Asking for password is an illegitimate request."\n'
            '}'
        )
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_json_response

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        result = await adapter.analyze_content("Please verify your account password immediately.")
        assert result["available"] is True
        assert result.get("provider_status") != "qwen_invalid"
        assert result["signals"]["qwen_is_phishing"] is True
        assert result["signals"]["qwen_verdict"] == "likely_phishing"
        assert len(result["findings"]) == 1
        assert "Password solicitation" in result["findings"][0].title

@pytest.mark.asyncio
async def test_qwen_adapter_malformed_output():
    adapter = QwenAdapter()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": "This is plain text not valid JSON!"}

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        result = await adapter.analyze_content("Hello")
        assert result["provider_status"] == "qwen_invalid"
        assert "Malformed model response" in result["error"]

@pytest.mark.asyncio
async def test_qwen_adapter_analyze_url_phishing():
    adapter = QwenAdapter()
    mock_json_response = {
        "response": (
            '{\n'
            '  "signals": [\n'
            '    {"type": "Unauthorized lookalike", "severity": "high", "evidence": "chase-security"}\n'
            '  ],\n'
            '  "confidence": 0.95,\n'
            '  "notes": "Identity mismatch."\n'
            '}'
        )
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_json_response

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        result = await adapter.analyze_url(
            "https://chase-security-update-verify.com/login",
            deterministic_signals={"matched_keywords": ["chase", "login"], "is_lookalike_domain": True},
            laya_signals={"laya_phishing_probability": 0.95},
        )
        assert result["available"] is True
        assert result.get("provider_status") != "qwen_invalid"
        assert result["signals"]["qwen_is_phishing"] is True
        assert result["signals"]["qwen_verdict"] == "likely_phishing"
        assert len(result["findings"]) == 1

@pytest.mark.asyncio
async def test_qwen_adapter_hallucinated_evidence():
    adapter = QwenAdapter()
    mock_json_response = {
        "response": (
            '{\n'
            '  "signals": [\n'
            '    {"type": "Fake Signal", "severity": "high", "evidence": "something totally made up"}\n'
            '  ],\n'
            '  "confidence": 0.95,\n'
            '  "notes": "Invented stuff."\n'
            '}'
        )
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_json_response

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        result = await adapter.analyze_content("Just a normal message.")
        assert result["provider_status"] == "qwen_invalid"
        assert "Validation failed" in result["error"]
        assert len(result["findings"]) == 0

@pytest.mark.asyncio
async def test_qwen_adapter_confidence_clamping():
    adapter = QwenAdapter()
    mock_json_response = {
        "response": (
            '{\n'
            '  "signals": [\n'
            '    {"type": "Minor issue", "severity": "low", "evidence": "normal"}\n'
            '  ],\n'
            '  "confidence": 0.99,\n'
            '  "notes": "High confidence but no high severity signals."\n'
            '}'
        )
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_json_response

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        result = await adapter.analyze_content("Just a normal message.")
        assert result["available"] is True
        assert result.get("provider_status") != "qwen_invalid"
        # Confidence should be clamped to 0.85
        assert result["signals"]["qwen_confidence"] == 0.85
        assert result["signals"]["qwen_verdict"] == "suspicious" # >0.5


@pytest.mark.asyncio
async def test_qwen_generate_narrative_report_success():
    adapter = QwenAdapter()
    sample_qwen_report = (
        "1. What was analyzed\n"
        "Input type: URL\n"
        "Target inspected: https://hdfc-bank-kyc-update.com/login/verify\n\n"
        "2. Verdict\n"
        "Verdict: High Risk (Risk Score: 98/100)\n\n"
        "3. Key findings\n"
        "High Severity:\n"
        "- Unauthorized Brand Lookalike Domain: Domain mimics HDFC Bank without authorization.\n"
        "- Credential Harvesting Path: Sensitive login and verification path on untrusted domain.\n\n"
        "4. Why this verdict\n"
        "This verdict was reached because the domain mimics an official financial institution while requesting credentials.\n\n"
        "5. What was checked\n"
        "- Deterministic URL Heuristics Detector\n"
        "- Laya Neural Decision Engine (CPU)\n"
        "- Qwen Semantic Threat Reasoner (GPU)\n\n"
        "6. Recommendation\n"
        "Do not click, open, or provide account credentials to this link. Delete and report it immediately."
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": sample_qwen_report}

    with patch.object(adapter, "is_available", new_callable=AsyncMock, return_value=True):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
            res = await adapter.generate_narrative_report(
                input_type="URL",
                target="https://hdfc-bank-kyc-update.com/login/verify",
                risk_score=98,
                classification="High Risk",
                findings=[Finding(severity="high", title="Lookalike", description="Spoofed brand")],
                providers_used=["Deterministic URL Heuristics Detector"],
                providers_not_used=["External Threat Intel (disabled)"],
            )
            assert res["generated_by"] == "qwen"
            assert "1. What was analyzed" in res["report_text"]
            assert "2. Verdict" in res["report_text"]
            assert "98/100" in res["report_text"]
            assert "6. Recommendation" in res["report_text"]
            assert "**" not in res["report_text"]
            assert "#" not in res["report_text"]


@pytest.mark.asyncio
async def test_qwen_generate_narrative_report_fallback_when_unavailable():
    adapter = QwenAdapter()
    with patch.object(adapter, "is_available", new_callable=AsyncMock, return_value=False):
        res = await adapter.generate_narrative_report(
            input_type="URL",
            target="https://legitimate-service.com/dashboard",
            risk_score=10,
            classification="Safe",
            findings=[],
            providers_used=["Deterministic Heuristics Engine"],
            providers_not_used=["External Threat Intel (disabled)"],
        )
        assert res["generated_by"] == "template"
        assert "1. What was analyzed" in res["report_text"]
        assert "2. Verdict" in res["report_text"]
        assert "Safe (Risk Score: 10/100)" in res["report_text"]
        assert "3. Key findings" in res["report_text"]
        assert "4. Why this verdict" in res["report_text"]
        assert "5. What was checked" in res["report_text"]
        assert "6. Recommendation" in res["report_text"]


def test_laya_adapter_timeout_handling():
    import time
    mock_slow_agent = MagicMock()
    def slow_predict(*args, **kwargs):
        time.sleep(0.5)
        return {}

    mock_slow_agent.predict.side_effect = slow_predict
    # Instantiate with very short timeout of 0.1s
    adapter = LayaAdapter(agent=mock_slow_agent, available=True, timeout=0.1)
    result = adapter.analyze_url("https://example.com/test-timeout")
    assert result["available"] is False
    assert "timed out" in result["error"]
    assert result["signals"] == {}
    assert result["findings"] == []


