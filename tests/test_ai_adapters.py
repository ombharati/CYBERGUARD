"""Unit tests for Laya and Qwen AI Adapters with mocking and fallback testing."""
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from app.backend.services.ai.laya_adapter import LayaAdapter
from app.backend.services.ai.qwen_adapter import QwenAdapter


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
        "response": '{"is_social_engineering": true, "urgency_level": "high", "credential_harvesting_intent": true, "suspicion_score": 0.9, "confidence": 0.85, "key_indicators": ["account suspension", "verify password"], "threat_summary": "High risk phishing attempt"}'
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_json_response

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        result = await adapter.analyze_content("Please verify your account password immediately.")
        assert result["available"] is True
        assert result["signals"]["qwen_social_engineering"] is True
        assert result["signals"]["qwen_credential_intent"] is True
        assert result["signals"]["qwen_urgency"] == "high"
        assert len(result["findings"]) >= 2
        assert any("Credential Theft" in f.title for f in result["findings"])


@pytest.mark.asyncio
async def test_qwen_adapter_malformed_output():
    adapter = QwenAdapter()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"response": "This is plain text not valid JSON!"}

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        result = await adapter.analyze_content("Hello")
        assert result["available"] is False
        assert "Malformed model response" in result["error"]


@pytest.mark.asyncio
async def test_qwen_adapter_analyze_url_phishing():
    adapter = QwenAdapter()
    mock_json_response = {
        "response": '{"is_phishing": true, "brand_impersonated": "Chase", "credential_theft": true, "suspicion_score": 0.95, "confidence": 0.92, "key_indicators": ["Fake Chase domain", "Suspicious login path"], "threat_summary": "Phishing portal imitating Chase", "technical_reasoning": "Domain spoofs Chase brand with login endpoint to harvest credentials."}'
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_json_response

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        result = await adapter.analyze_url(
            "https://chase-security-update-verify.com/login",
            deterministic_signals={"matched_keywords": ["chase", "login"]},
            laya_signals={"laya_phishing_probability": 0.95},
        )
        assert result["available"] is True
        assert result["signals"]["qwen_is_phishing"] is True
        assert result["signals"]["qwen_brand_impersonation"] is True
        assert result["signals"]["qwen_target_brand"] == "Chase"
        assert result["signals"]["qwen_credential_intent"] is True
        assert len(result["findings"]) >= 2
        assert any("Phishing Link Confirmed" in f.title for f in result["findings"])
        assert any("Credential Theft" in f.title for f in result["findings"])
