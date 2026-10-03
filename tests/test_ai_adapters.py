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
        "response": (
            '{\n'
            '  "reasoning": "Checked identity: claims Security Dept but sender is untrusted. Behavior: asks user to click and verify password urgently. Request: asking for password is an illegitimate request.",\n'
            '  "observations": [\n'
            '    {\n'
            '      "what": "Solicitation of account password",\n'
            '      "why_it_matters": "Real services never solicit user passwords directly.",\n'
            '      "strength": "strong"\n'
            '    },\n'
            '    {\n'
            '      "what": "High urgency language",\n'
            '      "why_it_matters": "Pressures victim to bypass standard safety precautions.",\n'
            '      "strength": "moderate"\n'
            '    }\n'
            '  ],\n'
            '  "legitimate_explanations": ["None found for password solicitation."],\n'
            '  "verdict": "likely_phishing",\n'
            '  "what_would_change_my_mind": "If verified this is internal security team test."\n'
            '}'
        )
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_json_response

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp):
        result = await adapter.analyze_content("Please verify your account password immediately.")
        assert result["available"] is True
        assert result["signals"]["qwen_is_phishing"] is True
        assert result["signals"]["qwen_verdict"] == "likely_phishing"
        assert result["signals"]["qwen_strong_observations"] >= 1
        assert len(result["findings"]) == 2
        assert any("password" in f.title.lower() for f in result["findings"])


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
        "response": (
            '{\n'
            '  "reasoning": "Identity mismatch: URL uses chase-security-update-verify.com rather than official chase.com. Sensitive path /login on an unauthorized lookalike domain indicates high risk credential harvesting.",\n'
            '  "observations": [\n'
            '    {\n'
            '      "what": "Unauthorized lookalike domain targeting Chase",\n'
            '      "why_it_matters": "Official brand domain is chase.com.",\n'
            '      "strength": "strong"\n'
            '    },\n'
            '    {\n'
            '      "what": "Credential harvesting /login endpoint on untrusted domain",\n'
            '      "why_it_matters": "Neutral on official domain, but on lookalike domain indicates credential theft.",\n'
            '      "strength": "strong"\n'
            '    }\n'
            '  ],\n'
            '  "legitimate_explanations": ["None found. Legitimate Chase login requires chase.com."],\n'
            '  "verdict": "likely_phishing",\n'
            '  "what_would_change_my_mind": "If the domain resolves to official chase.com."\n'
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
        assert result["signals"]["qwen_is_phishing"] is True
        assert result["signals"]["qwen_verdict"] == "likely_phishing"
        assert result["signals"]["qwen_strong_observations"] == 2
        assert len(result["findings"]) == 2
        assert any("lookalike domain" in f.title.lower() for f in result["findings"])
