import pytest
import asyncio
from app.backend.services.risk_engine import RiskEngine
from app.backend.schemas.scan import FindingResponse

def test_two_high_signals_produce_high_score():
    findings = [
        FindingResponse(severity="high", title="First high", description="Test", category="test", weight=35),
        FindingResponse(severity="high", title="Second high", description="Test", category="test", weight=35)
    ]
    assessment = RiskEngine.calculate_risk("logs", "test", {}, {}, {}, {}, findings)
    assert assessment.score >= 61
    assert assessment.classification in ("High", "Critical")

def test_high_and_successful_after_failures_produce_critical():
    findings = [
        FindingResponse(severity="high", title="Some high finding", description="Test", category="test", weight=30),
        FindingResponse(severity="high", title="Successful login after repeated failures", description="Test", category="test", weight=35)
    ]
    assessment = RiskEngine.calculate_risk("logs", "test", {}, {}, {}, {}, findings)
    assert assessment.score >= 81
    assert assessment.classification == "Critical"

def test_contribution_sum_equals_score_no_cap():
    findings = [
        FindingResponse(severity="medium", title="Medium finding", description="Test", category="test", weight=30),
        FindingResponse(severity="low", title="Low finding", description="Test", category="test", weight=20)
    ]
    assessment = RiskEngine.calculate_risk("logs", "test", {}, {}, {}, {}, findings)
    assert assessment.score == 50
    assert assessment.meta["raw_sum"] == 50

def test_score_cap_shows_cap_value():
    findings = [
        FindingResponse(severity="high", title="High finding 1", description="Test", category="test", weight=40),
        FindingResponse(severity="high", title="High finding 2", description="Test", category="test", weight=40),
        FindingResponse(severity="high", title="High finding 3", description="Test", category="test", weight=40)
    ]
    assessment = RiskEngine.calculate_risk("logs", "test", {}, {}, {}, {}, findings)
    assert assessment.meta["raw_sum"] == 120
    assert assessment.score == 98
    assert assessment.meta["raw_sum"] != assessment.score

def test_headline_text_matches_score_tier():
    def get_headline(classification):
        if classification == "Critical":
            return "Critical threat — immediate response recommended."
        elif classification == "High":
            return "High-risk activity — likely threat."
        elif classification in ("Medium", "Suspicious"):
            return "Suspicious indicators — worth reviewing."
        elif classification == "Low":
            return "Minor indicators — likely benign."
        return "No significant indicators detected."
        
    assert get_headline("Critical") == "Critical threat — immediate response recommended."
    assert get_headline("High") == "High-risk activity — likely threat."
    assert get_headline("Medium") == "Suspicious indicators — worth reviewing."
    assert get_headline("Low") == "Minor indicators — likely benign."
    assert get_headline("Safe") == "No significant indicators detected."

def test_recommendations_count_within_tier_range():
    from app.backend.services.recommendation import get_recommended_actions
    
    actions = get_recommended_actions("Critical", None, "logs", ["Test action 1", "Test action 2", "Test action 3", "Test action 4", "Test action 5", "Test action 6", "Test action 7", "Test action 8", "Test action 9"])
    assert len(actions) <= 8
    
    actions = get_recommended_actions("Medium", None, "logs", ["Test action 1", "Test action 2", "Test action 3", "Test action 4"])
    assert len(actions) <= 3
    
    actions = get_recommended_actions("Safe", None, "logs", ["Test action 1", "Test action 2"])
    assert len(actions) <= 1

def test_qwen_prompt_truncation_for_large_log(caplog, monkeypatch):
    import logging
    from app.backend.services.ai.qwen_adapter import QwenAdapter
    
    caplog.set_level(logging.INFO)
    adapter = QwenAdapter()
    
    # Mock _query_qwen to just return an empty dict and avoid real ollama call
    async def mock_query(*args, **kwargs):
        return {"reasoning": "ok", "observations": [], "verdict": "benign", "confidence": 100}
    
    monkeypatch.setattr(adapter, "_query_qwen", mock_query)
    
    large_log = "Line\n" * 1000
    
    async def run_test():
        await adapter.analyze_content(large_log)
    
    asyncio.run(run_test())
    
    assert any("Truncating input from 1000 lines" in record.message for record in caplog.records)
