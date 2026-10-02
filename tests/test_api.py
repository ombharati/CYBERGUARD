"""Integration and API unit tests using FastAPI TestClient with an isolated test database and mocked orchestration."""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.backend.core.database import Base, get_db
from app.backend.main import app
from app.backend.models.scan import Scan, ScanFinding, generate_scan_id

# Setup isolated in-memory SQLite database for test execution
TEST_SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
Base.metadata.create_all(bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_validation_errors_on_create_scan():
    # Invalid input_type
    res = client.post("/api/v1/scans", json={"input_type": "invalid_type", "data": "https://example.com"})
    assert res.status_code == 422  # Pydantic validation error

    # Empty data
    res2 = client.post("/api/v1/scans", json={"input_type": "url", "data": "   "})
    assert res2.status_code == 422


@patch("app.backend.services.scan_service.enqueue_scan_id", return_value=True)
def test_create_and_get_scan_v1(mock_enqueue):
    res = client.post(
        "/api/v1/scans",
        json={"input_type": "url", "data": "https://example.com/test"},
    )
    assert res.status_code == 201
    scan = res.json()
    assert scan["id"].startswith("CG-")
    assert scan["type"] == "URL"
    assert scan["status"] == "queued"

    # Get scan by ID
    get_res = client.get(f"/api/v1/scans/{scan['id']}")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == scan["id"]


def test_get_nonexistent_scan():
    res = client.get("/api/v1/scans/CG-NONEXISTENT")
    assert res.status_code == 404


def test_frontend_compat_scan():
    async def mock_execute(db, scan_id):
        s = db.query(Scan).filter(Scan.id == scan_id).first()
        s.status = "completed"
        s.risk_score = 25
        s.classification = "Safe"
        s.summary = "Mocked clean inspection"
        s.explanation = "No threats found in test."
        s.signals = [{"name": "Pattern analysis", "value": 25}]
        finding = ScanFinding(scan_id=s.id, severity="low", title="Test Clean", description="OK")
        db.add(finding)
        db.commit()
        db.refresh(s)
        return s

    with patch("app.backend.services.orchestrator.ScanOrchestrator.execute_scan", side_effect=mock_execute):
        # Frontend compatibility route executes synchronously
        res = client.post(
            "/api/scans",
            json={"input_type": "url", "data": "https://example.com"},
        )
        assert res.status_code == 200
        scan = res.json()
        assert scan["id"].startswith("CG-")
        assert scan["classification"] == "Safe"
        assert len(scan["signals"]) == 1
        assert len(scan["findings"]) >= 1

        # Frontend history route
        history_res = client.get("/api/scans")
        assert history_res.status_code == 200
        history = history_res.json()
        assert isinstance(history, list)
        assert len(history) >= 1


def test_frontend_static_serving():
    res = client.get("/")
    assert res.status_code == 200
    assert "CYBERGUARD" in res.text or "<!DOCTYPE html>" in res.text
