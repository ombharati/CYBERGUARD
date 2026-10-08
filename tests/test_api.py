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


@patch("app.backend.services.scan_service.enqueue_scan_id", return_value=True)
def test_create_logs_scan_api(mock_enqueue):
    log_sample = "Jan 15 09:00:10 host sshd[101]: Failed password for admin from 10.0.0.1 port 22 ssh2"
    res = client.post(
        "/api/v1/scans",
        json={"input_type": "logs", "data": log_sample},
    )
    assert res.status_code == 201
    scan = res.json()
    assert scan["type"] == "LOGS"
    assert scan["id"].startswith("CG-")


@patch("app.backend.services.scan_service.enqueue_scan_id", return_value=True)
def test_create_identity_scan_api(mock_enqueue):
    header_sample = "From: Alice <alice@example.com>\nSubject: Test\nAuthentication-Results: spf=pass"
    res = client.post(
        "/api/v1/scans",
        json={"input_type": "identity", "data": header_sample},
    )
    assert res.status_code == 201
    scan = res.json()
    assert scan["type"] == "IDENTITY"
    assert scan["id"].startswith("CG-")


@patch("app.backend.services.scan_service.enqueue_scan_id", return_value=True)
def test_create_headers_scan_api(mock_enqueue):
    header_sample = "From: Bob <bob@example.com>\nSubject: Hello"
    res = client.post(
        "/api/v1/scans",
        json={"input_type": "headers", "data": header_sample},
    )
    assert res.status_code == 201
    scan = res.json()
    assert scan["type"] == "HEADERS"
    assert scan["id"].startswith("CG-")


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
    dash_res = client.get("/js/dashboard.js")
    assert dash_res.status_code == 200
    assert "renderCommandDashboard" in dash_res.text


def test_scan_report_download_and_preview():
    db = TestingSessionLocal()
    scan_id = generate_scan_id()
    sample_narrative = (
        "1. What was analyzed\n"
        "Input type: URL\n"
        "Target inspected: https://example.com/test\n\n"
        "2. Verdict\n"
        "Verdict: Safe (Risk Score: 15/100)\n\n"
        "3. Key findings\n"
        "No suspicious indicators detected.\n\n"
        "4. Why this verdict\n"
        "Clean identity and verified behavior.\n\n"
        "5. What was checked\n"
        "- Deterministic heuristics\n\n"
        "6. What was not checked\n"
        "- None\n\n"
        "7. Recommendation\n"
        "Safe to use."
    )
    scan = Scan(
        id=scan_id,
        input_type="url",
        target="https://example.com/test",
        raw_input="https://example.com/test",
        status="completed",
        risk_score=15,
        classification="Safe",
        summary="Clean inspection",
        explanation="No threats found.",
        signals=[],
        report_text=sample_narrative,
        report_generated_by="template",
    )
    db.add(scan)
    db.commit()
    db.close()

    # 1. Test GET /api/v1/scans/{scan_id} includes report_text
    detail_res = client.get(f"/api/v1/scans/{scan_id}")
    assert detail_res.status_code == 200
    data = detail_res.json()
    assert data["report_text"] == sample_narrative
    assert data["report_generated_by"] == "template"

    # 2. Test GET /api/v1/scans/{scan_id}/report download as text/plain
    report_res = client.get(f"/api/v1/scans/{scan_id}/report")
    assert report_res.status_code == 200
    assert "text/plain" in report_res.headers["content-type"]
    assert f'filename="cyberguard-report-{scan_id}.txt"' in report_res.headers["content-disposition"]
    assert "1. What was analyzed" in report_res.text
    assert "2. Verdict" in report_res.text
    assert "Safe to use." in report_res.text

    # 3. Test GET /api/scans/{scan_id}/report (frontend compat endpoint)
    compat_report_res = client.get(f"/api/scans/{scan_id}/report")
    assert compat_report_res.status_code == 200
    assert "text/plain" in compat_report_res.headers["content-type"]
    assert f'filename="cyberguard-report-{scan_id}.txt"' in compat_report_res.headers["content-disposition"]


@patch("app.backend.services.scan_service.enqueue_scan_id", return_value=True)
def test_idempotency_keys_deduplication(mock_enqueue):
    key = "test-idem-key-9999"
    payload = {"input_type": "url", "data": "https://example.com/idempotent"}

    # First request
    res1 = client.post("/api/v1/scans", json=payload, headers={"Idempotency-Key": key})
    assert res1.status_code == 201
    scan1 = res1.json()

    # Second request with the same Idempotency-Key
    res2 = client.post("/api/v1/scans", json=payload, headers={"Idempotency-Key": key})
    assert res2.status_code == 201
    scan2 = res2.json()

    # Must return the exact same scan ID
    assert scan1["id"] == scan2["id"]

    # Verify idempotency_keys table contains the record
    db = TestingSessionLocal()
    from app.backend.models.scan import IdempotencyKey
    record = db.query(IdempotencyKey).filter(IdempotencyKey.key == key).first()
    assert record is not None
    assert record.scan_id == scan1["id"]

    # Verify only one scan exists with this target
    scans_count = db.query(Scan).filter(Scan.target == "https://example.com/idempotent").count()
    assert scans_count == 1
    db.close()


def test_clear_scan_history():
    res = client.delete("/api/v1/scans")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "cleared"

    res_list = client.get("/api/v1/scans")
    assert res_list.status_code == 200
    assert len(res_list.json()) == 0


def test_deterministic_url_signals_in_evidence_panel():
    # 1. URL scan with lookalike domain
    res_url = client.post(
        "/api/scans",
        json={"input_type": "url", "data": "https://hdfc-bank-kyc-update.com/login/verify?customer=123"},
    )
    assert res_url.status_code == 200
    scan_url = res_url.json()
    det_findings = [f for f in scan_url["findings"] if f.get("source") == "deterministic" or f.get("category") == "deterministic_url"]
    assert len(det_findings) >= 1
    assert any("Lookalike" in f["title"] for f in det_findings)
    assert any(f.get("weight", 0) > 0 for f in det_findings)

    # 2. Content scan with embedded lookalike URL
    res_content = client.post(
        "/api/scans",
        json={"input_type": "content", "data": "Please urgently update KYC at http://paypa1-update-login.com to avoid account suspension."},
    )
    assert res_content.status_code == 200
    scan_content = res_content.json()
    content_det_findings = [f for f in scan_content["findings"] if f.get("source") == "deterministic" or f.get("category") == "deterministic_url"]
    assert len(content_det_findings) >= 1
    assert any("Lookalike" in f["title"] or "Clean" in f["title"] or "Domain" in f["title"] for f in content_det_findings)
    assert any(f.get("weight", 0) >= 0 for f in content_det_findings)

    # 3. Email scan with embedded lookalike URL
    res_email = client.post(
        "/api/scans",
        json={
            "input_type": "email",
            "data": {
                "sender": "alert@paypa1-fake.com",
                "subject": "Urgent Security Notice",
                "body": "Click here to verify: https://paypa1-update-login.com/login",
            },
        },
    )
    assert res_email.status_code == 200
    scan_email = res_email.json()
    email_det_findings = [f for f in scan_email["findings"] if f.get("source") == "deterministic" or f.get("category") == "deterministic_url"]
    assert len(email_det_findings) >= 1



