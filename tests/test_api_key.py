import pytest
from fastapi.testclient import TestClient
from app.backend.main import app
from app.backend.core.config import settings

client = TestClient(app)

@pytest.fixture
def auth_disabled():
    original = settings.API_KEY
    settings.API_KEY = ""
    yield
    settings.API_KEY = original

@pytest.fixture
def auth_enabled():
    original = settings.API_KEY
    settings.API_KEY = "testsecret"
    yield
    settings.API_KEY = original

def test_auth_enabled_no_header(auth_enabled):
    # Should block API route
    response = client.get("/api/v1/scans")
    assert response.status_code == 401
    assert response.json()["detail"] == "Missing API key"

def test_auth_enabled_correct_header(auth_enabled):
    # We test with a dummy endpoint or GET /api/v1/scans which may return 200 if valid
    response = client.get("/api/v1/scans", headers={"X-API-Key": "testsecret"})
    assert response.status_code == 200

def test_auth_enabled_wrong_header(auth_enabled):
    response = client.get("/api/v1/scans", headers={"X-API-Key": "wrong"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid API key"

def test_auth_disabled_no_header(auth_disabled):
    response = client.get("/api/v1/scans")
    assert response.status_code == 200

def test_health_exempt(auth_enabled):
    # Even with auth enabled and no header, health should return 200
    response = client.get("/health")
    assert response.status_code == 200
