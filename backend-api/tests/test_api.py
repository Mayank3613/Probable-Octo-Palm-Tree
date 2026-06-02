import pytest
from fastapi.testclient import TestClient
from app.main import app

# Using TestClient within a context manager triggers the lifespan (startup/shutdown) events,
# which initializes the database.
@pytest.fixture
def client():
    with TestClient(app) as client:
        yield client

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_telemetry_upload(client):
    payload = {
        "events": [
            {
                "timestamp": "2026-05-28T12:00:00Z",
                "threat_type": "Phishing/Malicious URL",
                "details": "Suspicious keyword test",
                "severity": "high",
                "url": "http://example.com"
            }
        ]
    }
    response = client.post("/telemetry/upload", json=payload)
    assert response.status_code == 200
    assert response.json()["success"] == True
    assert response.json()["inserted"] == 1

def test_scan_safe_url(client):
    payload = {"url": "https://google.com"}
    response = client.post("/scan/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["url"] == "https://google.com"
    assert data["is_suspicious"] == False

def test_scan_phishing_url(client):
    payload = {"url": "http://paypa1-login-secure.com"}
    response = client.post("/scan/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_suspicious"] == True
    assert data["score"] > 0
    assert "Suspicious keyword" in data["reason"]

def test_alerts_live(client):
    response = client.get("/alerts/live")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)

def test_alerts_stats(client):
    response = client.get("/alerts/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "critical" in data
    assert "top_domains" in data
