import sqlite3

import pytest
from fastapi.testclient import TestClient

from app import config
from app.database.connection import initialize_database
from app.main import app
from app.services.abuse_protection import hash_client_ip, reset_rate_limits


@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test_phishshield.db"
    monkeypatch.setattr(config, "DATABASE_PATH", str(db_path))
    monkeypatch.setattr(config, "RATE_LIMIT_PER_MINUTE", 10)
    monkeypatch.setattr(config, "ENABLE_LLM_EXPLANATIONS", False)
    monkeypatch.setattr(config, "IP_HASH_SALT", "test-secret-salt")
    reset_rate_limits()
    initialize_database()
    with TestClient(app) as test_client:
        yield test_client, db_path
    reset_rate_limits()


def test_health_endpoint(client):
    test_client, _ = client
    response = test_client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_cors_allows_chrome_extension_origin(client):
    test_client, _ = client
    origin = "chrome-extension://abcdefghijklmnop"
    res = test_client.options(
        "/api/scan",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert res.status_code == 200
    assert res.headers.get("access-control-allow-origin") == origin


def test_scan_safe_and_dangerous_urls_with_ml_signal(client):
    test_client, db_path = client
    safe_res = test_client.post("/api/scan", json={"content": "https://www.example.com", "language": "en"})
    assert safe_res.status_code == 200
    safe_body = safe_res.json()
    assert safe_body["risk_level"] == "Low Risk"
    assert safe_body["content_type"] == "url"
    assert len(safe_body["scan_reference"]) == 12
    assert safe_body["ml_probability"] is not None
    assert 0.0 <= safe_body["ml_probability"] <= 1.0

    danger_res = test_client.post("/api/scan", json={"content": "http://198.51.100.42/verify", "language": "en"})
    assert danger_res.status_code == 200
    danger_body = danger_res.json()
    assert danger_body["risk_level"] == "Dangerous"
    assert danger_body["risk_score"] >= 60
    assert danger_body["ml_probability"] is not None

    with sqlite3.connect(db_path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    assert count == 2


def test_scan_hindi_fallback_and_validation(client):
    test_client, _ = client
    hi_res = test_client.post(
        "/api/scan",
        json={"content": "Urgent: share your OTP today to verify your KYC", "language": "hi"},
    )
    assert hi_res.status_code == 200
    body = hi_res.json()
    assert body["risk_level"] == "Dangerous"
    assert "खतरनाक" in body["explanation"]

    bad_res = test_client.post("/api/scan", json={"content": "hi", "language": "en"})
    assert bad_res.status_code == 422

    ipv6_res = test_client.post("/api/scan", json={"content": "http://[invalid-ipv6/login", "language": "en"})
    assert ipv6_res.status_code == 200
    assert ipv6_res.json()["risk_score"] >= 25


def test_rate_limit_logs_salted_hash_and_returns_429(client):
    test_client, db_path = client
    for _ in range(10):
        res = test_client.post("/api/scan", json={"content": "https://www.example.com", "language": "en"})
        assert res.status_code == 200

    blocked = test_client.post("/api/scan", json={"content": "https://www.example.com", "language": "en"})
    assert blocked.status_code == 429
    assert "Too many scan requests" in blocked.json()["detail"]

    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT client_hash, event_type, request_count, action_taken FROM security_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
    assert row is not None
    assert row[0] == hash_client_ip("testclient")
    assert row[1] == "rate_limit"
    assert row[2] == 11
    assert row[3] == "blocked_for_60_seconds"


def test_campaign_detection_flags_repeated_domain_and_similar_messages(client):
    test_client, db_path = client
    for idx in range(3):
        res = test_client.post(
            "/api/scan",
            json={
                "content": f"Urgent KYC update needed today share OTP {100 + idx} at http://198.51.100.42/login",
                "language": "en",
            },
        )
        assert res.status_code == 200
        body = res.json()

    assert body["campaign_detected"] is True
    assert any("Campaign pattern detected" in reason for reason in body["reasons"])

    with sqlite3.connect(db_path) as conn:
        events = [
            row[0]
            for row in conn.execute("SELECT event_type FROM security_events").fetchall()
        ]
    assert "campaign_domain" in events
    assert "campaign_message" in events
