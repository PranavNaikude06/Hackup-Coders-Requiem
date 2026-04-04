from fastapi.testclient import TestClient

from app.main import app
from app.api import routes


class StubEmailService:
    def analyze(self, email_text: str):
        if not email_text.strip():
            return {
                "error": "email_text must not be empty",
                "verdict": "SUSPICIOUS",
                "confidence": 0.55,
                "raw_confidence": 0.55,
                "evidence": ["empty content provided"],
                "model": {"provider": "validation"},
            }
        return {
            "verdict": "PHISHING",
            "confidence": 0.97,
            "raw_confidence": 0.99,
            "evidence": ["credential request language detected"],
            "model": {"provider": "stub"},
        }


def setup_module():
    routes.set_email_service(StubEmailService())


def test_analyze_email_happy_path():
    client = TestClient(app)
    response = client.post("/analyze/email", json={"email_text": "Please verify your password urgently."})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert "email_analysis" in body
    assert body["email_analysis"]["verdict"] in {"SAFE", "SUSPICIOUS", "PHISHING"}
    assert isinstance(body["email_analysis"]["confidence"], float)
    assert isinstance(body["email_analysis"]["evidence"], list)


def test_analyze_email_empty_text_validation():
    client = TestClient(app)
    response = client.post("/analyze/email", json={"email_text": "   "})

    assert response.status_code == 422


def test_analyze_email_requires_field():
    client = TestClient(app)
    response = client.post("/analyze/email", json={})

    assert response.status_code == 422


def test_analyze_email_plain_text_body():
    client = TestClient(app)
    response = client.post(
        "/analyze/email",
        content="Urgent: verify your account now.",
        headers={"content-type": "text/plain"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["email_analysis"]["verdict"] in {"SAFE", "SUSPICIOUS", "PHISHING"}
