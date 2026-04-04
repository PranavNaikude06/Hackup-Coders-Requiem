from app.services.email_nlp import EmailNLPService


def test_verdict_enum_and_schema():
    svc = EmailNLPService()
    svc._loaded = True
    svc._pipeline = None

    result = svc.analyze("Urgent: verify your account password now by clicking this link")

    assert result["verdict"] in {"SAFE", "SUSPICIOUS", "PHISHING"}
    assert isinstance(result["confidence"], float)
    assert 0.0 <= result["confidence"] <= 0.97
    assert isinstance(result["raw_confidence"], float)
    assert isinstance(result["evidence"], list)
    assert len(result["evidence"]) <= 3


def test_empty_input_controlled_response():
    svc = EmailNLPService()
    svc._loaded = True
    svc._pipeline = None

    result = svc.analyze("   ")

    assert "error" in result
    assert result["verdict"] in {"SAFE", "SUSPICIOUS", "PHISHING"}
    assert isinstance(result["evidence"], list)


def test_threshold_mapping_deterministic():
    svc = EmailNLPService()

    assert svc._map_verdict(0.2) == "SAFE"
    assert svc._map_verdict(0.6) == "SUSPICIOUS"
    assert svc._map_verdict(0.9) == "PHISHING"
