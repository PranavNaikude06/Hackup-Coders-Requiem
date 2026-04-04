import json
from app.services.feature_extractor import URLFeatureExtractor
from app.services.model_runner import ModelRunner

extractor = URLFeatureExtractor()
runner = ModelRunner()

def test_url(url):
    print(f"\n{'='*60}")
    print(f"URL: {url}")
    print(f"{'='*60}")
    features = extractor.extract(url)
    res = runner.predict(features)
    print(f"Risk Flag  : {res.get('risk_flag')}")
    print(f"Pred Code  : {res.get('prediction_code')}")
    if res.get('brand_impersonation'):
        print(f"Impersonates: {res['brand_impersonation']}")
    print(f"Verdicts:")
    for v in res.get('verdicts', []):
        print(f"  >> {v}")

print("=== ThreatLens URL Analysis Engine - Test Suite ===\n")

# Safe URLs
test_url("https://www.google.com")
test_url("https://github.com")

# Phishing URLs
test_url("http://paypa1.com")
test_url("http://secure-login-update-paypal.tk/login_auth")
test_url("http://bit.ly/123xyz")
test_url("http://g00gle.com")
test_url("http://amaz0n-security.com/verify")
