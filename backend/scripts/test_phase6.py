import json
import urllib.request

base = "http://127.0.0.1:8765"

print("=== Phase 6 Tests: Combined Scoring & Keyword Fix ===")

def test_url(url, expect_risk="SUSPICIOUS"):
    print(f"\n--- URL: {url} ---")
    data = json.dumps({"url": url}).encode()
    req = urllib.request.Request(f"{base}/analyze/url", data=data, headers={"Content-Type": "application/json"})
    try:
        res = urllib.request.urlopen(req, timeout=10)
        r = json.loads(res.read())
        ma = r.get("model_analysis", {})
        risk = ma.get("risk_flag")
        conf = ma.get("confidence")
        print(f"Risk: {risk} | Confidence: {conf}")
        if risk in [expect_risk, "HIGH_RISK"]:
            print("PASS (Fix-01 Works)")
        else:
            print("FAIL (Should not be SAFE)")
    except Exception as e:
        print(f"URL Test Failed: {e}")

def test_combined(url, email, name):
    print(f"\n--- Combined: {name} ---")
    data = json.dumps({"url": url, "email_text": email}).encode()
    req = urllib.request.Request(f"{base}/analyze/combined", data=data, headers={"Content-Type": "application/json"})
    try:
        res = urllib.request.urlopen(req, timeout=15)
        r = json.loads(res.read())
        score = r.get("combined_score")
        verdict = r.get("verdict")
        b = r.get("breakdown", {})
        url_raw = b.get("raw_url_score")
        email_raw = b.get("raw_email_score")
        rule_raw = b.get("raw_rule_score")
        print(f"Final Score: {score} ({verdict})")
        print(f"URL: {url_raw} | Email: {email_raw} | Rule: {rule_raw}")
        print("Flags:", len(r.get("flags", [])))
        
        # Verify Math
        expected_score = round(url_raw * 0.4 + email_raw * 0.4 + rule_raw * 0.2)
        if score == expected_score:
            print(f"PASS (Math check ok: {url_raw}*0.4 + {email_raw}*0.4 + {rule_raw}*0.2 = {expected_score})")
        else:
            print(f"FAIL Math check: expected {expected_score}, got {score}")
            
    except Exception as e:
        print(f"Combined Test Failed: {e}")


# 1. Test the false negative fix
test_url("http://amaz0n-security.com/verify")
test_url("http://secure-login-update-paypal.tk/login_auth")

# 2. Test Combined Endpoint
safe_email = "Hi team, please find the meeting notes attached."
phish_email = "URGENT: Verify your account immediately or it will be suspended forever."

test_combined("https://github.com/login", safe_email, "Safe URL + Safe Email")
test_combined("http://paypa1.com/login", phish_email, "Obvious Phish URL + Obvious Phish Email")
test_combined("http://amaz0n-security.com", phish_email, "Sneaky URL + Obvious Phish Email")

print("\n--- Done ---")
