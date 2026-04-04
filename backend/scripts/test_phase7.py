"""
test_phase7.py — Phase 7 verification: Multi-Stage Chain Detection.

Tests:
  1. ChainDetector unit tests (no server needed)
  2. /analyze/combined integration tests via live API
"""
import json
import urllib.request

base = "http://127.0.0.1:8765"
PASS = "[PASS]"
FAIL = "[FAIL]"

# ── 1. ChainDetector Unit Tests ─────────────────────────────────
print("=== Phase 7 — Chain Detector Unit Tests ===")
from app.services.chain_detector import ChainDetector

detector = ChainDetector()

# Case 1: Domain IS in email (exact match)
r = detector.detect("http://paypa1.com/login", "Please click paypa1.com to verify your account.")
ok = r["chain_detected"] is True and r["matched_domain"] == "paypa1.com"
print(f"{PASS if ok else FAIL} Case 1 (chain found): chain_detected={r['chain_detected']} domain={r['matched_domain']}")

# Case 2: Domain NOT in email
r2 = detector.detect("http://paypa1.com/login", "Your shipment has arrived. Track via our website.")
ok2 = r2["chain_detected"] is False and r2["matched_domain"] is None
print(f"{PASS if ok2 else FAIL} Case 2 (no chain):   chain_detected={r2['chain_detected']} domain={r2['matched_domain']}")

# Case 3: Case-insensitive match
r3 = detector.detect("http://PayPa1.COM/verify", "Contact PAYPA1.COM for help.")
ok3 = r3["chain_detected"] is True
print(f"{PASS if ok3 else FAIL} Case 3 (case-insensitive): chain_detected={r3['chain_detected']}")

# Case 4: Flag text is correct
ok4 = r["flag"] is not None and "paypa1.com" in r["flag"] and "multi-stage" in r["flag"]
print(f"{PASS if ok4 else FAIL} Case 4 (flag text correct): flag='{r['flag']}'")

# Case 5: Empty inputs
r5 = detector.detect("", "some email text")
ok5 = r5["chain_detected"] is False
print(f"{PASS if ok5 else FAIL} Case 5 (empty URL graceful): chain_detected={r5['chain_detected']}")

# ── 2. /analyze/combined Integration Tests ──────────────────────
print("\n=== Phase 7 — API Integration Tests (/analyze/combined) ===")

def combined_request(url, email):
    data = json.dumps({"url": url, "email_text": email}).encode()
    req = urllib.request.Request(
        f"{base}/analyze/combined", data=data,
        headers={"Content-Type": "application/json"}
    )
    try:
        res = urllib.request.urlopen(req, timeout=15)
        return json.loads(res.read())
    except Exception as e:
        return {"error": str(e)}

# API Test 1: Chain detected via combined endpoint
phish_email_with_domain = "URGENT: Your account has been compromised. Visit paypa1.com immediately."
r_api1 = combined_request("http://paypa1.com/login", phish_email_with_domain)
if "error" in r_api1:
    print(f"{FAIL} API Test 1 (chain via API): {r_api1['error']}")
else:
    chain_api = r_api1.get("chain_detected", "KEY_MISSING")
    chain_flag = r_api1.get("chain_flag")
    score = r_api1.get("combined_score")
    verdict = r_api1.get("verdict")
    ok_api1 = chain_api is True
    print(f"{PASS if ok_api1 else FAIL} API Test 1 (chain detected via API): chain_detected={chain_api} score={score} verdict={verdict}")
    print(f"     chain_flag: {chain_flag}")

# API Test 2: No chain when domain not in email
safe_email = "Hi your subscription has been renewed. Thank you for being a customer."
r_api2 = combined_request("http://paypa1.com/login", safe_email)
if "error" in r_api2:
    print(f"{FAIL} API Test 2 (no chain via API): {r_api2['error']}")
else:
    chain_api2 = r_api2.get("chain_detected", "KEY_MISSING")
    ok_api2 = chain_api2 is False
    print(f"{PASS if ok_api2 else FAIL} API Test 2 (no chain via API): chain_detected={chain_api2} score={r_api2.get('combined_score')}")

# API Test 3: chain_detected key ALWAYS present in response
r_api3 = combined_request("https://github.com", "your invoice is attached")
ok_api3 = "chain_detected" in r_api3
print(f"{PASS if ok_api3 else FAIL} API Test 3 (chain_detected key always present): keys={list(r_api3.keys())[:6]}")

# API Test 4: missing email text → 400 with helpful message
try:
    data = json.dumps({"url": "http://example.com"}).encode()
    req = urllib.request.Request(f"{base}/analyze/combined", data=data, headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=5)
    print(f"{FAIL} API Test 4 (missing email_text → should 400): got 200 instead")
except urllib.error.HTTPError as e:
    ok_api4 = e.code == 400
    body = e.read().decode()
    hint = "/analyze/url" in body or "/analyze/email" in body
    print(f"{PASS if ok_api4 else FAIL} API Test 4 (400 on missing email_text): status={e.code} hint_present={hint}")
except Exception as e:
    print(f"{FAIL} API Test 4 unexpected error: {e}")

print("\n=== Done ===")
