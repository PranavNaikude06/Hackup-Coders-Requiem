import requests
import json
import time

payload1 = {
    "url": "http://secure-update-paypal-login.verify-user-account.com/login",
    "email_text": "Dear Customer,\n\nWe detected unusual activity in your bank account. Your account will be suspended within 24 hours unless you verify your details immediately.\n\nClick here to secure your account:\nhttp://secure-bank-login.xyz/verify\n\nFailure to act will result in permanent suspension.\n\nRegards,\nBank Security Team"
}

payload2 = {
    "url": "http://secure-update-paypal-login.verify-user-account.com/login?token=abc",
    "email_text": "Dear Pranav,\n\nWe detected unusual activity in your bank account today. Your account might be suspended within 24 hours unless you verify your details immediately.\n\nClick here to secure your account:\nhttp://secure-bank-login.xyz/verify\n\nFailure to act will result in permanent suspension.\n\nRegards,\nBank IT Team"
}

print("== Sending Phishing Attempt 1 ==")
start = time.time()
r1 = requests.post("http://127.0.0.1:8765/analyze/combined", json=payload1)
d1 = r1.json()
print("Verdict:", d1.get("verdict"))
print("Campaign:", json.dumps(d1.get("campaign"), indent=2))
print("Time:", time.time() - start)

print("\n== Sending Variant Phishing Attempt 2 ==")
start = time.time()
r2 = requests.post("http://127.0.0.1:8765/analyze/combined", json=payload2)
d2 = r2.json()
print("Verdict:", d2.get("verdict"))
print("Campaign:", json.dumps(d2.get("campaign"), indent=2))
print("Time:", time.time() - start)
