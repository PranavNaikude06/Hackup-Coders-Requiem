"""
ThreatLens v1.0 Audit Script
Tests all Phase 1-5 components without live network calls.
"""
from app.services.model_runner import ModelRunner
from app.core.homograph_detector import HomographDetector
from app.services.email_nlp import EmailNLPService

runner = ModelRunner()
detector = HomographDetector()

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"

results = []

def check(label, got, expected_list, note=""):
    status = PASS if got in expected_list else FAIL
    results.append((status, label, got, expected_list, note))

# ── Homograph Detector ────────────────────────────────────────────
print("\n=== PHASE 1 / CORE — Homograph Detector ===")

lk1 = detector.check_similarity("paypa1.com")
check("paypa1.com detected", lk1["is_lookalike"], [True], "paypal homoglyph")
check("paypa1.com brand", lk1.get("matched_brand"), ["paypal"])

lk2 = detector.check_similarity("g00gle.com")
check("g00gle.com detected", lk2["is_lookalike"], [True], "google homoglyph")
check("g00gle.com brand", lk2.get("matched_brand"), ["google"])

lk3 = detector.check_similarity("amaz0n-security.com")
check("amaz0n-security detected", lk3["is_lookalike"], [True], "amazon brand embed")
check("amaz0n-security brand", lk3.get("matched_brand"), ["amazon"])

lk4 = detector.check_similarity("github.com")
check("github.com NOT flagged", lk4["is_lookalike"], [False], "real domain, no brand match")

for s, label, got, exp, note in results[-4:] + results[:2]:
    print(f"  [{s}] {label}: {got}  (note: {note})")

# ── Model Runner ────────────────────────────────────────────────
print("\n=== PHASE 2/4 — Model Runner (no network) ===")

def base_features():
    return {k: -1 for k in [
        "having_IP_Address","URL_Length","Shortining_Service","having_At_Symbol",
        "double_slash_redirecting","Prefix_Suffix","having_Sub_Domain","SSLfinal_State",
        "Domain_registeration_length","Favicon","port","HTTPS_token","Request_URL",
        "URL_of_Anchor","Links_in_tags","SFH","Submitting_to_email","Abnormal_URL",
        "Redirect","on_mouseover","RightClick","popUpWidnow","Iframe","age_of_domain",
        "DNSRecord","web_traffic","Page_Rank","Google_Index","Links_pointing_to_page",
        "Statistical_report","_whois_lookup_failed"
    ]}

model_results = []

# T1 - clean HTTPS domain
f = base_features()
f["_lookalike"] = {"is_lookalike": False}
r = runner.predict(f)
flag = r.get("risk_flag")
model_results.append(("clean HTTPS", flag, ["SAFE"]))

# T2 - IP address + no SSL → must be HIGH_RISK or SUSPICIOUS
f = base_features()
f["_lookalike"] = {"is_lookalike": False}
f["having_IP_Address"] = 1
f["SSLfinal_State"] = 1
r = runner.predict(f)
model_results.append(("IP + no SSL", r.get("risk_flag"), ["HIGH_RISK", "SUSPICIOUS"]))

# T3 - homograph paypal
f = base_features()
f["_lookalike"] = {"is_lookalike": True, "similarity": 1.0, "matched_brand": "paypal"}
f["SSLfinal_State"] = 1
r = runner.predict(f)
model_results.append(("paypa1 homograph", r.get("risk_flag"), ["HIGH_RISK"]))

# T4 - DNS unresolvable + no SSL + clone → HIGH_RISK
f = base_features()
f["_lookalike"] = {"is_lookalike": True, "similarity": 0.95, "matched_brand": "amazon"}
f["SSLfinal_State"] = 1
f["DNSRecord"] = 1
r = runner.predict(f)
model_results.append(("amaz0n brand embed", r.get("risk_flag"), ["HIGH_RISK"]))

# T5 - verdict lines exist
f = base_features()
f["_lookalike"] = {"is_lookalike": True, "similarity": 1.0, "matched_brand": "paypal"}
f["SSLfinal_State"] = 1
r = runner.predict(f)
verdicts = r.get("verdicts", [])
humanized = r.get("humanized_verdict", {})
model_results.append(("verdicts non-empty", bool(verdicts), [True]))
model_results.append(("humanized summary exists", bool(humanized.get("summary")), [True]))
model_results.append(("confidence capped at max 97%", r.get("confidence", 0) <= 0.97, [True]))

for label, got, exp in model_results:
    status = PASS if got in exp else FAIL
    print(f"  [{status}] {label}: {got}  (expected: {exp})")

# ── Email NLP ──────────────────────────────────────────────────
print("\n=== PHASE 3 — Email NLP (DistilBERT) ===")
svc = EmailNLPService()
svc.preload()

ea1 = svc.analyze("Urgent! Your account has been suspended. Verify your password now or it will be deleted permanently.")
print(f"  Phishing email -> verdict={ea1['verdict']}  conf={ea1['confidence']}")
print(f"  Evidence: {ea1['evidence']}")
print(f"  Model provider: {ea1['model'].get('provider')}")
e1_ok = ea1["verdict"] in ["PHISHING", "SUSPICIOUS"]
print(f"  [{PASS if e1_ok else FAIL}] Phishing email correctly flagged as {ea1['verdict']}")

ea2 = svc.analyze("Hi there, your package has shipped. Tracking: TRK12345. Expected delivery: Friday.")
print(f"\n  Benign email   -> verdict={ea2['verdict']}  conf={ea2['confidence']}")
e2_ok = ea2["verdict"] == "SAFE"
print(f"  [{PASS if e2_ok else WARN}] Benign email verdict: {ea2['verdict']}  (WARN if not SAFE)")

# ── Summary ────────────────────────────────────────────────────
print("\n=== AUDIT SUMMARY ===")
passed = sum(1 for s,*_ in results if s == PASS) + sum(1 for l,g,e in model_results if g in e) + int(e1_ok) + int(e2_ok)
total = len(results) + len(model_results) + 2
print(f"  {passed}/{total} checks passed")

known_issues = []
# Check amaz0n-security false negative at model level (without brand embed)
f = base_features()
f["_lookalike"] = {"is_lookalike": False}  # as if detector missed it
f["SSLfinal_State"] = 1
f["DNSRecord"] = 1
f["Prefix_Suffix"] = 1
r = runner.predict(f)
if r.get("risk_flag") == "SAFE":
    known_issues.append("FIX-01 NEEDED: keyword phishing URL (no brand embed) still returns SAFE — to be fixed in Phase 6")

if known_issues:
    print("\n  Known issues (to fix in v2.0):")
    for i in known_issues:
        print(f"    [!] {i}")
else:
    print("  No known issues.")
