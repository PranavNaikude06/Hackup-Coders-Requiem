import requests
import json
import time

payload = {
    "url": "http://secure-update-paypal-login.verify-user-account.com/login",
    "email_text": "Dear Customer,\n\nWe detected unusual activity in your bank account. Your account will be suspended within 24 hours unless you verify your details immediately.\n\nClick here to secure your account:\nhttp://secure-bank-login.xyz/verify\n\nFailure to act will result in permanent suspension.\n\nRegards,\nBank Security Team"
}

print("Initiating SSE Stream...\n")
start_time = time.time()

with requests.post("http://127.0.0.1:8765/analyze/stream", json=payload, stream=True) as r:
    for line in r.iter_lines():
        if line:
            line_str = line.decode('utf-8')
            if line_str.startswith("event: "):
                event = line_str[7:]
                print(f"[{time.time() - start_time:.2f}s] Event: {event}")
            if line_str.startswith("data: "):
                data_str = line_str[6:]
                data = json.loads(data_str)
                # Print a summary of the data based on the stage
                if data.get("stage") == "url_scan":
                    print(f"  -> risk_flag: {data.get('risk_flag')}, confidence: {data.get('confidence')}")
                elif data.get("stage") == "email_scan":
                    print(f"  -> verdict: {data.get('email_verdict')}, chain: {data.get('chain_detected')}, mismatch: {data.get('mismatch_detected')}")
                elif data.get("stage") == "final":
                    print(f"  -> provider: {data.get('analysis_provider')}, verdict: {data.get('verdict')}, score: {data.get('combined_score')}")
                    print(f"  -> explanation: {data.get('llm_human_explanation')}")
                elif data.get("message") == "Analysis complete":
                    print("  -> Analysis complete!")
                
                print()
