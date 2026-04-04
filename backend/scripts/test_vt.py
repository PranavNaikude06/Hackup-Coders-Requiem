import requests
import json

# EICAR test string - standard harmless file that ALL antiviruses flag as malware
eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

print("Testing dynamic sandbox analysis via VirusTotal Endpoint...\n")

files = {
    'file': ('eicar.exe', eicar_bytes, 'application/octet-stream')
}

r = requests.post("http://127.0.0.1:8765/analyze/attachment", files=files)
data = r.json()

print(f"Status Code : {r.status_code}")
print(f"Verdict     : {data.get('verdict')}")
print(f"VT Score    : {data.get('breakdown', {}).get('virustotal_cloud_score')}")
print("\n--- Findings ---")
for f in data.get('findings', []):
    print(f"  - {f}")

print("\n--- VirusTotal Stats ---")
print(json.dumps(data.get('virustotal'), indent=2))
