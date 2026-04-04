import requests
import io
import sys

BASE_URL = "http://127.0.0.1:8765/analyze/attachment"

def test_unsupported_type():
    print("Testing unsupported file type (.png)...")
    files = {"file": ("test.png", b"fake file content", "image/png")}
    response = requests.post(BASE_URL, files=files)
    if response.status_code == 400 and "Unsupported file type" in response.text:
        print("[PASS] 400 Unsupported type")
        return True
    print(f"[FAIL] Expected 400 with unsupported message, got {response.status_code} - {response.text}")
    return False

def test_dangerous_extension():
    print("Testing dangerous extension (.exe)...")
    files = {"file": ("malware.exe", b"MZ fake executable", "application/x-msdownload")}
    response = requests.post(BASE_URL, files=files)
    if response.status_code == 200:
        data = response.json()
        if data.get("verdict") == "PHISHING" and data.get("attachment_score") == 100:
            findings = " ".join(data.get("findings", []))
            if "Dangerous file extension" in findings:
                print("[PASS] Dangerous extension")
                return True
    print(f"[FAIL] Expected PHISHING with 100 score, got {response.status_code} - {response.text}")
    return False

def test_dangerous_extension_and_filename():
    print("Testing dangerous extension + filename (invoice_urgent.exe)...")
    files = {"file": ("invoice_urgent.exe", b"MZ fake executable", "application/x-msdownload")}
    response = requests.post(BASE_URL, files=files)
    if response.status_code == 200:
        data = response.json()
        findings = " ".join(data.get("findings", []))
        if "Dangerous file extension" in findings and "Suspicious filename keyword" in findings:
            print("[PASS] Dangerous extension and filename finding")
            return True
    print(f"[FAIL] Expected both findings, got {response.text}")
    return False

def test_suspicious_filename_only():
    print("Testing filename finding only (invoice.pdf)...")
    # Create a dummy valid PDF (minimal valid PDF structure)
    pdf_content = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\nxref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n106\n%%EOF"
    files = {"file": ("invoice.pdf", pdf_content, "application/pdf")}
    response = requests.post(BASE_URL, files=files)
    if response.status_code == 200:
        data = response.json()
        findings = " ".join(data.get("findings", []))
        # 60 * 0.20 = 12 score if no URLs found
        if "Suspicious filename keyword" in findings and "Dangerous file extension" not in findings:
            print("[PASS] Suspicious filename only")
            return True
    print(f"[FAIL] Expected filename finding only, got {response.text}")
    return False

def run_all_tests():
    print("=== Phase 8: Attachment Analysis Tests ===")
    results = [
        test_unsupported_type(),
        test_dangerous_extension(),
        test_dangerous_extension_and_filename(),
        test_suspicious_filename_only()
    ]
    
    if all(results):
        print("\nAll Phase 8 API tests PASS.")
        sys.exit(0)
    else:
        print("\nSome tests FAILED.")
        sys.exit(1)

if __name__ == "__main__":
    try:
        # Check if server is up
        health = requests.get("http://127.0.0.1:8765/")
        if health.status_code != 200:
            print("Server is not healthy. Please start the server first.")
            sys.exit(1)
            
        run_all_tests()
    except requests.exceptions.ConnectionError:
        print("Server is down. Please run `uvicorn app.main:app`")
        sys.exit(1)
