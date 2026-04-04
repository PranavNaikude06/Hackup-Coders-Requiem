import requests
import io
import sys
import docx

BASE_URL = "http://127.0.0.1:8765"

def test_email_nlp_exact_sentence():
    print("Testing /analyze/combined for exact sentence evidence extraction...")
    payload = {
        "url": "https://google.com/", 
        "email_text": "Hello user, verify your account immediately. Or we will suspend it."
    }
    response = requests.post(f"{BASE_URL}/analyze/combined", json=payload)
    if response.status_code == 200:
        data = response.json()
        flags = " ".join(data.get("flags", []))
        if "verify your account immediately" in flags and "Suspicious phrasing detected:" in flags:
            print("[PASS] Exact sentence extraction for email_nlp working.")
            return True
        else:
            print(f"[FAIL] Exact sentence not found in flags: {flags}")
            return False
    print(f"[FAIL] HTTP {response.status_code}: {response.text}")
    return False

def test_text_analyzer_attachment():
    print("Testing /analyze/attachment text extraction & roberta-spam analysis...")
    doc = docx.Document()
    doc.add_paragraph("You have won one million dollars cash! Send us your banking details to claim your money now.")
    
    file_stream = io.BytesIO()
    doc.save(file_stream)
    file_bytes = file_stream.getvalue()
    
    files = {"file": ("spam_letter.docx", file_bytes, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")}
    response = requests.post(f"{BASE_URL}/analyze/attachment", files=files)
    
    if response.status_code == 200:
        data = response.json()
        findings = " ".join(data.get("findings", []))
        breakdown = data.get("breakdown", {})
        
        # We expect text_score to be > 0 and verdict to be affected
        if "Document content flagged as" in findings and breakdown.get("text_score", 0) > 0:
            print(f"[PASS] Attachment text extracted and evaluated by TextAnalyzer (Text Score Check: {breakdown['text_score']}).")
            return True
        else:
            print(f"[FAIL] TextAnalyzer failed or text not extracted. Breakdown: {breakdown}")
            return False
    print(f"[FAIL] HTTP {response.status_code}: {response.text}")
    return False

def run_all_tests():
    print("=== Phase 9: Modification in Analyzers Tests ===")
    results = [
        test_email_nlp_exact_sentence(),
        test_text_analyzer_attachment()
    ]
    
    if all(results):
        print("\nAll Phase 9 API tests PASS.")
        sys.exit(0)
    else:
        print("\nSome tests FAILED.")
        sys.exit(1)

if __name__ == "__main__":
    try:
        health = requests.get(f"{BASE_URL}/")
        if health.status_code != 200:
            print("Server is not healthy.")
            sys.exit(1)
        run_all_tests()
    except requests.exceptions.ConnectionError:
        print("Server is down. Please run `uvicorn app.main:app`")
        sys.exit(1)
