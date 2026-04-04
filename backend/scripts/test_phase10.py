"""
test_phase10.py — Phase 10: VirusTotal Dynamic Analysis
Tests all VT integration paths with mocked HTTP responses. No live network calls.
"""
import asyncio
import hashlib
import io
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.services.attachment_analyzer import AttachmentAnalyzer
from app.services.feature_extractor import URLFeatureExtractor
from app.services.model_runner import ModelRunner


def make_analyzer():
    return AttachmentAnalyzer(
        url_extractor=URLFeatureExtractor(),
        model_runner=ModelRunner(),
        text_analyzer=None,
    )


def make_vt_response(status_code: int, body: dict) -> MagicMock:
    m = MagicMock()
    m.status_code = status_code
    m.json.return_value = body
    return m


# ---------------------------------------------------------------------------
# Test 1: Missing API key
# ---------------------------------------------------------------------------
class TestVTMissingKey(unittest.IsolatedAsyncioTestCase):
    async def test_missing_api_key_returns_score_zero(self):
        """When VIRUSTOTAL_API_KEY is absent, vt_score must be 0 and finding says 'not configured'."""
        env = {k: v for k, v in os.environ.items() if k != "VIRUSTOTAL_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            analyzer = make_analyzer()
            vt_score, findings, meta = await analyzer._run_virustotal_analysis(b"dummy", "test.pdf")

        self.assertEqual(vt_score, 0, f"Expected score 0, got {vt_score}")
        self.assertFalse(meta["active"])
        self.assertTrue(
            any("not configured" in f for f in findings),
            f"Expected 'not configured' in findings: {findings}",
        )


# ---------------------------------------------------------------------------
# Test 2: Known hash — clean file
# ---------------------------------------------------------------------------
class TestVTHashHitClean(unittest.IsolatedAsyncioTestCase):
    async def test_known_hash_clean_returns_score_zero(self):
        """200 with 0 malicious/suspicious → vt_score = 0 and finding mentions 'Clean'."""
        clean_resp = make_vt_response(200, {
            "data": {"attributes": {"last_analysis_stats": {
                "malicious": 0, "suspicious": 0, "undetected": 70, "harmless": 0,
            }}}
        })
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test_key"}):
            with patch("app.services.attachment_analyzer.requests.get", return_value=clean_resp):
                analyzer = make_analyzer()
                vt_score, findings, meta = await analyzer._run_virustotal_analysis(b"clean", "clean.pdf")

        self.assertEqual(vt_score, 0, f"Expected 0, got {vt_score}")
        self.assertTrue(
            any("Clean" in f or "0 engines" in f for f in findings),
            f"Expected clean finding: {findings}",
        )


# ---------------------------------------------------------------------------
# Test 3: Known hash — 3 malicious engines → score 100
# ---------------------------------------------------------------------------
class TestVTHashHitMalicious(unittest.IsolatedAsyncioTestCase):
    async def test_known_hash_3_malicious_returns_score_100(self):
        """200 with malicious=3 → vt_score = 100."""
        malicious_resp = make_vt_response(200, {
            "data": {"attributes": {"last_analysis_stats": {
                "malicious": 3, "suspicious": 1, "undetected": 65, "harmless": 0,
            }}}
        })
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test_key"}):
            with patch("app.services.attachment_analyzer.requests.get", return_value=malicious_resp):
                analyzer = make_analyzer()
                vt_score, _, _ = await analyzer._run_virustotal_analysis(b"malware", "evil.exe")

        self.assertEqual(vt_score, 100, f"Expected 100, got {vt_score}")


# ---------------------------------------------------------------------------
# Test 4: Known hash — 1 malicious engine → score 85
# ---------------------------------------------------------------------------
class TestVTHashHitOneMalicious(unittest.IsolatedAsyncioTestCase):
    async def test_known_hash_1_malicious_returns_score_85(self):
        """200 with malicious=1 → vt_score = 85."""
        resp = make_vt_response(200, {
            "data": {"attributes": {"last_analysis_stats": {
                "malicious": 1, "suspicious": 0, "undetected": 69,
            }}}
        })
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test_key"}):
            with patch("app.services.attachment_analyzer.requests.get", return_value=resp):
                analyzer = make_analyzer()
                vt_score, _, _ = await analyzer._run_virustotal_analysis(b"file", "test.pdf")

        self.assertEqual(vt_score, 85, f"Expected 85, got {vt_score}")


# ---------------------------------------------------------------------------
# Test 5: Unknown hash → upload + poll → completed with 2 malicious → score 85
# ---------------------------------------------------------------------------
class TestVTFileUploadAndPoll(unittest.IsolatedAsyncioTestCase):
    async def test_unknown_hash_triggers_upload_and_poll(self):
        """404 on hash → upload → poll (queued then completed) → vt_score=85 (malicious=2)."""
        not_found = make_vt_response(404, {})
        upload_ok = make_vt_response(200, {"data": {"id": "analysis-abc123xyz"}})
        queued = make_vt_response(200, {
            "data": {"attributes": {"status": "queued", "stats": {}}}
        })
        completed = make_vt_response(200, {
            "data": {"attributes": {"status": "completed", "stats": {
                "malicious": 2, "suspicious": 0,
            }}}
        })

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test_key", "VT_UPLOAD_ENABLED": "true"}):
            with patch("app.services.attachment_analyzer.requests.get",
                       side_effect=[not_found, queued, completed]):
                with patch("app.services.attachment_analyzer.requests.post", return_value=upload_ok):
                    with patch("app.services.attachment_analyzer.time.sleep"):
                        analyzer = make_analyzer()
                        vt_score, findings, _ = await analyzer._run_virustotal_analysis(
                            b"x" * 100, "unknown.pdf"
                        )

        # malicious=2 → malicious>=1 → score 85
        self.assertEqual(vt_score, 85, f"Expected 85 (malicious=2 → >=1 threshold), got {vt_score}")
        self.assertTrue(
            any("upload" in f.lower() or "Upload" in f for f in findings),
            f"Expected upload finding: {findings}",
        )


# ---------------------------------------------------------------------------
# Test 6: File > 32MB → upload skipped
# ---------------------------------------------------------------------------
class TestVTLargeFileSkip(unittest.IsolatedAsyncioTestCase):
    async def test_file_larger_than_32mb_skips_upload(self):
        """Files > 32MB must NOT be uploaded — vt_score=0, finding mentions '>32MB'."""
        not_found = make_vt_response(404, {})
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test_key", "VT_UPLOAD_ENABLED": "true"}):
            with patch("app.services.attachment_analyzer.requests.get", return_value=not_found):
                with patch("app.services.attachment_analyzer.requests.post") as mock_post:
                    analyzer = make_analyzer()
                    large_file = b"x" * (33 * 1024 * 1024)  # 33 MB
                    vt_score, findings, _ = await analyzer._run_virustotal_analysis(
                        large_file, "huge.pdf"
                    )

        mock_post.assert_not_called()
        self.assertEqual(vt_score, 0)
        self.assertTrue(
            any("32MB" in f or "too large" in f for f in findings),
            f"Expected size-limit finding: {findings}",
        )


# ---------------------------------------------------------------------------
# Test 7: Rate limit (429) → graceful fallback
# ---------------------------------------------------------------------------
class TestVTRateLimitGraceful(unittest.IsolatedAsyncioTestCase):
    async def test_rate_limit_429_returns_score_zero_gracefully(self):
        """HTTP 429 on hash lookup → vt_score=0, finding mentions 'rate limit', no exception."""
        rate_limited = make_vt_response(429, {})
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test_key"}):
            with patch("app.services.attachment_analyzer.requests.get", return_value=rate_limited):
                analyzer = make_analyzer()
                vt_score, findings, _ = await analyzer._run_virustotal_analysis(b"file", "test.pdf")

        self.assertEqual(vt_score, 0, f"Expected 0, got {vt_score}")
        self.assertTrue(
            any("rate limit" in f.lower() for f in findings),
            f"Expected rate limit finding: {findings}",
        )


# ---------------------------------------------------------------------------
# Test 8: Polling timeout (12 queued responses) → score 0
# ---------------------------------------------------------------------------
class TestVTPollingTimeout(unittest.IsolatedAsyncioTestCase):
    async def test_polling_timeout_after_12_attempts_returns_score_zero(self):
        """If analysis stays 'queued' for all 12 polls → vt_score=0, finding mentions timeout."""
        not_found = make_vt_response(404, {})
        upload_ok = make_vt_response(200, {"data": {"id": "analysis-xyz999"}})
        queued = make_vt_response(200, {
            "data": {"attributes": {"status": "queued", "stats": {}}}
        })

        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test_key", "VT_UPLOAD_ENABLED": "true"}):
            # hash lookup (404) + 12 poll attempts (all queued)
            with patch("app.services.attachment_analyzer.requests.get",
                       side_effect=[not_found] + [queued] * 12):
                with patch("app.services.attachment_analyzer.requests.post", return_value=upload_ok):
                    with patch("app.services.attachment_analyzer.time.sleep"):
                        analyzer = make_analyzer()
                        vt_score, findings, _ = await analyzer._run_virustotal_analysis(
                            b"file", "timeout_test.pdf"
                        )

        self.assertEqual(vt_score, 0, f"Expected 0 on timeout, got {vt_score}")
        self.assertTrue(
            any("timed out" in f.lower() or "timeout" in f.lower() for f in findings),
            f"Expected timeout finding: {findings}",
        )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 55)
    print(" Phase 10: VirusTotal Dynamic Analysis — Test Suite")
    print("=" * 55)
    print()
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print()
    if result.wasSuccessful():
        print("✓ All tests passed")
    else:
        print(f"✗ {len(result.failures)} failure(s), {len(result.errors)} error(s)")
    sys.exit(0 if result.wasSuccessful() else 1)
