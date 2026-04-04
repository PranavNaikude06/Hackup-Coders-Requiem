"""
stream_routes.py — Real-time streaming phishing detection via Server-Sent Events (SSE).

Endpoint: POST /analyze/stream
Returns a text/event-stream response streaming partial results as each analysis
stage completes, instead of waiting for the full pipeline.

Stages emitted:
  1. url_scan    (~100ms)  — RandomForest URL result
  2. email_scan  (~500ms)  — DistilBERT + chain/mismatch keyword results
  3. final       (~2-3s)   — LLM verdict + human explanation
"""
import json
import asyncio
import re as _re
from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

stream_router = APIRouter()


def _sse(event: str, data: dict) -> str:
    """Format a single SSE message."""
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


@stream_router.post("/stream")
async def analyze_stream(request: Request):
    """
    Streams phishing analysis results in real-time as each stage completes.
    Client should listen using EventSource or fetch with ReadableStream.
    """
    try:
        raw = await request.body()
        raw_str = raw.decode("utf-8", errors="ignore")
        try:
            payload = json.loads(raw_str)
            url = str(payload.get("url", ""))
            email_text = str(payload.get("email_text", ""))
            fast_mode = bool(payload.get("fast_mode", False))
        except Exception:
            url_m = _re.search(r'"url"\s*:\s*"((?:[^"\\]|\\.)*)"', raw_str)
            email_m = _re.search(r'"email_text"\s*:\s*"((?:[^"\\]|\\.)*)"', raw_str)
            fast_mode_m = _re.search(r'"fast_mode"\s*:\s*(true|false)', raw_str, _re.IGNORECASE)
            url = url_m.group(1) if url_m else ""
            email_text = email_m.group(1) if email_m else ""
            fast_mode = fast_mode_m.group(1).lower() == "true" if fast_mode_m else False
    except Exception as e:
        async def _err():
            yield _sse("error", {"message": f"Could not parse request: {e}"})
        return StreamingResponse(_err(), media_type="text/event-stream")

    # Import services lazily (they are initialized at startup)
    from app.api.routes import extractor, runner
    from app.services.email_nlp import EmailNLPService
    from app.services.chain_detector import ChainDetector
    from app.services.intent_mismatch import IntentMismatchDetector
    from app.services.llm_analyzer import LLMAnalyzer
    from app.api import routes as _routes

    async def stream_generator():
        # ── Stage 1: URL Scan ──────────────────────────────────────────────
        try:
            if url:
                url_features = extractor.extract(url, fast_mode=fast_mode)
                url_analysis = runner.predict(url_features)
                u_risk = url_analysis.get("risk_flag", "SAFE")
                u_conf = url_analysis.get("confidence", 0)
                lookalike = url_features.get("_lookalike", {})

                yield _sse("url_scan", {
                    "stage": "url_scan",
                    "risk_flag": u_risk,
                    "confidence": u_conf,
                    "brand_impersonation": lookalike.get("matched_brand") if lookalike.get("is_lookalike") else None,
                    "key_reasons": url_analysis.get("humanized_verdict", {}).get("key_reasons", [])
                })
            else:
                u_risk = "SAFE"
                u_conf = 0
                yield _sse("url_scan", {"stage": "url_scan", "message": "Skipped (no primary URL)"})
        except Exception as e:
            yield _sse("url_scan", {"stage": "url_scan", "error": str(e)})

        await asyncio.sleep(0)  # yield control to event loop

        # ── Stage 2: Email + Chain + Mismatch ─────────────────────────────
        try:
            email_nlp = _routes._email_service
            email_analysis = email_nlp.analyze(email_text) if email_nlp else {}
            e_risk = email_analysis.get("verdict", "UNKNOWN")

            # Extract embedded URLs from email body
            embedded_urls = _re.findall(r'https?://[^\s<>"\']+', email_text)
            embedded_scan = []
            for eurl in list(dict.fromkeys(embedded_urls))[:5]:
                try:
                    ef = extractor.extract(eurl, fast_mode=fast_mode)
                    er = runner.predict(ef)
                    embedded_scan.append({"url": eurl, "risk_flag": er.get("risk_flag", "SAFE")})
                except Exception:
                    pass

            # Chain + mismatch
            chain_result = ChainDetector().detect(url, email_text)
            mismatch_result = IntentMismatchDetector().detect(url, email_text)

            yield _sse("email_scan", {
                "stage": "email_scan",
                "email_verdict": e_risk,
                "evidence": email_analysis.get("evidence", []),
                "chain_detected": chain_result["chain_detected"],
                "chain_flag": chain_result.get("flag"),
                "mismatch_detected": mismatch_result["mismatch_detected"],
                "mismatch_flag": mismatch_result.get("flag"),
                "embedded_urls": embedded_scan
            })
        except Exception as e:
            yield _sse("email_scan", {"stage": "email_scan", "error": str(e)})

        await asyncio.sleep(0)

        # ── Stage 3: LLM Final Verdict & Campaign Clustering ────────────────
        try:
            llm = LLMAnalyzer()
            llm_result = llm.analyze(url, email_text)

            if "error" not in llm_result:
                score = max(0, min(100, int(llm_result.get("combined_score", 50))))
                verdict = llm_result.get("verdict", "SUSPICIOUS")
                if verdict == "PHISHING" and score < 70:
                    score = 75
                elif verdict == "SAFE" and score > 39:
                    score = 20

                final_payload = {
                    "stage": "final",
                    "verdict": verdict,
                    "combined_score": score,
                    "analysis_provider": llm_result.get("_provider", "llm"),
                    "llm_human_explanation": llm_result.get("human_explanation", ""),
                    "escalate_to_phishing": llm_result.get("escalate_to_phishing", False)
                }
            else:
                # LLM failed — fall back to simple ML-based final verdict
                score = round(u_conf * 100)
                verdict = u_risk.replace("HIGH_RISK", "PHISHING")
                final_payload = {
                    "stage": "final",
                    "verdict": verdict,
                    "combined_score": score,
                    "analysis_provider": "ml_pipeline",
                    "llm_human_explanation": "LLM unavailable — verdict based on ML pipeline.",
                    "escalate_to_phishing": False
                }
                
            # Run fast local campaign clustering
            try:
                from app.services.campaign_tracker import CampaignTracker
                tracker = CampaignTracker()
                campaign_info = tracker.find_or_create_campaign(
                    url=url, 
                    email_text=email_text, 
                    score=score, 
                    verdict=verdict
                )
                if campaign_info.get("is_part_of_campaign"):
                    final_payload["campaign"] = campaign_info
            except Exception as e:
                print(f"[CampaignTracker stream] Error: {e}")

            yield _sse("final", final_payload)
            
        except Exception as e:
            yield _sse("final", {"stage": "final", "error": str(e)})

        # Signal stream is done
        yield _sse("done", {"message": "Analysis complete"})

    return StreamingResponse(
        stream_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",       # disable nginx buffering
            "Access-Control-Allow-Origin": "*"
        }
    )
