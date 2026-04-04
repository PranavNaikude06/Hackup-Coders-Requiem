import json
import re

from fastapi import APIRouter, HTTPException, Request, File, UploadFile
from fastapi.responses import StreamingResponse
from app.services.feature_extractor import URLFeatureExtractor
from app.services.attachment_analyzer import AttachmentAnalyzer
from app.services.model_runner import ModelRunner
from app.services.email_nlp import EmailNLPService
from app.services.scoring_engine import ScoringEngine

from app.services.text_analyzer import TextAnalyzer

router = APIRouter()
extractor = URLFeatureExtractor()
runner = ModelRunner()
_email_service: EmailNLPService | None = None
_text_service: TextAnalyzer | None = None


def set_email_service(service: EmailNLPService) -> None:
    global _email_service
    _email_service = service

def set_text_service(service: TextAnalyzer) -> None:
    global _text_service
    _text_service = service


@router.post(
    "/url",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {"url": {"type": "string"}},
                        "required": ["url"],
                    },
                    "example": {"url": "https://example.com"},
                },
                "text/plain": {
                    "schema": {"type": "string"},
                    "example": "https://example.com",
                },
            },
        }
    },
)
async def analyze_url_endpoint(request: Request):
    raw_body = await request.body()
    content_type = request.headers.get("content-type", "").lower()

    url_text = ""
    if "application/json" in content_type:
        decoded = raw_body.decode("utf-8", errors="ignore")
        try:
            payload = json.loads(decoded or "{}")
            if isinstance(payload, dict):
                url_text = str(payload.get("url", ""))
            elif isinstance(payload, str):
                url_text = payload
        except Exception:
            # Fallback for malformed JSON (for example, control chars in url string).
            m = re.search(r'"url"\s*:\s*"([\s\S]*?)"', decoded)
            if m:
                url_text = m.group(1)
            else:
                url_text = decoded
    else:
        url_text = raw_body.decode("utf-8", errors="ignore")

    # Remove control chars/newlines commonly introduced by copy/paste.
    url_text = "".join(ch for ch in url_text if ch >= " " or ch in ("\t",)).strip()
    if not url_text:
        raise HTTPException(status_code=422, detail="url must not be empty")

    features = extractor.extract(url_text)
    model_analysis = runner.predict(features)
    return {
        "status": "success",
        "features": features,
        "model_analysis": model_analysis,
    }


@router.post(
    "/email",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {"email_text": {"type": "string"}},
                        "required": ["email_text"],
                    },
                    "example": {"email_text": "Please verify your account immediately."},
                },
                "text/plain": {
                    "schema": {"type": "string"},
                    "example": "Please verify your account immediately.",
                },
            },
        }
    },
)
async def analyze_email_endpoint(request: Request):
    raw_body = await request.body()
    content_type = request.headers.get("content-type", "").lower()

    email_text = ""
    if "application/json" in content_type:
        try:
            payload = json.loads(raw_body.decode("utf-8", errors="ignore") or "{}")
            if isinstance(payload, dict):
                email_text = str(payload.get("email_text", ""))
            elif isinstance(payload, str):
                email_text = payload
        except Exception:
            # Fallback for malformed JSON: treat body as raw text.
            email_text = raw_body.decode("utf-8", errors="ignore")
    else:
        email_text = raw_body.decode("utf-8", errors="ignore")

    if not email_text or not email_text.strip():
        raise HTTPException(status_code=422, detail="email_text must not be empty")

    if _email_service is None:
        raise HTTPException(status_code=503, detail="Email NLP service not initialized")

    email_analysis = _email_service.analyze(email_text)
    
    # Extract and scan any URLs found in the email body
    import re as _re
    email_urls = _re.findall(r'https?://[^\s<>"\']+', email_text)
    email_urls = list(dict.fromkeys(email_urls))[:5]
    
    embedded_url_results = []
    for eurl in email_urls:
        try:
            ef = extractor.extract(eurl)
            ef["_raw_url"] = eurl
            er = runner.predict(ef)
            embedded_url_results.append({
                "url": eurl,
                "risk_flag": er.get("risk_flag", "SAFE"),
                "confidence": er.get("confidence")
            })
        except Exception:
            pass
    
    return {
        "status": "success",
        "email_analysis": email_analysis,
        "embedded_urls_found": embedded_url_results,
    }


@router.post(
    "/combined",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string"},
                            "email_text": {"type": "string"}
                        },
                        "required": ["url", "email_text"],
                    },
                    "example": {
                        "url": "https://example.com/login",
                        "email_text": "Verify your account immediately."
                    },
                }
            },
        }
    },
)
async def analyze_combined_endpoint(request: Request):
    raw_body = await request.body()
    raw_str = raw_body.decode("utf-8", errors="ignore")

    url_text = ""
    email_text = ""

    # Stage 1: standard JSON parse
    try:
        payload = json.loads(raw_str)
        url_text = str(payload.get("url", ""))
        email_text = str(payload.get("email_text", ""))
        sender = str(payload.get("sender", ""))
        subject = str(payload.get("subject", ""))
        fast_mode = bool(payload.get("fast_mode", False))
    except Exception:
        # Stage 2: regex extraction — handles extra quotes, stray chars, raw \n
        url_m = re.search(r'"url"\s*:\s*"((?:[^"\\]|\\.)*)"', raw_str)
        email_m = re.search(r'"email_text"\s*:\s*"((?:[^"\\]|\\.)*)"', raw_str)
        sender_m = re.search(r'"sender"\s*:\s*"((?:[^"\\]|\\.)*)"', raw_str)
        subject_m = re.search(r'"subject"\s*:\s*"((?:[^"\\]|\\.)*)"', raw_str)
        fast_mode_m = re.search(r'"fast_mode"\s*:\s*(true|false)', raw_str, re.IGNORECASE)
        if url_m:
            url_text = url_m.group(1).encode("raw_unicode_escape").decode("unicode_escape", errors="replace")
        if email_m:
            email_text = email_m.group(1).encode("raw_unicode_escape").decode("unicode_escape", errors="replace")
        if sender_m:
            sender = sender_m.group(1).encode("raw_unicode_escape").decode("unicode_escape", errors="replace")
        if subject_m:
            subject = subject_m.group(1).encode("raw_unicode_escape").decode("unicode_escape", errors="replace")
        if fast_mode_m:
            fast_mode = fast_mode_m.group(1).lower() == "true"
        else:
            fast_mode = False
        if not url_text and not email_text:
            raise HTTPException(status_code=400, detail="Invalid JSON payload — could not parse 'url' or 'email_text'")

    # Sanitize control chars except newlines (they're valid in email text)
    url_text = "".join(ch for ch in url_text if ch >= " " or ch == "\t").strip()
    email_text = email_text.strip()


    if not url_text and not email_text:
        raise HTTPException(status_code=400, detail="Please provide at least 'url' or 'email_text'")

    if _email_service is None:
        raise HTTPException(status_code=503, detail="Email NLP service not initialized")

    scoring_engine = ScoringEngine(
        url_extractor=extractor,
        model_runner=runner,
        email_nlp=_email_service
    )

    try:
        result = scoring_engine.calculate_combined_score(url_text, email_text, sender, subject, fast_mode)
        return {
            "status": "success",
            **result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/attachment/stream")
async def analyze_attachment_stream_endpoint(file: UploadFile = File(...)):
    filename = file.filename or "unknown"
    file_bytes = await file.read()

    attachment_analyzer = AttachmentAnalyzer(
        url_extractor=extractor,
        model_runner=runner,
        text_analyzer=_text_service
    )

    async def event_generator():
        try:
            async for event in attachment_analyzer.analyze_stream(filename, file_bytes):
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'error': str(e)})}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@router.post("/attachment")
async def analyze_attachment_endpoint(file: UploadFile = File(...)):
    filename = file.filename or "unknown"
    file_bytes = await file.read()

    attachment_analyzer = AttachmentAnalyzer(
        url_extractor=extractor,
        model_runner=runner,
        text_analyzer=_text_service
    )

    try:
        result = await attachment_analyzer.analyze(filename, file_bytes)
        return {"status": "success", **result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

