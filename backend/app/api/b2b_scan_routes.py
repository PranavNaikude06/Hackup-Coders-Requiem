"""
B2B Scan endpoints protected by API Key.
Duplicates the structure of internal endpoints but adds usage logging and API key auth.
"""
import time
import logging
from fastapi import APIRouter, HTTPException, Depends, Request, File, UploadFile, BackgroundTasks

from app.api.routes import (
    analyze_url_endpoint,
    analyze_email_endpoint,
    analyze_attachment_endpoint,
    analyze_combined_endpoint
)
from app.dependencies.api_key_auth import verify_api_key
from app.firebase_admin_client import get_firestore_client
from google.cloud import firestore

logger = logging.getLogger(__name__)

b2b_scan_router = APIRouter()

def log_api_usage(api_key: str, uid: str, endpoint: str, response_ms: int):
    """
    Log an API request to Firestore.
    Runs as a background task to prevent blocking the response.
    """
    try:
        db = get_firestore_client()
        # Create a document in usage_logs
        usage_ref = db.collection("usage_logs").document()
        # Only store the prefix of the API key for security
        key_prefix = api_key[:12] + "..." if api_key else "unknown"
        
        usage_ref.set({
            "api_key": key_prefix,
            "uid": uid,
            "endpoint": endpoint,
            "timestamp": firestore.SERVER_TIMESTAMP,
            "response_ms": response_ms,
        })
    except Exception as e:
        logger.error(f"Failed to log API usage to Firestore: {e}")


@b2b_scan_router.post("/url")
async def b2b_scan_url(
    request: Request,
    background_tasks: BackgroundTasks,
    api_user: dict = Depends(verify_api_key)
):
    """B2B Endpoint for scanning a URL."""
    start_time = time.time()
    try:
        # Delegate to the exact same logic as web endpoint
        response = await analyze_url_endpoint(request)
        return response
    finally:
        response_ms = int((time.time() - start_time) * 1000)
        background_tasks.add_task(
            log_api_usage,
            api_key=api_user.get("api_key"),
            uid=api_user.get("uid"),
            endpoint="url",
            response_ms=response_ms
        )

@b2b_scan_router.post("/email")
async def b2b_scan_email(
    request: Request,
    background_tasks: BackgroundTasks,
    api_user: dict = Depends(verify_api_key)
):
    """B2B Endpoint for scanning email text."""
    start_time = time.time()
    try:
        response = await analyze_email_endpoint(request)
        return response
    finally:
        response_ms = int((time.time() - start_time) * 1000)
        background_tasks.add_task(
            log_api_usage,
            api_key=api_user.get("api_key"),
            uid=api_user.get("uid"),
            endpoint="email",
            response_ms=response_ms
        )

@b2b_scan_router.post("/combined")
async def b2b_scan_combined(
    request: Request,
    background_tasks: BackgroundTasks,
    api_user: dict = Depends(verify_api_key)
):
    """B2B Endpoint for combined scoring."""
    start_time = time.time()
    try:
        response = await analyze_combined_endpoint(request)
        return response
    finally:
        response_ms = int((time.time() - start_time) * 1000)
        background_tasks.add_task(
            log_api_usage,
            api_key=api_user.get("api_key"),
            uid=api_user.get("uid"),
            endpoint="combined",
            response_ms=response_ms
        )

@b2b_scan_router.post("/file")
async def b2b_scan_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    api_user: dict = Depends(verify_api_key)
):
    """B2B Endpoint for scanning attachments."""
    start_time = time.time()
    try:
        response = await analyze_attachment_endpoint(file)
        return response
    finally:
        response_ms = int((time.time() - start_time) * 1000)
        background_tasks.add_task(
            log_api_usage,
            api_key=api_user.get("api_key"),
            uid=api_user.get("uid"),
            endpoint="file",
            response_ms=response_ms
        )
