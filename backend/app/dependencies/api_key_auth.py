"""
API Key authentication dependency for FastAPI.
Validates X-API-Key header against Firestore for B2B scan endpoints.
"""
import logging
from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

from app.firebase_admin_client import get_firestore_client

logger = logging.getLogger(__name__)

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def verify_api_key(api_key: str = Security(api_key_header)) -> dict:
    """
    FastAPI dependency that validates an API key from the X-API-Key header.

    Looks up the key in Firestore across all user documents.
    Returns a dict with uid and email if valid.
    Raises 401 if invalid or missing.
    """
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "Missing API key",
                "code": "api_key_missing",
                "message": "Provide your API key in the X-API-Key header. Generate one at your Developer Dashboard.",
            },
        )

    # Basic format check
    if not api_key.startswith("tl_live_") or len(api_key) != 40:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "Invalid API key format",
                "code": "api_key_invalid",
                "message": "The provided key is not a valid ThreatLens API key.",
            },
        )

    try:
        db = get_firestore_client()

        # Query users collection for a document whose apiKey field matches
        query = db.collection("users").where("apiKey", "==", api_key).limit(1)
        docs = list(query.stream())

        if not docs:
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "Invalid or revoked API key",
                    "code": "api_key_invalid",
                    "message": "The provided API key does not exist or has been revoked.",
                },
            )

        doc = docs[0]
        data = doc.to_dict()
        return {"uid": doc.id, "email": data.get("email"), "api_key": api_key}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"API key validation error: {e}")
        raise HTTPException(
            status_code=503,
            detail={
                "error": "Authentication service unavailable",
                "code": "auth_service_error",
                "message": "Could not validate API key. Please try again.",
            },
        )
