"""
API Key management routes — generate, retrieve, and revoke keys.
Protected by Firebase Auth (Bearer token required).
"""
import secrets
import logging
from fastapi import APIRouter, HTTPException, Header
from typing import Optional

from app.firebase_admin_client import get_firestore_client, verify_firebase_token

logger = logging.getLogger(__name__)

apikey_router = APIRouter()


def _generate_key() -> str:
    """Return a secure tl_live_ prefixed key (40 chars total)."""
    return "tl_live_" + secrets.token_hex(16)  # 8 + 32 = 40


def _uid_from_auth(authorization: Optional[str]) -> str:
    """Validate Bearer token and return Firebase UID."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail={"error": "Authorization header required", "code": "auth_required"},
        )
    id_token = authorization[len("Bearer "):]
    try:
        decoded = verify_firebase_token(id_token)
        return decoded["uid"]
    except Exception as e:
        logger.warning(f"Token verification failed: {e}")
        raise HTTPException(
            status_code=401,
            detail={"error": "Invalid or expired token", "code": "auth_invalid"},
        )


@apikey_router.post("/generate")
async def generate_api_key(authorization: Optional[str] = Header(None)):
    """
    Generate (or rotate) an API key for the authenticated user.
    Requires: Authorization: Bearer <firebase_id_token>
    If a key already exists it is overwritten — old key is immediately revoked.
    """
    uid = _uid_from_auth(authorization)
    try:
        db = get_firestore_client()
        new_key = _generate_key()
        db.collection("users").document(uid).set({"apiKey": new_key}, merge=True)
        logger.info(f"Generated API key for uid={uid}")
        return {
            "api_key": new_key,
            "message": "API key generated. Store it securely — this is the only time it is returned in full.",
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Key generation failed for uid={uid}: {e}")
        raise HTTPException(
            status_code=500,
            detail={"error": "Failed to generate API key", "code": "generation_error"},
        )


@apikey_router.get("/me")
async def get_my_api_key(authorization: Optional[str] = Header(None)):
    """
    Return the current API key for the authenticated user (or null if none).
    Requires: Authorization: Bearer <firebase_id_token>
    """
    uid = _uid_from_auth(authorization)
    try:
        db = get_firestore_client()
        doc = db.collection("users").document(uid).get()
        if not doc.exists:
            return {"has_key": False, "api_key": None}
        data = doc.to_dict()
        api_key = data.get("apiKey")
        if not api_key:
            return {"has_key": False, "api_key": None}
        return {"has_key": True, "api_key": api_key}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Key retrieval failed for uid={uid}: {e}")
        raise HTTPException(
            status_code=500,
            detail={"error": "Failed to retrieve API key", "code": "retrieval_error"},
        )


@apikey_router.delete("/revoke")
async def revoke_api_key(authorization: Optional[str] = Header(None)):
    """
    Revoke the API key for the authenticated user.
    Any subsequent request using the old key will immediately return 401.
    Requires: Authorization: Bearer <firebase_id_token>
    """
    uid = _uid_from_auth(authorization)
    try:
        db = get_firestore_client()
        db.collection("users").document(uid).update({"apiKey": None})
        logger.info(f"Revoked API key for uid={uid}")
        return {"message": "API key revoked. Generate a new one from your Developer Dashboard."}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Key revocation failed for uid={uid}: {e}")
        raise HTTPException(
            status_code=500,
            detail={"error": "Failed to revoke API key", "code": "revocation_error"},
        )
