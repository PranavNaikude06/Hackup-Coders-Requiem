"""
Firebase Admin SDK initialization for ThreatLens backend.
Used for validating Firebase ID tokens and reading/writing Firestore data.
"""
import os
import logging
import firebase_admin
from firebase_admin import credentials, firestore, auth as firebase_auth

logger = logging.getLogger(__name__)

_app = None
_db = None


def get_firebase_app():
    global _app
    if _app is not None:
        return _app

    service_account_path = os.getenv("FIREBASE_SERVICE_ACCOUNT_PATH")

    if service_account_path and os.path.exists(service_account_path):
        logger.info(f"Initializing Firebase Admin with service account: {service_account_path}")
        cred = credentials.Certificate(service_account_path)
        _app = firebase_admin.initialize_app(cred)
    else:
        # Fall back to Application Default Credentials (ADC)
        # Works on Google Cloud / Railway with Workload Identity
        logger.info("Initializing Firebase Admin with Application Default Credentials")
        _app = firebase_admin.initialize_app()

    return _app


def get_firestore_client():
    global _db
    if _db is None:
        get_firebase_app()
        _db = firestore.client()
    return _db


def verify_firebase_token(id_token: str) -> dict:
    """Verify a Firebase ID token and return the decoded claims."""
    get_firebase_app()
    return firebase_auth.verify_id_token(id_token)
