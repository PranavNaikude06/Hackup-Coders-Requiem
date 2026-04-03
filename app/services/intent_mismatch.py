"""
intent_mismatch.py — Contextual intent-mismatch detection.

Classifies the email body's TOPIC and the URL's PURPOSE into semantic
categories, then checks whether they are logically compatible.

A mismatch (e.g. email talks about "order/shipping" but URL points to
"account verification") is a strong phishing signal that neither the URL
analyzer nor the email analyzer can catch independently.
"""
import re
import urllib.parse

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False


# ── Email intent categories ──────────────────────────────────────────
EMAIL_INTENT_MAP = {
    "ORDER": [
        "order", "shipping", "delivery", "package", "cart", "purchase",
        "item", "shipment", "tracking", "dispatch", "warehouse",
    ],
    "ACCOUNT": [
        "account", "verify", "password", "login", "credentials",
        "security", "authentication", "sign in", "two-factor",
    ],
    "BILLING": [
        "payment", "invoice", "billing", "refund", "transaction",
        "charge", "receipt", "subscription", "renewal",
    ],
    "SOCIAL": [
        "friend", "follow", "message", "notification", "post",
        "share", "like", "comment", "tag", "mention",
    ],
    "LEGAL": [
        "legal", "compliance", "subpoena", "court", "lawsuit",
        "attorney", "warrant", "violation",
    ],
}

# ── URL intent categories (matched against domain + path) ────────────
URL_INTENT_MAP = {
    "ACCOUNT": [
        "/verify", "/login", "/auth", "/password", "/confirm",
        "/secure", "/signin", "/sso", "/reset", "/credential",
    ],
    "BILLING": [
        "/pay", "/invoice", "/checkout", "/billing", "/payment",
        "paypal", "stripe", "razorpay",
    ],
    "SOCIAL": [
        "facebook", "twitter", "instagram", "linkedin", "tiktok",
        "reddit", "discord",
    ],
    "DOWNLOAD": [
        "/download", "/attachment", "/file", "drive.google",
        "dropbox", "wetransfer",
    ],
    "ORDER": [
        "/orders", "/tracking", "/shipment", "/cart",
        "amazon", "flipkart", "ebay", "shopify",
    ],
}

# ── Mismatch matrix ─────────────────────────────────────────────────
# Key = email intent, Value = set of URL intents that are MISMATCHED.
MISMATCH_RULES = {
    "ORDER":   {"ACCOUNT", "SOCIAL", "LEGAL"},
    "BILLING": {"SOCIAL", "DOWNLOAD", "LEGAL"},
    "SOCIAL":  {"ACCOUNT", "BILLING", "LEGAL"},
    "LEGAL":   {"BILLING", "SOCIAL", "DOWNLOAD"},
    "ACCOUNT": {"ORDER", "SOCIAL"},
}


class IntentMismatchDetector:
    """Detects when the email's topic doesn't logically match the URL's purpose."""

    @staticmethod
    def _classify_email(email_text: str) -> str | None:
        """Return the dominant intent category of the email body, or None."""
        low = email_text.lower()
        scores: dict[str, int] = {}

        for category, keywords in EMAIL_INTENT_MAP.items():
            count = sum(1 for kw in keywords if kw in low)
            if count > 0:
                scores[category] = count

        if not scores:
            return None

        # Return the category with the most keyword hits
        return max(scores, key=scores.get)

    @staticmethod
    def _classify_url(url: str) -> str | None:
        """Return the intent category of the URL based on domain + path."""
        if not url:
            return None

        if "://" not in url:
            url = "http://" + url

        parsed = urllib.parse.urlparse(url)
        # Combine netloc + path for matching
        full_target = (parsed.netloc + parsed.path).lower()

        scores: dict[str, int] = {}
        for category, patterns in URL_INTENT_MAP.items():
            count = sum(1 for p in patterns if p in full_target)
            if count > 0:
                scores[category] = count

        if not scores:
            return None

        return max(scores, key=scores.get)

    def detect(self, url: str, email_text: str) -> dict:
        """
        Check if the email's topic is logically inconsistent with the URL's purpose.

        Returns:
            {
                "mismatch_detected": bool,
                "email_intent": str | None,
                "url_intent": str | None,
                "flag": str | None,
            }
        """
        empty = {
            "mismatch_detected": False,
            "email_intent": None,
            "url_intent": None,
            "flag": None,
        }

        if not url or not email_text:
            return empty

        email_intent = self._classify_email(email_text)
        url_intent = self._classify_url(url)

        if email_intent is None or url_intent is None:
            return empty

        # Same category = no mismatch
        if email_intent == url_intent:
            return {**empty, "email_intent": email_intent, "url_intent": url_intent}

        # Check the mismatch matrix
        mismatched_targets = MISMATCH_RULES.get(email_intent, set())
        if url_intent in mismatched_targets:
            intent_labels = {
                "ORDER": "order/shipping",
                "ACCOUNT": "account verification",
                "BILLING": "payment/billing",
                "SOCIAL": "social media",
                "LEGAL": "legal/compliance",
                "DOWNLOAD": "file download",
            }
            email_label = intent_labels.get(email_intent, email_intent.lower())
            url_label = intent_labels.get(url_intent, url_intent.lower())

            flag = (
                f"Intent mismatch: email discusses '{email_label}' "
                f"but URL points to '{url_label}' — "
                f"context inconsistency detected"
            )
            return {
                "mismatch_detected": True,
                "email_intent": email_intent,
                "url_intent": url_intent,
                "flag": flag,
            }

        # Different categories but not in the mismatch matrix → no flag
        return {**empty, "email_intent": email_intent, "url_intent": url_intent}
