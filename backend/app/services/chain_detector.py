"""
chain_detector.py — Multi-stage phishing chain detection.

Checks whether the URL's registered domain appears inside the email
body text, which is a strong indicator of a coordinated email→link
attack chain.
"""
import urllib.parse

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False


def _extract_registered_domain(url: str) -> str:
    """
    Return the registered domain (e.g. 'paypa1.com') from a URL.
    Uses tldextract if available, falls back to urlparse netloc.
    """
    if not url:
        return ""

    # Ensure URL has a scheme so urlparse works correctly
    if "://" not in url:
        url = "http://" + url

    if _HAS_TLDEXTRACT:
        extracted = tldextract.extract(url)
        # e.g. ExtractResult(subdomain='www', domain='paypa1', suffix='com')
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}".lower()

    # Fallback: strip subdomain is too complex without tldextract,
    # so return the full netloc (e.g. "www.paypa1.com") — still works
    # for chain detection because email usually contains the same host.
    netloc = urllib.parse.urlparse(url).netloc.lower()
    # Strip port if present
    netloc = netloc.split(":")[0]
    return netloc


class ChainDetector:
    """
    Detects multi-stage phishing attack chains by correlating
    the URL domain with the email body text.
    """

    def detect(self, url: str, email_text: str) -> dict:
        """
        Check if the URL's registered domain appears in the email body.

        Args:
            url:        The URL being analyzed (e.g. "http://paypa1.com/login")
            email_text: The email body text to scan against.

        Returns:
            {
                "chain_detected": bool,
                "matched_domain": str | None,
                "flag": str | None
            }
        """
        empty_result = {
            "chain_detected": False,
            "matched_domain": None,
            "flag": None,
        }

        if not url or not email_text:
            return empty_result

        registered_domain = _extract_registered_domain(url)
        if not registered_domain:
            return empty_result

        # Case-insensitive substring match
        if registered_domain in email_text.lower():
            flag = (
                f"multi-stage phishing chain: URL domain "
                f"'{registered_domain}' found in email body"
            )
            return {
                "chain_detected": True,
                "matched_domain": registered_domain,
                "flag": flag,
            }

        return empty_result
