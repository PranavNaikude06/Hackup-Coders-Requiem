import re
import urllib.parse
import requests
from bs4 import BeautifulSoup
from app.core.utils import get_domain, is_shortened
from app.core.homograph_detector import HomographDetector
import socket
import whois
from datetime import datetime

class URLFeatureExtractor:
    def __init__(self):
        self.homograph_detector = HomographDetector()

    def extract(self, url: str) -> dict:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        parsed = urllib.parse.urlparse(url)
        domain = get_domain(url)
        
        # Typosquatting / Homograph check (returns structured dict)
        lookalike = self.homograph_detector.check_similarity(domain)
        is_clone = lookalike["is_lookalike"]
        
        # 1. having_IP_Address
        ip_pattern = re.compile(
            r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])'
            r'|([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'
        )
        having_ip = 1 if ip_pattern.search(domain) else -1
        
        # 2. URL_Length
        l = len(url)
        url_length = 1 if l > 75 else (0 if 54 <= l <= 75 else -1)
        
        # 3. Shortining_Service
        shortening_service = 1 if is_shortened(url) == -1 else -1
        
        # 4. having_At_Symbol
        having_at = 1 if '@' in url else -1
        
        # 5. double_slash_redirecting
        idx = url.rfind('//')
        double_slash = 1 if idx > 7 else -1
        
        # 6. Prefix_Suffix (also flag if it's a brand clone)
        prefix_suffix = 1 if ('-' in domain or is_clone) else -1
        
        # 7. having_Sub_Domain
        dots = domain.count('.')
        sub_domain = -1 if dots <= 2 else (0 if dots == 3 else 1)
        
        # 8. SSLfinal_State
        scheme = parsed.scheme.lower()
        ssl_state = -1 if scheme == 'https' else 1
        
        # 11. port
        port_val = -1
        if parsed.port and parsed.port not in [80, 443]:
            port_val = 1
            
        # 12. HTTPS_token
        https_token = 1 if 'https' in domain else -1
        
        # --- Content-based features (fetch HTML) ---
        soup = None
        redirect = 0
        try:
            response = requests.get(url, timeout=1.5, allow_redirects=True)
            soup = BeautifulSoup(response.content, 'html.parser')
            redirect = 1 if len(response.history) > 1 else -1
        except:
            redirect = 0

        # 10. Favicon
        favicon = -1
        if soup:
            for link in soup.find_all('link', rel=True):
                if 'icon' in ' '.join(link.get('rel', [])):
                    href = link.get('href', '')
                    if href.startswith('http') and domain not in href:
                        favicon = 1

        # 13. Request_URL
        request_url = -1
        if soup:
            tags = soup.find_all(['img', 'audio', 'embed', 'iframe'], src=True)
            if tags:
                external = sum(1 for t in tags if t['src'].startswith('http') and domain not in t['src'])
                ratio = external / len(tags)
                request_url = 1 if ratio > 0.61 else (0 if ratio > 0.22 else -1)

        # 14. URL_of_Anchor
        anchor_url = -1
        if soup:
            anchors = soup.find_all('a', href=True)
            if anchors:
                external = sum(1 for a in anchors if a['href'].startswith('http') and domain not in a['href'])
                ratio = external / len(anchors)
                anchor_url = 1 if ratio > 0.67 else (0 if ratio > 0.31 else -1)

        # 15. Links_in_tags
        links_in_tags = -1
        if soup:
            meta_tags = soup.find_all(['meta', 'script', 'link'])
            if meta_tags:
                external = 0
                for t in meta_tags:
                    src = t.get('href', '') or t.get('src', '')
                    if src.startswith('http') and domain not in src:
                        external += 1
                ratio = external / len(meta_tags)
                links_in_tags = 1 if ratio > 0.81 else (0 if ratio > 0.17 else -1)

        # 16. SFH
        sfh = -1
        if soup:
            forms = soup.find_all('form', action=True)
            for f in forms:
                action = f['action'].strip().lower()
                if action in ("", "about:blank"):
                    sfh = 1
                    break
                elif action.startswith('http') and domain not in action:
                    sfh = 0

        # 17. Submitting_to_email
        page_text = str(soup).lower() if soup else url.lower()
        submitting_email = 1 if 'mailto:' in page_text else -1
        
        # 18. Abnormal_URL (critical: flag brand clones here)
        abnormal = 1 if (domain not in url) or is_clone else -1

        # 20. on_mouseover
        on_mouseover = 1 if soup and "window.status" in str(soup) else -1
        
        # 21. RightClick
        right_click = 1 if soup and "event.button==2" in str(soup) else -1
        
        # 22. popUpWidnow
        popup = 1 if soup and "window.open" in str(soup) else -1
        
        # 23. Iframe
        iframe = 1 if soup and soup.find('iframe') else -1
        
        # --- WHOIS BASED FEATURES ---
        domain_reg = 0
        age_of_domain = 0
        whois_lookup_failed = False
        
        import concurrent.futures
        def fetch_whois():
            return whois.whois(domain)

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(fetch_whois)
                w = future.result(timeout=1.5)  # Strict 1.5s timeout

            creation_date = w.creation_date
            expiration_date = w.expiration_date
            if isinstance(creation_date, list): creation_date = creation_date[0]
            if isinstance(expiration_date, list): expiration_date = expiration_date[0]
            
            if creation_date and expiration_date:
                reg_length = (expiration_date - creation_date).days
                domain_reg = -1 if reg_length > 365 else 1
                age = (datetime.now() - creation_date).days
                age_of_domain = -1 if age >= 180 else 1
        except Exception:
            domain_reg = 1   # Unable to verify = suspicious
            age_of_domain = 1
            whois_lookup_failed = True

        # 25. DNSRecord
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(socket.gethostbyname, domain)
                future.result(timeout=1.0)
            dns_record = -1
        except Exception:
            dns_record = 1

        # Remaining features defaulted to safe (-1)
        web_traffic = -1
        page_rank = -1
        google_index = -1
        links_pointing = -1
        statistical_report = 1 if is_clone else -1  # Flag clones here too

        return {
            "having_IP_Address": having_ip,
            "URL_Length": url_length,
            "Shortining_Service": shortening_service,
            "having_At_Symbol": having_at,
            "double_slash_redirecting": double_slash,
            "Prefix_Suffix": prefix_suffix,
            "having_Sub_Domain": sub_domain,
            "SSLfinal_State": ssl_state,
            "Domain_registeration_length": domain_reg,
            "Favicon": favicon,
            "port": port_val,
            "HTTPS_token": https_token,
            "Request_URL": request_url,
            "URL_of_Anchor": anchor_url,
            "Links_in_tags": links_in_tags,
            "SFH": sfh,
            "Submitting_to_email": submitting_email,
            "Abnormal_URL": abnormal,
            "Redirect": redirect,
            "on_mouseover": on_mouseover,
            "RightClick": right_click,
            "popUpWidnow": popup,
            "Iframe": iframe,
            "age_of_domain": age_of_domain,
            "DNSRecord": dns_record,
            "web_traffic": web_traffic,
            "Page_Rank": page_rank,
            "Google_Index": google_index,
            "Links_pointing_to_page": links_pointing,
            "Statistical_report": statistical_report,
            # Metadata (not fed to model, used by verdict engine)
            "_lookalike": lookalike,
            "_whois_lookup_failed": whois_lookup_failed
        }
