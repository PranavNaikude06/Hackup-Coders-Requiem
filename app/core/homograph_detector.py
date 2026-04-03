import difflib

class HomographDetector:
    def __init__(self):
        self.targets = [
            "google", "microsoft", "apple", "amazon", "facebook", 
            "instagram", "whatsapp", "paypal", "netflix", "ebay", 
            "linkedin", "outlook", "yahoo", "dropbox",
            "bankofamerica", "wellsfargo", "chase", "citibank", 
            "coinbase", "binance", "metamask", "steam", "twitter",
            "telegram", "snapchat", "uber", "spotify", "adobe",
            "salesforce", "stripe", "shopify", "squarespace"
        ]
        self.homoglyphs = {
            '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', 
            '7': 't', '8': 'b', '9': 'g', '@': 'a', '$': 's',
            '!': 'i', '|': 'l'
        }

    def normalize(self, text: str) -> str:
        normalized = text.lower()
        # Multi-char substitutions
        normalized = normalized.replace('rn', 'm')
        # Single-char substitutions
        for char, replacement in self.homoglyphs.items():
            normalized = normalized.replace(char, replacement)
        return normalized

    def check_similarity(self, domain: str) -> dict:
        """
        Returns:
          - is_lookalike (bool)
          - similarity (float 0.0-1.0)
          - matched_brand (str|None)
        """
        # Strip TLD: "amaz0n-security.com" -> "amaz0n-security"
        base_domain = domain.split('.')[0].lower()
        
        # Also strip hyphens/numbers to get core word: "amaz0n-security" -> "amaz0nsecurity"
        clean_domain = base_domain.replace('-', '').replace('_', '')
        norm_domain = self.normalize(clean_domain)
        norm_base = self.normalize(base_domain.replace('-', ''))
        
        best = {"is_lookalike": False, "similarity": 0.0, "matched_brand": None}
        
        for target in self.targets:
            # Skip exact match (it IS the brand)
            if clean_domain == target or base_domain == target:
                continue
            
            # Case 1: Normalized domain perfectly equals brand
            if norm_domain == target or norm_base == target:
                return {"is_lookalike": True, "similarity": 1.0, "matched_brand": target}
            
            # Case 2: Brand name is embedded in the normalized domain
            # e.g. "amaz0n-security" normalizes to "amazonsecurity" which contains "amazon"
            if target in norm_domain and len(target) >= 4:
                return {"is_lookalike": True, "similarity": 0.95, "matched_brand": target}
            
            # Case 3: Brand in the raw base domain (e.g. "secure-paypal-login")
            if target in base_domain and len(target) >= 4:
                return {"is_lookalike": True, "similarity": 0.9, "matched_brand": target}
                
            # Case 4: Levenshtein similarity on normalized domain
            score = difflib.SequenceMatcher(None, norm_domain, target).ratio()
            if score > 0.85 and score > best["similarity"]:
                best = {"is_lookalike": True, "similarity": score, "matched_brand": target}
            elif score > best["similarity"]:
                best["similarity"] = score
                
        return best
