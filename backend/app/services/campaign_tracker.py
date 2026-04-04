import sqlite3
import os
import json
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "campaigns.db")

class CampaignTracker:
    def __init__(self):
        self.db_path = DB_PATH
        self._ensure_db()

    def _ensure_db(self):
        """Initialize the SQLite database and create tables if they don't exist."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Campaigns table keeps track of active clusters
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    first_seen TEXT,
                    last_seen TEXT,
                    hit_count INTEGER,
                    primary_domain TEXT,
                    primary_email_hash TEXT
                )
            ''')
            # Log all mapped threats
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    campaign_id TEXT,
                    timestamp TEXT,
                    url TEXT,
                    score INTEGER,
                    verdict TEXT
                )
            ''')
            conn.commit()

    def _compute_email_hash(self, text: str) -> str:
        """
        Computes a simple structural token hash (bag of words) to catch email variations.
        For production, a true SimHash/TLSH should be used here.
        """
        import re
        import hashlib
        # Normalize: lower case, remove non-alphanumeric, split into tokens
        normalized = re.sub(r'[^a-z0-9]', ' ', text.lower())
        tokens = sorted(list(set(normalized.split())))
        # Filter out short/common tokens loosely
        significant_tokens = [t for t in tokens if len(t) > 3][:50]
        hash_input = " ".join(significant_tokens)
        return hashlib.md5(hash_input.encode()).hexdigest()

    def find_or_create_campaign(self, url: str, email_text: str, score: int, verdict: str) -> dict:
        """
        Checks if the threat belongs to an existing campaign.
        If yes, increments the cluster size and returns campaign data.
        If no, creates a new campaign cluster.
        """
        from urllib.parse import urlparse
        
        # Only cluster actual threats
        if verdict not in ["SUSPICIOUS", "PHISHING"]:
            return {"is_part_of_campaign": False}

        # 1. Generate Fingerprint
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
            
        email_hash = self._compute_email_hash(email_text) if email_text.strip() else "none"
        now_str = datetime.now(timezone.utc).isoformat()

        # 2. Search for exact domain OR exact email structural hash
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Simple heuristic: Match on domain OR email_hash
            cursor.execute('''
                SELECT campaign_id, hit_count, first_seen FROM campaigns
                WHERE primary_domain = ? OR (primary_email_hash = ? AND primary_email_hash != 'none')
            ''', (domain, email_hash))
            
            row = cursor.fetchone()
            
            if row:
                # Existing campaign found
                campaign_id, hit_count, first_seen = row
                new_hit_count = hit_count + 1
                
                # Update hit count and last_seen
                cursor.execute('''
                    UPDATE campaigns 
                    SET hit_count = ?, last_seen = ? 
                    WHERE campaign_id = ?
                ''', (new_hit_count, now_str, campaign_id))
            else:
                # Create a new campaign
                import uuid
                campaign_id = "CMP-" + str(uuid.uuid4())[:8].upper()
                new_hit_count = 1
                first_seen = now_str
                
                cursor.execute('''
                    INSERT INTO campaigns (campaign_id, first_seen, last_seen, hit_count, primary_domain, primary_email_hash)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (campaign_id, first_seen, now_str, new_hit_count, domain, email_hash))

            # 3. Log the specific threat instance
            cursor.execute('''
                INSERT INTO threat_logs (campaign_id, timestamp, url, score, verdict)
                VALUES (?, ?, ?, ?, ?)
            ''', (campaign_id, now_str, url, score, verdict))
            
            conn.commit()

        return {
            "is_part_of_campaign": True,
            "campaign_id": campaign_id,
            "similar_threats_detected": new_hit_count,
            "first_seen": first_seen
        }
