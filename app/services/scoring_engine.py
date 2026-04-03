import re as _re
from app.services.feature_extractor import URLFeatureExtractor
from app.services.model_runner import ModelRunner
from app.services.email_nlp import EmailNLPService
from app.services.chain_detector import ChainDetector
from app.services.intent_mismatch import IntentMismatchDetector


class ScoringEngine:
    def __init__(self, url_extractor: URLFeatureExtractor, model_runner: ModelRunner, email_nlp: EmailNLPService):
        self.url_extractor = url_extractor
        self.model_runner = model_runner
        self.email_nlp = email_nlp

    def _map_to_score(self, risk: str, confidence: float) -> float:
        """Map label and confidence to a 0-100 score."""
        if risk in ["HIGH_RISK", "PHISHING"]:
            return min(100.0, max(75.0, confidence * 100))
        elif risk == "SUSPICIOUS":
            return 45.0 + (confidence * 29.0)
        else:  # SAFE
            return max(0.0, min(40.0, (1.0 - confidence) * 40))

    def _run_ml_pipeline(self, url: str, email_text: str, sender: str = "", subject: str = "", fast_mode: bool = False) -> dict:
        """Full local ML pipeline — used as final fallback when both LLMs fail."""
        flags = []
        url_score = 0
        email_score = 0
        rule_score = 0

        # 1. Evaluate URL with RandomForest
        if url:
            url_features = self.url_extractor.extract(url, fast_mode=fast_mode)
            url_analysis = self.model_runner.predict(url_features)
            if "error" in url_analysis:
                raise ValueError(f"URL Analysis Error: {url_analysis['error']}")

            u_risk = url_analysis.get("risk_flag", "SAFE")
            u_conf = url_analysis.get("raw_model_confidence", url_analysis.get("confidence", 0))
            url_score = self._map_to_score(u_risk, u_conf)
            flags.extend([f"URL: {r}" for r in url_analysis.get("humanized_verdict", {}).get("key_reasons", [])])
        else:
            url_features = {}
            url_analysis = {}
            u_risk = "SAFE"
            u_conf = 0
            url_score = 0

        # Hard rule checks on URL
        lookalike = url_features.get("_lookalike", {})
        is_clone = lookalike.get("is_lookalike", False)
        is_ip = url_features.get("having_IP_Address") == 1
        no_ssl = url_features.get("SSLfinal_State") == 1
        dns_fail = url_features.get("DNSRecord") == 1
        has_phish_kw = url_features.get("_keyword_flagged", False)

        rule_hit = False
        if is_clone:
            flags.append(f"RULE HIT: Domain impersonates '{lookalike.get('matched_brand')}'")
            rule_hit = True
            
        # Hard rule check on Sender Address
        if sender and "@" in sender:
            # e.g. "Google <no-reply@accounts.google.com>" -> "accounts.google.com"
            sender_email = _re.search(r'[\w\.-]+@[\w\.-]+', sender)
            if sender_email:
                sender_domain = sender_email.group(0).split("@")[1].strip()
                s_lookalike = self.url_extractor.homograph_detector.check_similarity(sender_domain)
                if s_lookalike.get("is_lookalike"):
                    flags.append(f"RULE HIT: Sender impersonates '{s_lookalike.get('matched_brand')}'")
                    rule_hit = True

        if is_ip and no_ssl:
            flags.append("RULE HIT: Raw IP address used over HTTP")
            rule_hit = True
        if dns_fail:
            flags.append("RULE HIT: Domain does not resolve (DNS failure)")
            rule_hit = True
        if has_phish_kw:
            flags.append("RULE HIT: URL contains known phishing keywords")
            rule_hit = True

        # 2. Evaluate Email with DistilBERT
        email_analysis = self.email_nlp.analyze(email_text)
        e_risk = email_analysis.get("verdict", "SAFE")
        e_conf = email_analysis.get("confidence", 0)
        email_score = self._map_to_score(e_risk, e_conf)
        flags.extend([f"EMAIL: {r}" for r in email_analysis.get("evidence", [])])

        # 2.1 Extract and scan URLs embedded in email body
        email_urls = _re.findall(r'https?://[^\s<>"\' ]+', email_text)
        email_urls = list(dict.fromkeys(email_urls))[:5]
        embedded_url_results = []
        embedded_high_risk = 0
        for eurl in email_urls:
            try:
                ef = self.url_extractor.extract(eurl)
                ef["_raw_url"] = eurl
                er = self.model_runner.predict(ef)
                erisk = er.get("risk_flag", "SAFE")
                if erisk == "HIGH_RISK":
                    embedded_high_risk += 1
                    flags.append(f"EMAIL URL [HIGH RISK]: {eurl}")
                    rule_hit = True
                elif erisk == "SUSPICIOUS":
                    flags.append(f"EMAIL URL [SUSPICIOUS]: {eurl}")
                embedded_url_results.append({"url": eurl, "risk_flag": erisk, "confidence": er.get("confidence")})
            except Exception:
                pass
        if embedded_high_risk >= 1:
            url_score = max(url_score, 80)

        # 2.5 Chain Detection
        chain_result = ChainDetector().detect(url, email_text)
        chain_detected = chain_result["chain_detected"]
        if chain_detected:
            flags.append(f"CHAIN: {chain_result['flag']}")
            rule_hit = True

        # 2.6 Intent Mismatch Detection
        mismatch_result = IntentMismatchDetector().detect(url, email_text)
        mismatch_detected = mismatch_result["mismatch_detected"]
        if mismatch_detected:
            flags.append(f"MISMATCH: {mismatch_result['flag']}")
            rule_hit = True

        # Rule score
        rule_score = 100 if rule_hit else 0

        # 3. Weighted Score
        final_score_raw = (url_score * 0.4) + (email_score * 0.4) + (rule_score * 0.2)
        final_score = round(final_score_raw)

        # 4. Hard overrides
        if chain_detected:
            final_score = max(final_score, 90)
        if mismatch_detected:
            if url_score >= 30 or email_score >= 30:
                final_score = max(final_score, 75)
            else:
                final_score = max(final_score, 55)
        if rule_hit and url_score >= 75:
            final_score = max(final_score, 85)
        if url_score >= 90 or email_score >= 90:
            final_score = max(final_score, 75)
        final_score = max(0, min(100, final_score))

        # 5. Verdict
        if final_score > 70:
            final_verdict = "PHISHING"
        elif final_score >= 40:
            final_verdict = "SUSPICIOUS"
        else:
            final_verdict = "SAFE"

        return {
            "combined_score": final_score,
            "verdict": final_verdict,
            "analysis_provider": "ml_pipeline",
            "chain_detected": chain_detected,
            "chain_flag": chain_result.get("flag"),
            "mismatch_detected": mismatch_detected,
            "mismatch_flag": mismatch_result.get("flag"),
            "email_intent": mismatch_result.get("email_intent"),
            "url_intent": mismatch_result.get("url_intent"),
            "breakdown": {
                "url_score_contrib": round(url_score * 0.4, 1),
                "email_score_contrib": round(email_score * 0.4, 1),
                "rule_score_contrib": round(rule_score * 0.2, 1),
                "raw_url_score": round(url_score, 1),
                "raw_email_score": round(email_score, 1),
                "raw_rule_score": rule_score
            },
            "url_analysis": url_analysis,
            "email_analysis": email_analysis,
            "embedded_url_scan": embedded_url_results,
            "llm_human_explanation": "LLM services unavailable — analysis performed by local ML pipeline.",
            "flags": flags
        }

    def calculate_combined_score(self, url: str, email_text: str, sender: str = "", subject: str = "", fast_mode: bool = False) -> dict:
        """
        Priority chain:
          1. Groq (Llama 3.3 70B) — primary LLM
          2. OpenRouter (Gemma 3 27B) — LLM fallback
          3. Local ML Pipeline (RandomForest + DistilBERT + rules) — offline fallback
        """
        from app.services.llm_analyzer import LLMAnalyzer
        llm = LLMAnalyzer()
        llm_result = llm.analyze(url, email_text, sender, subject)

        if "error" not in llm_result:
            # ── LLM succeeded — use its verdict as the primary result ──
            score = llm_result.get("combined_score", 50)
            verdict = llm_result.get("verdict", "SUSPICIOUS")
            
            # Normalize score within verdict bands to avoid LLM hallucinating out-of-band values
            score = max(0, min(100, int(score)))
            if verdict == "PHISHING" and score < 70:
                score = 75
            elif verdict == "SUSPICIOUS" and not (40 <= score <= 69):
                score = 50
            elif verdict == "SAFE" and score > 39:
                score = 20

            flags = []
            if llm_result.get("escalate_to_phishing") and verdict == "PHISHING":
                flags.append("LLM: Critical context mismatch — phishing intent confirmed")
            
            provider = llm_result.get("_provider", "llm")

            final_result = {
                "combined_score": score,
                "verdict": verdict,
                "analysis_provider": provider,
                "chain_detected": False,
                "chain_flag": None,
                "mismatch_detected": llm_result.get("escalate_to_phishing", False) and verdict != "SAFE",
                "mismatch_flag": None,
                "email_intent": None,
                "url_intent": None,
                "breakdown": {},
                "url_analysis": {},
                "email_analysis": {},
                "embedded_url_scan": [],
                "llm_human_explanation": llm_result.get("human_explanation", ""),
                "flags": flags
            }
        else:
            # ── Both LLMs failed — run full ML pipeline ──
            print("[ScoringEngine] Both LLMs unavailable — running local ML pipeline")
            final_result = self._run_ml_pipeline(url, email_text, sender, subject, fast_mode)
            
        # ── Campaign Clustering ──
        try:
            from app.services.campaign_tracker import CampaignTracker
            tracker = CampaignTracker()
            campaign_info = tracker.find_or_create_campaign(
                url=url, 
                email_text=email_text, 
                score=final_result["combined_score"], 
                verdict=final_result["verdict"]
            )
            if campaign_info.get("is_part_of_campaign"):
                final_result["campaign"] = campaign_info
        except Exception as e:
            print(f"[CampaignTracker] Error: {e}")
            
        return final_result
