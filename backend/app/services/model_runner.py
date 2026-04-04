import joblib
import os
import warnings


class ModelRunner:
    def __init__(self):
        self.model = None
        model_path = "app/core/rf_model.pkl"
        if os.path.exists(model_path):
            self.model = joblib.load(model_path)
            if hasattr(self.model, "n_jobs"):
                self.model.n_jobs = 1

    def _collect_risk_reasons(self, features: dict) -> list:
        reasons = []
        lookalike = features.get("_lookalike", {})

        if lookalike.get("is_lookalike"):
            brand = lookalike.get("matched_brand", "unknown")
            reasons.append(f"Brand impersonation detected: resembles '{brand}'.")

        if features.get("SSLfinal_State") == 1:
            reasons.append("Connection is not encrypted (HTTP instead of HTTPS).")

        if features.get("Prefix_Suffix") == 1 and not lookalike.get("is_lookalike"):
            reasons.append("Domain uses suspicious separators (e.g., hyphen patterns).")

        if features.get("Shortining_Service") == 1:
            reasons.append("URL shortener detected; destination is obscured.")

        if features.get("having_IP_Address") == 1:
            reasons.append("Raw IP address used instead of a normal domain.")

        if features.get("DNSRecord") == 1:
            reasons.append("DNS records could not be resolved for this host.")

        if features.get("Iframe") == 1:
            reasons.append("Embedded iframe detected; can be used in phishing flows.")

        if features.get("URL_Length") == 1:
            reasons.append("Unusually long URL structure.")

        if features.get("_whois_lookup_failed"):
            reasons.append("Domain ownership/age could not be verified (WHOIS unavailable).")
        elif features.get("age_of_domain") == 1:
            reasons.append("Domain appears very new based on registration age.")

        # Expose FIX-01 reasons if detected
        if features.get("_keyword_flagged"):
            reasons.append("Contains highly suspicious keywords commonly used in phishing attacks.")

        return reasons

    def generate_humanized_verdict(self, features: dict, risk: str, confidence: float) -> dict:
        reasons = self._collect_risk_reasons(features)
        key_reasons = reasons[:4]
        confidence_pct_raw = int(round(confidence * 100))
        confidence_pct_display = min(97, confidence_pct_raw)

        if risk == "HIGH_RISK":
            summary = "High phishing risk. Do not submit credentials or payment details."
            if not key_reasons:
                key_reasons = ["Multiple structural indicators matched known phishing behavior."]
            actions = [
                "Do not click further links on this page.",
                "Open the official website manually from a trusted bookmark.",
                "If credentials were entered, change password immediately and enable 2FA.",
            ]
        elif risk == "SUSPICIOUS":
            summary = "Suspicious URL. Treat with caution until verified."
            if not key_reasons:
                key_reasons = ["Some structural signals are unusual but not conclusive."]
            actions = [
                "Verify the domain spelling and TLD carefully.",
                "Avoid logging in until the sender/site is validated.",
                "Use an isolated browser session or security scanner before proceeding.",
            ]
        else:
            summary = "No critical phishing indicators were detected."
            safe_reasons = [
                r for r in reasons
                if "WHOIS unavailable" not in r and "very new" not in r
            ]
            if safe_reasons:
                summary = "No critical phishing indicators were detected, but a few caution signals exist."
                key_reasons = safe_reasons[:3]
            else:
                positive_checks = []
                if features.get("SSLfinal_State") == -1:
                    positive_checks.append("HTTPS detected")
                if not features.get("_lookalike", {}).get("is_lookalike"):
                    positive_checks.append("no brand-impersonation pattern")
                if features.get("having_IP_Address") != 1:
                    positive_checks.append("domain format appears normal")
                key_reasons = positive_checks[:3] if positive_checks else ["Structural checks looked normal."]
            actions = [
                "You can proceed, but still verify sender/context if this came via email.",
                "Never enter credentials if the page behavior feels unusual.",
            ]

        return {
            "summary": summary,
            "confidence": confidence_pct_display,
            "raw_confidence": confidence_pct_raw,
            "key_reasons": key_reasons,
            "recommended_actions": actions,
        }

    def generate_verdict(self, features: dict, risk: str, confidence: float) -> list:
        human = self.generate_humanized_verdict(features, risk, confidence)
        lines = [
            f"SUMMARY: {human['summary']}",
            f"CONFIDENCE: {human['confidence']}%",
        ]
        if human["key_reasons"]:
            lines.append("WHY:")
            for reason in human["key_reasons"]:
                lines.append(f"- {reason}")
        if human["recommended_actions"]:
            lines.append("WHAT TO DO:")
            for action in human["recommended_actions"]:
                lines.append(f"- {action}")
        return lines

    def predict(self, features_dict: dict) -> dict:
        if not self.model:
            return {"error": "Model not trained. Run train_model.py"}

        expected_keys = [
            "having_IP_Address",
            "URL_Length",
            "Shortining_Service",
            "having_At_Symbol",
            "double_slash_redirecting",
            "Prefix_Suffix",
            "having_Sub_Domain",
            "SSLfinal_State",
            "Domain_registeration_length",
            "Favicon",
            "port",
            "HTTPS_token",
            "Request_URL",
            "URL_of_Anchor",
            "Links_in_tags",
            "SFH",
            "Submitting_to_email",
            "Abnormal_URL",
            "Redirect",
            "on_mouseover",
            "RightClick",
            "popUpWidnow",
            "Iframe",
            "age_of_domain",
            "DNSRecord",
            "web_traffic",
            "Page_Rank",
            "Google_Index",
            "Links_pointing_to_page",
            "Statistical_report",
        ]

        feature_vector = [[features_dict.get(k, -1) for k in expected_keys]]
        prediction_input = feature_vector
        try:
            import pandas as pd
            prediction_input = pd.DataFrame(feature_vector, columns=expected_keys)
        except Exception:
            prediction_input = feature_vector
        
        lookalike = features_dict.get("_lookalike", {})
        
        # FIX-01: Keyword matching
        raw_url = features_dict.get("_raw_url", "").lower()
        phishing_keywords = ["login", "secure", "verify", "update", "account", "billing", "support", "auth"]
        keyword_detected = any(kw in raw_url for kw in phishing_keywords) if raw_url else False
        if keyword_detected:
            features_dict["_keyword_flagged"] = True

        try:
            if lookalike.get("is_lookalike") and lookalike.get("similarity", 0) >= 0.85:
                risk = "HIGH_RISK"
                pred = -1
                confidence = 0.99
            else:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    pred = self.model.predict(prediction_input)[0]
                risk = "HIGH_RISK" if pred == -1 else ("SAFE" if pred == 1 else "SUSPICIOUS")
                if hasattr(self.model, "predict_proba"):
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore")
                        proba = self.model.predict_proba(prediction_input)[0]
                    confidence = float(max(proba))
                else:
                    confidence = 0.75

            # Rule floor: non-resolving domains must never be reported as SAFE.
            dns_unresolved = features_dict.get("DNSRecord") == 1
            whois_failed = bool(features_dict.get("_whois_lookup_failed"))
            no_ssl = features_dict.get("SSLfinal_State") == 1
            clone_detected = bool(lookalike.get("is_lookalike"))
            is_ip = features_dict.get("having_IP_Address") == 1

            if dns_unresolved:
                if clone_detected or no_ssl:
                    risk = "HIGH_RISK"
                    pred = -1
                    confidence = max(confidence, 0.9)
                elif risk == "SAFE":
                    risk = "SUSPICIOUS"
                    pred = 0
                    confidence = max(confidence, 0.82 if whois_failed else 0.75)
            
            # IP address hard rule
            if is_ip and no_ssl:
                risk = "HIGH_RISK"
                pred = -1
                confidence = max(confidence, 0.9)
                
            # FIX-01 Keyword hard rule
            if keyword_detected and risk == "SAFE":
                risk = "SUSPICIOUS"
                pred = 0
                confidence = max(confidence, 0.85)

            verdicts = self.generate_verdict(features_dict, risk, confidence)
            humanized = self.generate_humanized_verdict(features_dict, risk, confidence)

            return {
                "prediction_code": int(pred),
                "risk_flag": risk,
                "confidence": round(min(confidence, 0.97), 4),
                "raw_model_confidence": round(confidence, 4),
                "verdicts": verdicts,
                "humanized_verdict": humanized,
                "brand_impersonation": lookalike.get("matched_brand") if lookalike.get("is_lookalike") else None,
            }
        except Exception as e:
            return {"error": str(e)}
