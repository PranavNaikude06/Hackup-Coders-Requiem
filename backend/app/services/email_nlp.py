from __future__ import annotations

from typing import Any
import re


class EmailNLPService:
    """Email NLP analyzer with 3-class verdicts and explainable evidence.

    The service attempts to use a transformers text-classification pipeline when
    available. If unavailable, it falls back to a deterministic keyword heuristic
    so API behavior remains stable in constrained environments.
    """

    def __init__(self) -> None:
        self._pipeline = None
        self._loaded = False
        self._error: str | None = None

    def preload(self) -> None:
        """Load model pipeline once during app startup."""
        if self._loaded:
            return

        try:
            from transformers import pipeline

            self._pipeline = pipeline(
                "text-classification",
                model="distilbert-base-uncased-finetuned-sst-2-english",
                tokenizer="distilbert-base-uncased-finetuned-sst-2-english",
            )
            self._loaded = True
            self._error = None
        except Exception as exc:  # pragma: no cover
            self._pipeline = None
            self._loaded = True
            self._error = str(exc)

    @staticmethod
    def _normalize(text: str) -> str:
        return re.sub(r"\s+", " ", text.strip())

    @staticmethod
    def _extract_evidence(text: str) -> list[str]:
        evidence: list[str] = []
        
        # Split into sentences using common delimiters
        sentences = []
        for s in re.split(r'[.!?\n]', text):
            s = s.strip()
            if s:
                sentences.append(s)

        needles = [
            "verify your account", "confirm your password", "login now", "account suspended", "security alert",
            "urgent", "immediately", "within 24 hours", "expires today",
            "refund", "payment failed", "bank", "invoice", "wire transfer",
            "click here", "open the link", "reset now", "review activity"
        ]

        found_needles = set()

        for sentence in sentences:
            low_s = sentence.lower()
            for needle in needles:
                if needle in low_s and needle not in found_needles:
                    # Clip sentence to a reasonable length if very long
                    clipped = sentence if len(sentence) < 100 else sentence[:97] + "..."
                    evidence.append(f"Suspicious phrasing detected: \"{clipped}\"")
                    found_needles.add(needle)
                    break # Move to next sentence to avoid spamming multiple flags for one sentence
            
            if len(evidence) >= 3:
                break

        if "http://" in text.lower() and len(evidence) < 3:
            evidence.append("non-https (http://) link detected in text")

        return evidence[:3]

    @staticmethod
    def _map_verdict(score: float) -> str:
        if score >= 0.85:
            return "PHISHING"
        if score >= 0.55:
            return "SUSPICIOUS"
        return "SAFE"

    def _score_text(self, text: str) -> tuple[float, dict[str, Any]]:
        # Use transformer output if loaded, otherwise fallback keyword score.
        if self._pipeline is not None:
            result = self._pipeline(text[:1024])[0]
            label = str(result.get("label", ""))
            model_score = float(result.get("score", 0.5))
            # This model is sentiment oriented; map negative sentiment as higher risk.
            risk_score = model_score if label.upper() == "NEGATIVE" else (1.0 - model_score)
            return risk_score, {"provider": "transformers", "label": label, "score": model_score}

        low = text.lower()
        risk_score = 0.1
        weights = {
            "verify": 0.18,
            "password": 0.2,
            "urgent": 0.18,
            "suspend": 0.2,
            "click": 0.15,
            "bank": 0.15,
            "invoice": 0.12,
            "http://": 0.16,
        }
        for token, w in weights.items():
            if token in low:
                risk_score += w

        risk_score = max(0.0, min(0.99, risk_score))
        return risk_score, {"provider": "heuristic", "label": "RISK", "score": risk_score}

    def analyze(self, email_text: str) -> dict[str, Any]:
        normalized = self._normalize(email_text)
        if not normalized:
            return {
                "error": "email_text must not be empty",
                "verdict": "SUSPICIOUS",
                "confidence": 0.55,
                "raw_confidence": 0.55,
                "evidence": ["empty content provided"],
                "model": {"provider": "validation"},
            }

        # Lazy safety: if startup hook didn't run, make one attempt.
        if not self._loaded:
            self.preload()

        risk_score, model_meta = self._score_text(normalized)
        verdict = self._map_verdict(risk_score)
        raw_confidence = float(max(risk_score, 1.0 - risk_score))
        confidence = min(0.97, raw_confidence)

        evidence = self._extract_evidence(normalized)
        if not evidence:
            if verdict == "SAFE":
                evidence = ["no strong phishing cues detected"]
            elif verdict == "SUSPICIOUS":
                evidence = ["mixed risk indicators detected"]
            else:
                evidence = ["high-risk language pattern detected"]

        response = {
            "verdict": verdict,
            "confidence": round(confidence, 4),
            "raw_confidence": round(raw_confidence, 4),
            "evidence": evidence[:3],
            "model": model_meta,
        }

        if self._error:
            response["model_error"] = self._error

        return response
