from __future__ import annotations
from typing import Any
import re

class TextAnalyzer:
    """Standalone text analyzer specifically trained for spam/phishing text detection.
    
    Uses `mshenoda/roberta-spam` pipeline to classify arbitrary text strings.
    """

    def __init__(self) -> None:
        self._pipeline = None
        self._loaded = False
        self._error: str | None = None

    def preload(self) -> None:
        if self._loaded:
            return

        try:
            from transformers import pipeline
            # Loading the spam classification model
            self._pipeline = pipeline(
                "text-classification",
                model="mshenoda/roberta-spam",
                tokenizer="mshenoda/roberta-spam"
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
    def _map_verdict(label: str, score: float) -> tuple[str, float]:
        """Convert roberta-spam label (SPAM/HAM) into our risk metric (PHISHING/SUSPICIOUS/SAFE)"""
        if label.upper() == "SPAM" or label.upper() == "LABEL_1":
            if score >= 0.85:
                return "PHISHING", score * 100.0
            return "SUSPICIOUS", 45.0 + (score * 29.0)
        
        # HAM or SAFE
        # highly confident it is ham = low score
        risk_score = max(0.0, min(40.0, (1.0 - score) * 40))
        return "SAFE", risk_score

    def analyze(self, text: str) -> dict[str, Any]:
        normalized = self._normalize(text)
        if not normalized:
            return {
                "verdict": "SAFE",
                "risk_score": 0.0,
                "confidence": 0.0,
                "error": "Empty text provided"
            }

        if not self._loaded:
            self.preload()

        # Fallback if transformers fails
        if self._pipeline is None:
            return {
                "verdict": "SAFE",
                "risk_score": 0.0,
                "confidence": 0.0,
                "error": self._error or "Model failed to load"
            }

        # Model has a max token length, typically 512. Clip input text.
        clipped_text = normalized[:2048] # pipeline will tokenize and clip internally but we clip string length trivially
        
        try:
            result = self._pipeline(clipped_text)[0]
        except Exception as e:
            return {
                "verdict": "SAFE",
                "risk_score": 0.0,
                "confidence": 0.0,
                "error": f"Inference failed: {str(e)}"
            }

        label = str(result.get("label", ""))
        confidence = float(result.get("score", 0.0))

        verdict, risk_score = self._map_verdict(label, confidence)

        return {
            "verdict": verdict,
            "risk_score": risk_score,
            "confidence": confidence,
            "model": {
                "provider": "mshenoda/roberta-spam",
                "raw_label": label,
                "raw_score": confidence
            }
        }
