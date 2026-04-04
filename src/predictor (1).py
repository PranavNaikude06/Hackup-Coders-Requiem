import os
import joblib
import numpy as np
import pandas as pd
from src.data_loader import load_config
from src.feature_extractor import extract_features, FEATURE_NAMES


def load_artifacts(config: dict):
    art_dir = config["artifacts"]["directory"]
    scaler  = joblib.load(os.path.join(art_dir, config["artifacts"]["scaler_filename"]))
    xgb     = joblib.load(os.path.join(art_dir, config["artifacts"]["xgb_model_filename"]))
    ann     = joblib.load(os.path.join(art_dir, config["artifacts"]["ann_model_filename"]))
    return scaler, xgb, ann


def predict_url(url: str, config: dict = None) -> dict:
    if config is None:
        config = load_config()

    scaler, xgb, ann = load_artifacts(config)
    features = extract_features(url)

    # Pass as DataFrame with correct column names so scaler uses right order
    X = pd.DataFrame([features], columns=FEATURE_NAMES)
    X_scaled = scaler.transform(X)

    xgb_pred = int(xgb.predict(X_scaled)[0])
    xgb_prob = float(xgb.predict_proba(X_scaled)[0][1])

    ann_pred = int(ann.predict(X_scaled)[0])
    ann_prob = float(ann.predict_proba(X_scaled)[0][1])

    avg_prob = (xgb_prob + ann_prob) / 2
    final_pred = 1 if avg_prob >= 0.5 else 0

    return {
        "url": url,
        "prediction": "Phishing" if final_pred == 1 else "Legitimate",
        "confidence": round(avg_prob * 100, 2),
        "xgboost": {
            "prediction": "Phishing" if xgb_pred == 1 else "Legitimate",
            "probability": round(xgb_prob * 100, 2),
        },
        "ann": {
            "prediction": "Phishing" if ann_pred == 1 else "Legitimate",
            "probability": round(ann_prob * 100, 2),
        },
        "features": dict(zip(FEATURE_NAMES, features)),
    }
