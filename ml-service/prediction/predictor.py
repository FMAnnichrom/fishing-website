"""
Prediction wrapper loading the serialized Scikit-learn model bundle.
"""

import re
from pathlib import Path

import joblib
import numpy as np

from feature_extraction.extractor import FEATURE_NAMES, extract_structural_vector


class PhishingPredictor:
    def __init__(self, model_path: Path):
        self.model_path = model_path
        self.bundle = joblib.load(model_path) if model_path.exists() else None

    def is_loaded(self) -> bool:
        return self.bundle is not None

    def predict(self, url: str) -> dict:
        if not self.bundle:
            return {
                "label": "unavailable",
                "probability": 0.5,
                "confidence": 0,
                "engine": "Scikit-learn RandomForest (model file missing)",
                "modelVersion": "none",
                "topFeatures": [],
            }

        surface = re.sub(r"^https?://", "", url.strip())
        tfidf = self.bundle["vectorizer"].transform([surface]).toarray()
        struct = np.array([extract_structural_vector(url)])
        struct_scaled = self.bundle["scaler"].transform(struct)
        features = np.hstack([struct_scaled, tfidf])

        prob = float(self.bundle["model"].predict_proba(features)[0][1])
        label = "phishing" if prob >= 0.5 else "legitimate"
        confidence = int(round(abs(prob - 0.5) * 200))

        importances = self.bundle["model"].feature_importances_[: len(FEATURE_NAMES)]
        top_idx = np.argsort(importances)[::-1][:5]
        top_features = [
            {
                "name": FEATURE_NAMES[i].replace("_", " "),
                "value": str(round(float(struct[0][i]), 2)),
                "contribution": round(float(importances[i]), 4),
            }
            for i in top_idx
        ]

        return {
            "label": label,
            "probability": round(prob, 4),
            "confidence": confidence,
            "engine": "Scikit-learn RandomForestClassifier (FastAPI)",
            "modelVersion": "1.0.0",
            "topFeatures": top_features,
        }
