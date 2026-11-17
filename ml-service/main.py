"""
FastAPI Machine Learning Inference Microservice for Phishing URL Detection.
"""

from pathlib import Path
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from prediction.predictor import PhishingPredictor

app = FastAPI(title="Phishing URL ML Service", version="1.0.0")
MODEL_PATH = Path(__file__).resolve().parent / "models" / "sklearn_phishing_model.joblib"
predictor = PhishingPredictor(MODEL_PATH)


class PredictRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2048)


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": predictor.is_loaded()}


@app.post("/predict")
def predict(payload: PredictRequest):
    if not payload.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Only http:// and https:// URLs are supported.")
    return predictor.predict(payload.url)
