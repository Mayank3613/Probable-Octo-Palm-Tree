from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import joblib
import pandas as pd
import os
import logging
from features import extract_features

app = FastAPI(title="OctoPlamTree AI Engine", version="1.0.0")

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global variables for model and feature names
MODEL = None
FEATURE_NAMES = None

class PredictionRequest(BaseModel):
    url: str

class PredictionResponse(BaseModel):
    url: str
    ml_score: int
    is_malicious: bool
    confidence: float

@app.on_event("startup")
async def load_model():
    global MODEL, FEATURE_NAMES
    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(base_dir, "model.joblib")
    features_path = os.path.join(base_dir, "feature_names.joblib")
    
    if os.path.exists(model_path) and os.path.exists(features_path):
        logger.info(f"Loading ML model from {model_path}...")
        MODEL = joblib.load(model_path)
        FEATURE_NAMES = joblib.load(features_path)
        logger.info("ML model loaded successfully.")
    else:
        logger.warning(f"Model not found at {model_path}. Please run train.py first.")

@app.get("/health")
async def health_check():
    status = "healthy" if MODEL is not None else "degraded (model not loaded)"
    return {"status": status, "version": "1.0.0"}

@app.post("/predict/url", response_model=PredictionResponse)
async def predict_url(request: PredictionRequest):
    if MODEL is None or FEATURE_NAMES is None:
        raise HTTPException(status_code=503, detail="Model not loaded")
        
    try:
        url = request.url
        features_dict = extract_features(url)
        
        # Create DataFrame with the exact columns used during training
        df = pd.DataFrame([features_dict], columns=FEATURE_NAMES)
        
        # Predict probability of class 1 (malicious)
        proba = MODEL.predict_proba(df)[0]
        malicious_prob = float(proba[1])
        
        # Calculate a 0-100 score
        ml_score = int(malicious_prob * 100)
        is_malicious = ml_score >= 50
        
        return PredictionResponse(
            url=url,
            ml_score=ml_score,
            is_malicious=is_malicious,
            confidence=max(float(proba[0]), float(proba[1]))
        )
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
