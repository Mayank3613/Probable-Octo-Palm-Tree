from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
import joblib
import pandas as pd
import os
import json
import logging

from features import extract_features

# ==========================================================
# Logging
# ==========================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

# ==========================================================
# Globals
# ==========================================================

MODEL = None
FEATURE_NAMES = None
MODEL_METADATA = {}

# ==========================================================
# Request Models
# ==========================================================

class PredictionRequest(BaseModel):
    url: str


class BatchPredictionRequest(BaseModel):
    urls: List[str]


# ==========================================================
# Response Models
# ==========================================================

class PredictionResponse(BaseModel):
    url: str
    ml_score: int
    confidence: float
    is_malicious: bool
    risk_level: str
    reasons: List[str]


# ==========================================================
# Utility Functions
# ==========================================================

def get_risk_level(score: int) -> str:

    if score >= 90:
        return "critical"

    if score >= 70:
        return "high"

    if score >= 40:
        return "medium"

    return "low"


def generate_reasons(
    url: str,
    features: Dict[str, Any]
) -> List[str]:

    reasons = []

    if features.get("is_ip", 0):
        reasons.append("Hostname is an IP address")

    if features.get("contains_punycode", 0):
        reasons.append("Punycode detected")

    if features.get("contains_unicode", 0):
        reasons.append("Unicode characters detected")

    if features.get("has_suspicious_tld", 0):
        reasons.append("Suspicious TLD detected")

    if features.get("is_shortened_url", 0):
        reasons.append("URL shortener detected")

    if features.get("contains_login", 0):
        reasons.append("Contains login keyword")

    if features.get("contains_verify", 0):
        reasons.append("Contains verify keyword")

    if features.get("contains_account", 0):
        reasons.append("Contains account keyword")

    if features.get("contains_secure", 0):
        reasons.append("Contains secure keyword")

    if features.get("contains_auth", 0):
        reasons.append("Contains authentication keyword")

    if features.get("contains_banking", 0):
        reasons.append("Contains banking keyword")

    if features.get("contains_wallet", 0):
        reasons.append("Contains wallet keyword")

    if features.get("executable_extension", 0):
        reasons.append("Executable file detected")

    if features.get("contains_hex_encoding", 0):
        reasons.append("Encoded payload detected")

    if features.get("contains_base64_pattern", 0):
        reasons.append("Possible obfuscated content")

    if features.get("double_slash_redirect", 0):
        reasons.append("Redirect-like URL structure")

    if features.get("has_at_symbol", 0):
        reasons.append("@ symbol present")

    if features.get("suspicious_word_count", 0) >= 3:
        reasons.append(
            f"{features['suspicious_word_count']} suspicious keywords"
        )

    if features.get("domain_entropy", 0) > 3.5:
        reasons.append("High entropy domain")

    if features.get("url_entropy", 0) > 4.5:
        reasons.append("High entropy URL")

    if features.get("long_query_string", 0):
        reasons.append("Long query string")

    if not reasons:
        reasons.append("No major phishing indicators detected")

    return reasons


def build_dataframe(features_dict):

    return pd.DataFrame(
        [[features_dict.get(col, 0) for col in FEATURE_NAMES]],
        columns=FEATURE_NAMES
    )


# ==========================================================
# Lifespan
# ==========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    global MODEL
    global FEATURE_NAMES
    global MODEL_METADATA

    base_dir = os.path.dirname(
        os.path.abspath(__file__)
    )

    model_path = os.path.join(
        base_dir,
        "model.joblib"
    )

    features_path = os.path.join(
        base_dir,
        "feature_names.joblib"
    )

    metadata_path = os.path.join(
        base_dir,
        "model_metadata.json"
    )

    try:

        if os.path.exists(model_path):

            MODEL = joblib.load(model_path)

            logger.info(
                "Model loaded successfully"
            )

        if os.path.exists(features_path):

            FEATURE_NAMES = joblib.load(
                features_path
            )

            logger.info(
                f"{len(FEATURE_NAMES)} features loaded"
            )

        if os.path.exists(metadata_path):

            with open(
                metadata_path,
                "r"
            ) as f:

                MODEL_METADATA = json.load(f)

    except Exception as e:

        logger.error(
            f"Startup error: {e}"
        )

    yield
# ==========================================================
# FastAPI
# ==========================================================

app = FastAPI(
    title="OctoPalmTree AI Engine",
    version="2.0.0",
    lifespan=lifespan
)
# ==========================================================
# Telemetry Compatibility Endpoints
# ==========================================================

@app.get("/telemetry/stats")
async def telemetry_stats():
    return {
        "total_events": 0,
        "critical_events": 0,
        "high_events": 0,
        "medium_events": 0,
        "low_events": 0
    }

@app.get("/telemetry/live")
async def telemetry_live(limit: int = 50):
    return []

@app.get("/telemetry/critical")
async def telemetry_critical(limit: int = 20):
    return []

@app.get("/telemetry/analytics")
async def telemetry_analytics():
    return {
        "total_scans": 0,
        "malicious_detected": 0,
        "safe_urls": 0,
        "average_risk_score": 0
    }



# ==========================================================
# Legacy Compatibility Endpoint
# ==========================================================

@app.post("/scan/url")
async def legacy_scan_url(request: PredictionRequest):
    """
    Legacy endpoint used by backend-api and dashboard.

    Returns the OLD response format:
    {
        "url": "...",
        "is_suspicious": true,
        "score": 91,
        "reason": "..."
    }
    """

    if MODEL is None:
        raise HTTPException(
            status_code=503,
            detail="Model not loaded"
        )

    try:

        url = request.url

        features = extract_features(url)

        df = build_dataframe(features)

        probabilities = MODEL.predict_proba(df)[0]

        malicious_prob = float(probabilities[1])

        score = int(malicious_prob * 100)

        reasons = generate_reasons(
            url,
            features
        )

        return {
            "url": url,
            "is_suspicious": score >= 50,
            "score": score,
            "reason": ", ".join(reasons)
        }

    except Exception as e:

        logger.exception(
            "Legacy scan failed"
        )

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )




# ==========================================================
# Model Info
# ==========================================================

@app.get("/model/info")
async def model_info():

    return MODEL_METADATA


# ==========================================================
# Feature List
# ==========================================================
@app.get("/health")
async def health():
    return {
        "status": "healthy" if MODEL is not None else "degraded",
        "model_loaded": MODEL is not None,
        "feature_count": len(FEATURE_NAMES) if FEATURE_NAMES else 0,
        "version": "2.0.0"
    }

@app.get("/features")
async def features():

    return {
        "feature_count":
            len(FEATURE_NAMES),

        "features":
            FEATURE_NAMES
    }


# ==========================================================
# Analyze URL
# ==========================================================

@app.post("/analyze/url")
async def analyze_url(
    request: PredictionRequest
):

    feature_data = extract_features(
        request.url
    )

    return {
        "url":
            request.url,

        "features":
            feature_data,

        "reasons":
            generate_reasons(
                request.url,
                feature_data
            )
    }


# ==========================================================
# Predict Single URL
# ==========================================================

@app.post(
    "/predict/url",
    response_model=PredictionResponse
)
async def predict_url(
    request: PredictionRequest
):

    if MODEL is None:
        raise HTTPException(
            status_code=503,
            detail="Model not loaded"
        )

    try:

        url = request.url

        features = extract_features(
            url
        )

        df = build_dataframe(
            features
        )

        probabilities = (
            MODEL.predict_proba(df)[0]
        )

        malicious_prob = float(
            probabilities[1]
        )

        confidence = float(
            max(probabilities)
        )

        score = int(
            malicious_prob * 100
        )

        risk_level = get_risk_level(
            score
        )

        reasons = generate_reasons(
            url,
            features
        )

        return PredictionResponse(
            url=url,
            ml_score=score,
            confidence=confidence,
            is_malicious=score >= 50,
            risk_level=risk_level,
            reasons=reasons
        )

    except Exception as e:

        logger.exception(
            "Prediction failed"
        )

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# ==========================================================
# Batch Prediction
# ==========================================================

@app.post("/predict/batch")
async def predict_batch(
    request: BatchPredictionRequest
):

    if MODEL is None:

        raise HTTPException(
            status_code=503,
            detail="Model not loaded"
        )

    results = []

    for url in request.urls:

        try:

            features = extract_features(
                url
            )

            df = build_dataframe(
                features
            )

            probabilities = (
                MODEL.predict_proba(df)[0]
            )

            malicious_prob = float(
                probabilities[1]
            )

            confidence = float(
                max(probabilities)
            )

            score = int(
                malicious_prob * 100
            )

            results.append({
                "url": url,
                "ml_score": score,
                "confidence": confidence,
                "risk_level":
                    get_risk_level(score),

                "is_malicious":
                    score >= 50,

                "reasons":
                    generate_reasons(
                        url,
                        features
                    )
            })

        except Exception as e:

            results.append({
                "url": url,
                "error": str(e)
            })

    return {
        "total_urls":
            len(request.urls),

        "results":
            results
    }


# ==========================================================
# Root Endpoint
# ==========================================================

@app.get("/")
async def root():

    return {
        "name":
            "OctoPalmTree AI Engine",

        "version":
            "2.0.0",

        "endpoints": [
            "/health",
            "/model/info",
            "/features",
            "/analyze/url",
            "/predict/url",
            "/predict/batch"
        ]
    }