"""Scanner Router — server-side URL threat analysis"""

from fastapi import APIRouter
import httpx
import logging
from ..models import URLScanRequest, URLScanResponse
from ..database import get_db
from ..services.url_analyzer import analyze_url

router = APIRouter(prefix="/scan", tags=["Scanner"])
logger = logging.getLogger(__name__)

# AI Engine Endpoint
AI_ENGINE_URL = "http://127.0.0.1:8001/predict/url"

@router.post("/url", response_model=URLScanResponse)
async def scan_url(request: URLScanRequest):
    """Analyze a URL for phishing/malicious indicators."""
    # 1. Get rule-based analysis
    analysis = analyze_url(request.url)
    rule_score = analysis["score"]
    reason = analysis["reason"]
    
    # 2. Get ML-based analysis from AI Engine
    ml_score = 0
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(AI_ENGINE_URL, json={"url": request.url}, timeout=2.0)
            if resp.status_code == 200:
                data = resp.json()
                ml_score = data.get("ml_score", 0)
                if data.get("is_malicious") and "AI Engine classified as malicious" not in reason:
                    reason = reason + "; AI Engine classified as malicious" if reason else "AI Engine classified as malicious"
    except Exception as e:
        logger.warning(f"Failed to query AI Engine: {e}")
        
    # 3. Blend scores (60% Rule-based, 40% ML-based)
    if ml_score > 0:
        final_score = int((rule_score * 0.6) + (ml_score * 0.4))
    else:
        final_score = rule_score
        
    is_suspicious = final_score >= 35

    # 4. Store scan result
    async with get_db() as db:
        await db.execute(
            "INSERT INTO url_scans (url, score, is_suspicious, reason) VALUES (?, ?, ?, ?)",
            (request.url, final_score, int(is_suspicious), reason),
        )
        await db.commit()

    return URLScanResponse(
        url=request.url,
        is_suspicious=is_suspicious,
        score=final_score,
        reason=reason or "No threats detected",
    )
