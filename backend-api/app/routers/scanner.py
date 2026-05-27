"""Scanner Router — server-side URL threat analysis"""

from fastapi import APIRouter
from ..models import URLScanRequest, URLScanResponse
from ..database import get_db
from ..services.url_analyzer import analyze_url

router = APIRouter(prefix="/scan", tags=["Scanner"])


@router.post("/url", response_model=URLScanResponse)
async def scan_url(request: URLScanRequest):
    """Analyze a URL for phishing/malicious indicators."""
    analysis = analyze_url(request.url)

    # Store scan result
    async with get_db() as db:
        await db.execute(
            "INSERT INTO url_scans (url, score, is_suspicious, reason) VALUES (?, ?, ?, ?)",
            (request.url, analysis["score"], int(analysis["is_suspicious"]), analysis["reason"]),
        )
        await db.commit()

    return URLScanResponse(
        url=request.url,
        is_suspicious=analysis["is_suspicious"],
        score=analysis["score"],
        reason=analysis["reason"] or "No threats detected",
    )
