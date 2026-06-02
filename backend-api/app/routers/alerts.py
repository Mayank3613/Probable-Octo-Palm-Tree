"""Alerts Router — threat feed, history, and statistics"""

from fastapi import APIRouter, Query
from typing import Optional
from urllib.parse import urlparse
from ..models import ThreatLogResponse, StatsResponse
from ..database import get_db
from ..config import DEFAULT_PAGE_SIZE

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("/live", response_model=list[ThreatLogResponse])
async def get_live_alerts():
    """Get the 50 most recent threat alerts."""
    async with get_db() as db:
        cursor = await db.execute(
            "SELECT * FROM threat_logs ORDER BY timestamp DESC LIMIT 50"
        )
        rows = await cursor.fetchall()
        return [_row_to_threat(row) for row in rows]


@router.get("/history", response_model=dict)
async def get_alert_history(
    page: int = Query(1, ge=1),
    size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=200),
    severity: Optional[str] = None,
    threat_type: Optional[str] = None,
):
    """Get paginated threat history with optional filters."""
    offset = (page - 1) * size
    conditions = []
    params: list = []

    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if threat_type:
        conditions.append("threat_type LIKE ?")
        params.append(f"%{threat_type}%")

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    async with get_db() as db:
        # Get total count
        count_cursor = await db.execute(
            f"SELECT COUNT(*) FROM threat_logs {where}", params
        )
        total = (await count_cursor.fetchone())[0]

        # Get page
        cursor = await db.execute(
            f"SELECT * FROM threat_logs {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [size, offset],
        )
        rows = await cursor.fetchall()

    return {
        "page": page,
        "size": size,
        "total": total,
        "total_pages": max(1, (total + size - 1) // size),
        "data": [_row_to_threat(row) for row in rows],
    }


@router.get("/stats", response_model=StatsResponse)
async def get_stats():
    """Get threat statistics — severity breakdown, top domains, recent 24h count."""
    async with get_db() as db:
        # Total
        cur = await db.execute("SELECT COUNT(*) FROM threat_logs")
        total = (await cur.fetchone())[0]

        # By severity
        cur = await db.execute("SELECT COUNT(*) FROM threat_logs WHERE severity = 'critical'")
        critical = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM threat_logs WHERE severity = 'high'")
        high = (await cur.fetchone())[0]
        cur = await db.execute("SELECT COUNT(*) FROM threat_logs WHERE severity = 'medium'")
        medium = (await cur.fetchone())[0]

        # Recent 24h
        cur = await db.execute(
            "SELECT COUNT(*) FROM threat_logs WHERE timestamp >= datetime('now', '-1 day')"
        )
        recent_24h = (await cur.fetchone())[0]

        # Top 10 domains
        cur = await db.execute("SELECT url FROM threat_logs WHERE url IS NOT NULL AND url != ''")
        rows = await cur.fetchall()

    domain_counts: dict[str, int] = {}
    for row in rows:
        try:
            host = urlparse(row[0]).hostname
            if host:
                domain_counts[host] = domain_counts.get(host, 0) + 1
        except Exception:
            pass

    top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return StatsResponse(
        total=total,
        critical=critical,
        high=high,
        medium=medium,
        top_domains=[{"domain": d, "count": c} for d, c in top_domains],
        recent_24h=recent_24h,
    )


def _row_to_threat(row) -> ThreatLogResponse:
    return ThreatLogResponse(
        id=row[0],
        timestamp=row[1] or "",
        threat_type=row[2] or "",
        details=row[3] or "",
        severity=row[4] or "medium",
        url=row[5] or "",
        risk_score=row[6] or 0,
        source=row[7] or "extension",
        created_at=row[9] or "",
    )
