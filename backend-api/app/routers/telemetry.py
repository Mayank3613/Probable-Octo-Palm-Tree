# FINAL `backend-api/app/routers/telemetry.py`
"""
Live Telemetry Router
Receives telemetry from browser extension
Stores events into SQLite
Provides realtime dashboard APIs
"""

from fastapi import APIRouter, HTTPException
from datetime import datetime
from typing import Optional

from app.database import get_db_connection

router = APIRouter(
    prefix="/telemetry",
    tags=["Telemetry"]
)


# =========================================================
# HEALTH CHECK
# =========================================================

@router.get("/health")
def telemetry_health():
    return {
        "status": "ok",
        "service": "telemetry"
    }


# =========================================================
# RECEIVE TELEMETRY FROM EXTENSION
# =========================================================

@router.post("/upload")
def upload_telemetry(payload: dict):

    if not payload:
        raise HTTPException(
            status_code=400,
            detail="No telemetry payload received"
        )

    events = payload.get("events", [])

    if not isinstance(events, list):
        raise HTTPException(
            status_code=400,
            detail="Events must be an array"
        )

    conn = get_db_connection()
    cursor = conn.cursor()

    inserted = 0

    for event in events:

        try:
            threat_type = event.get("threat_type", "unknown")
            severity = event.get("severity", "low")
            url = event.get("url", "")
            details = event.get("details", "")
            source = event.get("source", "browser-extension")
            risk_score = event.get("risk_score", 0)
            action = event.get("action", "detected")

            timestamp = event.get("timestamp")

            if not timestamp:
                timestamp = datetime.utcnow().isoformat()

            cursor.execute(
                """
                INSERT INTO threat_logs (
                    timestamp,
                    threat_type,
                    severity,
                    url,
                    details,
                    source,
                    risk_score,
                    action
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    threat_type,
                    severity,
                    url,
                    details,
                    source,
                    risk_score,
                    action
                )
            )

            inserted += 1

        except Exception as e:
            print(f"Telemetry insert error: {e}")

    conn.commit()
    conn.close()

    return {
        "success": True,
        "inserted": inserted,
        "received": len(events)
    }


# =========================================================
# LIVE THREAT FEED
# =========================================================

@router.get("/live")
def get_live_telemetry(limit: int = 100):

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM threat_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    )

    rows = cursor.fetchall()

    conn.close()

    events = [dict(row) for row in rows]

    return {
        "events": events,
        "count": len(events)
    }


# =========================================================
# DASHBOARD STATS
# =========================================================

@router.get("/stats")
def get_dashboard_stats():

    conn = get_db_connection()
    cursor = conn.cursor()

    # Total threats
    cursor.execute(
        "SELECT COUNT(*) FROM threat_logs"
    )

    total = cursor.fetchone()[0]

    # Critical threats
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM threat_logs
        WHERE LOWER(severity) = 'critical'
        """
    )

    critical = cursor.fetchone()[0]

    # High threats
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM threat_logs
        WHERE LOWER(severity) = 'high'
        """
    )

    high = cursor.fetchone()[0]

    # Medium threats
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM threat_logs
        WHERE LOWER(severity) = 'medium'
        """
    )

    medium = cursor.fetchone()[0]

    # Low threats
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM threat_logs
        WHERE LOWER(severity) = 'low'
        """
    )

    low = cursor.fetchone()[0]

    # Average risk score
    cursor.execute(
        """
        SELECT AVG(risk_score)
        FROM threat_logs
        """
    )

    avg_risk = cursor.fetchone()[0]

    if avg_risk is None:
        avg_risk = 0

    # Threats in last 24 hours
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM threat_logs
        WHERE timestamp >= datetime('now', '-1 day')
        """
    )

    recent_24h = cursor.fetchone()[0]

    # Most targeted domains
    cursor.execute(
        """
        SELECT url, COUNT(*) as count
        FROM threat_logs
        WHERE url != ''
        GROUP BY url
        ORDER BY count DESC
        LIMIT 10
        """
    )

    top_domains = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        "stats": {
            "total": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "avg_risk": round(avg_risk, 1),
            "recent_24h": recent_24h,
            "top_domains": top_domains
        }
    }


# =========================================================
# CRITICAL THREATS ONLY
# =========================================================

@router.get("/critical")
def get_critical_threats(limit: int = 20):

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT *
        FROM threat_logs
        WHERE LOWER(severity) = 'critical'
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    )

    rows = cursor.fetchall()

    conn.close()

    return {
        "events": [dict(row) for row in rows]
    }


# =========================================================
# RECENT THREATS
# =========================================================

@router.get("/recent")
def get_recent_threats(hours: int = 1):

    conn = get_db_connection()
    cursor = conn.cursor()

    query = f"""
        SELECT *
        FROM threat_logs
        WHERE timestamp >= datetime('now', '-{hours} hours')
        ORDER BY id DESC
    """

    cursor.execute(query)

    rows = cursor.fetchall()

    conn.close()

    return {
        "events": [dict(row) for row in rows],
        "hours": hours
    }


# =========================================================
# DELETE ALL TELEMETRY
# =========================================================

@router.delete("/clear")
def clear_telemetry():

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM threat_logs"
    )

    conn.commit()
    conn.close()

    return {
        "success": True,
        "message": "Telemetry cleared"
    }


@router.get("/analytics")
def get_analytics():

    conn = get_db_connection()
    cursor = conn.cursor()

    # Weekly trend
    cursor.execute("""
        SELECT
            DATE(timestamp) as day,
            COUNT(*) as count
        FROM threat_logs
        WHERE timestamp >= datetime('now', '-7 days')
        GROUP BY DATE(timestamp)
        ORDER BY day ASC
    """)

    weekly = [dict(row) for row in cursor.fetchall()]

    # Severity distribution
    cursor.execute("""
        SELECT
            severity,
            COUNT(*) as count
        FROM threat_logs
        GROUP BY severity
    """)

    severity = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return {
        "weekly": weekly,
        "severity": severity
    }



# =========================================================
# LIVE METRICS FOR DASHBOARD CARDS
# =========================================================

@router.get("/metrics")
def get_live_metrics():

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM threat_logs"
    )

    total = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM threat_logs
        WHERE LOWER(action) = 'blocked'
        """
    )

    blocked = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM threat_logs
        WHERE LOWER(severity) = 'critical'
        """
    )

    critical = cursor.fetchone()[0]

    cursor.execute(
        """
        SELECT AVG(risk_score)
        FROM threat_logs
        """
    )

    avg_risk = cursor.fetchone()[0] or 0

    conn.close()

    return {
        "total_threats": total,
        "blocked_threats": blocked,
        "critical_threats": critical,
        "average_risk": round(avg_risk, 1)
    }
