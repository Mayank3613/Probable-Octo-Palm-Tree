"""Telemetry Router — receives threat events from the browser extension"""

from fastapi import APIRouter
from ..models import TelemetryUpload, APIResponse
from ..database import get_db
from ..config import MAX_EVENTS_PER_UPLOAD

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


@router.post("/upload", response_model=APIResponse)
async def upload_telemetry(payload: TelemetryUpload):
    """Receive threat events from the browser extension and store them."""
    events = payload.events[:MAX_EVENTS_PER_UPLOAD]

    if not events:
        return APIResponse(success=True, message="No events to process", data={"stored": 0})

    async with get_db() as db:
        for event in events:
            await db.execute(
                """INSERT INTO threat_logs (timestamp, threat_type, details, severity, url, risk_score, source)
                   VALUES (?, ?, ?, ?, ?, ?, 'extension')""",
                (event.timestamp, event.threat_type, event.details,
                 event.severity, event.url, event.risk_score or 0),
            )
        await db.commit()

    return APIResponse(
        success=True,
        message=f"Stored {len(events)} threat events",
        data={"stored": len(events)},
    )
