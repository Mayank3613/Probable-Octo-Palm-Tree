"""Probable-Octo-Palm-Tree Pydantic Models — Request/Response schemas"""

from pydantic import BaseModel, Field
from typing import Any, Literal, Optional
from datetime import datetime


# ========== Telemetry ==========

class ThreatEvent(BaseModel):
    timestamp: str
    threat_type: str
    details: str
    severity: Literal["critical", "high", "medium"] = "medium"
    url: str
    risk_score: Optional[int] = 0


class TelemetryUpload(BaseModel):
    events: list[ThreatEvent]


class ConnectionEvent(BaseModel):
    timestamp: str
    type: str
    url: str
    method: str = ""
    page_url: str = Field(default="", alias="pageUrl")

    model_config = {"populate_by_name": True}


# ========== URL Scanner ==========

class URLScanRequest(BaseModel):
    url: str


class URLScanResponse(BaseModel):
    url: str
    is_suspicious: bool
    score: int
    reason: str


# ========== Alerts ==========

class ThreatLogResponse(BaseModel):
    id: int
    timestamp: str
    threat_type: str
    details: str
    severity: str
    url: str
    risk_score: int = 0
    source: str = "extension"
    created_at: str = ""


class StatsResponse(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    top_domains: list[dict] = []
    recent_24h: int = 0


# ========== Attribution ==========

class DomainAttributionRequest(BaseModel):
    domain: str


class DomainAttributionResponse(BaseModel):
    domain: str
    ip_addresses: list[str] = []
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    name_servers: list[str] = []
    country: Optional[str] = None
    dnssec: Optional[str] = None
    is_suspicious: bool = False


# ========== Generic ==========

class APIResponse(BaseModel):
    success: bool
    message: str
    data: Any = None
