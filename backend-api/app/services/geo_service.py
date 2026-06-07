import asyncio
import time
import httpx
from typing import Optional
from dataclasses import dataclass, field

DEGRADED_THRESHOLD_MS = 250
CIRCUIT_OPEN_AFTER    = 3      # consecutive failures before circuit opens
CIRCUIT_RESET_AFTER_S = 60     # seconds before retrying primary

@dataclass
class GeoResult:
    ip:           str
    country:      Optional[str]
    country_code: Optional[str]
    city:         Optional[str]
    asn:          Optional[str]
    org:          Optional[str]
    source:       str           # "maxmind" | "ip-api" | "unavailable"
    latency_ms:   Optional[float] = None

class GeoIPService:
    def __init__(self, maxmind_account_id: str, maxmind_license_key: str):
        self._account  = maxmind_account_id
        self._key      = maxmind_license_key
        self._failures = 0
        self._opened   = 0.0           # timestamp circuit was opened
        self._status   = "online"
        self._latency  = 0.0
        self._lock     = asyncio.Lock()

    # ── public ───────────────────────────────────────────────────────────

    async def lookup(self, ip: str) -> GeoResult:
        circuit_open = (
            self._failures >= CIRCUIT_OPEN_AFTER
            and (time.monotonic() - self._opened) < CIRCUIT_RESET_AFTER_S
        )
        if not circuit_open:
            result = await self._try_primary(ip)
            if result:
                return result
        return await self._fallback(ip)

    def health(self) -> dict:
        return {
            "provider":          "maxmind",
            "fallback_provider": "ip-api.com",
            "status":            self._status,
            "latency_ms":        round(self._latency, 1),
        }

    # ── primary ──────────────────────────────────────────────────────────

    async def _try_primary(self, ip: str) -> Optional[GeoResult]:
        url = f"https://geoip.maxmind.com/geoip/v2.1/city/{ip}"
        t0  = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                r = await client.get(url, auth=(self._account, self._key))
                r.raise_for_status()
                d   = r.json()
                lat = (time.monotonic() - t0) * 1000

            async with self._lock:
                self._failures = 0
                self._latency  = lat
                self._status   = "degraded" if lat > DEGRADED_THRESHOLD_MS else "online"

            return GeoResult(
                ip           = ip,
                country      = d.get("country", {}).get("names", {}).get("en"),
                country_code = d.get("country", {}).get("iso_code"),
                city         = d.get("city",    {}).get("names", {}).get("en"),
                asn          = str(d.get("traits", {}).get("autonomous_system_number", "")),
                org          = d.get("traits", {}).get("isp"),
                source       = "maxmind",
                latency_ms   = lat,
            )

        except Exception:
            async with self._lock:
                self._failures += 1
                if self._failures >= CIRCUIT_OPEN_AFTER:
                    self._opened = time.monotonic()
                self._status = "offline"
            return None

    # ── fallback ─────────────────────────────────────────────────────────

    async def _fallback(self, ip: str) -> GeoResult:
        url = (
            f"http://ip-api.com/json/{ip}"
            "?fields=status,country,countryCode,city,isp,org,as,query"
        )
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(url)
                r.raise_for_status()
                d = r.json()
            if d.get("status") != "success":
                raise ValueError("ip-api returned non-success")
            return GeoResult(
                ip           = ip,
                country      = d.get("country"),
                country_code = d.get("countryCode"),
                city         = d.get("city"),
                asn          = d.get("as"),
                org          = d.get("org"),
                source       = "ip-api",
            )
        except Exception:
            return GeoResult(
                ip=ip, country=None, country_code=None,
                city=None, asn=None, org=None, source="unavailable",
            )
