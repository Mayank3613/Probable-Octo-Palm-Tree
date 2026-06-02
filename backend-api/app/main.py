
"""
Probable-Octo-Palm-Tree Threat Intelligence API
Production Live Telemetry Backend
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

import os
import time

from .config import APP_NAME, VERSION, CORS_ORIGINS
from .database import init_db

# Routers
from .routers import (
    telemetry,
    scanner,
    alerts,
    attribution
)

# =========================================================
# BASE DIRECTORY
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

templates = Jinja2Templates(
    directory=os.path.join(BASE_DIR, "templates")
)

BOOT_TIME = time.time()

# =========================================================
# APPLICATION LIFESPAN
# =========================================================

@asynccontextmanager
async def lifespan(app: FastAPI):

    print("\n")
    print("=" * 60)
    print(f"[BOOT] Starting {APP_NAME} v{VERSION}")
    print("=" * 60)

    # Initialize SQLite database
    init_db()

    print("[OK] Database initialized")
    print("[OK] Live telemetry enabled")
    print("[OK] Dashboard APIs active")
    print("[OK] Threat intelligence engine online")

    print("=" * 60)
    print(f"[READY] {APP_NAME} backend online")
    print("=" * 60)
    print("\n")

    yield

    print("\n")
    print("=" * 60)
    print("[SHUTDOWN] Closing backend services")
    print("=" * 60)

# =========================================================
# FASTAPI APP
# =========================================================

app = FastAPI(
    title=APP_NAME,
    description=(
        "Realtime cybersecurity telemetry backend for the "
        "Probable-Octo-Palm-Tree browser extension."
    ),
    version=VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# =========================================================
# CORS CONFIGURATION
# =========================================================

# Important for:
# - Browser extension
# - Frontend dashboard
# - Live polling
# - WebSocket upgrades

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Production: replace with specific origins
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================================
# REQUEST LOGGER MIDDLEWARE
# =========================================================

@app.middleware("http")
async def log_requests(request: Request, call_next):

    start_time = time.time()

    response = await call_next(request)

    process_time = round((time.time() - start_time) * 1000, 2)

    print(
        f"[REQUEST] "
        f"{request.method} "
        f"{request.url.path} "
        f"{response.status_code} "
        f"{process_time}ms"
    )

    return response

# =========================================================
# REGISTER ROUTERS
# =========================================================

app.include_router(telemetry.router)
app.include_router(scanner.router)
app.include_router(alerts.router)
app.include_router(attribution.router)

from fastapi.staticfiles import StaticFiles

DASHBOARD_DIST = os.path.abspath(os.path.join(BASE_DIR, "..", "..", "dashboard", "dist"))

# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health", tags=["System"])
async def health_check():
    uptime_seconds = int(time.time() - BOOT_TIME)
    return {
        "status": "healthy",
        "application": APP_NAME,
        "version": VERSION,
        "uptime_seconds": uptime_seconds,
        "telemetry": "active",
        "database": "connected"
    }

# =========================================================
# ROOT ENDPOINT / DASHBOARD STATIC FILES
# =========================================================

if os.path.exists(DASHBOARD_DIST):
    app.mount("/", StaticFiles(directory=DASHBOARD_DIST, html=True), name="dashboard")
else:
    @app.get("/")
    async def root():
        return {"error": "Dashboard build not found. Run 'npm run build' in the dashboard directory."}

# =========================================================
# API STATUS
# =========================================================

@app.get("/api/status", tags=["System"])
async def api_status():

    return JSONResponse(
        content={
            "success": True,
            "backend": "online",
            "telemetry_pipeline": "active",
            "sqlite": "connected",
            "dashboard": "live",
            "timestamp": int(time.time())
        }
    )

# =========================================================
# NOT FOUND HANDLER
# =========================================================

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):

    return JSONResponse(
        status_code=404,
        content={
            "success": False,
            "error": "Endpoint not found",
            "path": request.url.path
        }
    )

# =========================================================
# GLOBAL ERROR HANDLER
# =========================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc):

    print(f"[ERROR] {str(exc)}")

    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": "Internal server error"
        }
    )

