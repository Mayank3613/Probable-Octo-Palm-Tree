"""OctoPlamTree Threat Intelligence API — FastAPI Application"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import os

from .config import APP_NAME, VERSION, CORS_ORIGINS
from .database import init_db
from .routers import telemetry, scanner, alerts, attribution

# Set up templates directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: initialize database."""
    await init_db()
    print(f"[OctoPlamTree] {APP_NAME} v{VERSION} — ready")
    yield
    print("[OctoPlamTree] Shutting down...")


app = FastAPI(
    title=APP_NAME,
    description=(
        "Backend threat intelligence server for the OctoPlamTree browser extension. "
        "Receives telemetry, analyzes URLs, serves threat alerts, and provides domain attribution."
    ),
    version=VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — allow browser extension to connect
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(telemetry.router)
app.include_router(scanner.router)
app.include_router(alerts.router)
app.include_router(attribution.router)


@app.get("/", tags=["System"])
async def root():
    """Welcome endpoint."""
    return {
        "name": APP_NAME,
        "version": VERSION,
        "status": "online",
        "docs": "/docs",
        "dashboard": "/dashboard",
        "endpoints": {
            "telemetry": "POST /telemetry/upload",
            "scan_url": "POST /scan/url",
            "alerts_live": "GET /alerts/live",
            "alerts_history": "GET /alerts/history",
            "alerts_stats": "GET /alerts/stats",
            "attribution": "POST /attribution/domain",
            "health": "GET /health",
        },
    }

@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": VERSION}

@app.get("/dashboard", response_class=HTMLResponse, tags=["UI"])
async def render_dashboard(request: Request):
    """Serve the Premium Threat Intelligence Dashboard."""
    return templates.TemplateResponse(
        request=request, name="dashboard.html", context={"version": VERSION}
    )
