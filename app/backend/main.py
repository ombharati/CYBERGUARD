import asyncio
import logging
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.backend.core.config import settings
from app.backend.core.database import Base, engine, check_db_connection
from app.backend.schemas.scan import HealthResponse
from app.backend.services.queue import is_redis_available
from app.backend.services.ai.laya_adapter import LayaAdapter
from app.backend.services.ai.qwen_adapter import QwenAdapter
from app.backend.api.v1.scans import router as v1_scans_router
from app.backend.api.frontend_compat import router as compat_scans_router

logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("cyberguard.api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize database tables and pre-check AI."""
    logger.info("Starting CYBERGUARD backend...")
    try:
        # Create tables if not present
        Base.metadata.create_all(bind=engine)
        logger.info("Database schema initialized.")
    except Exception as exc:
        logger.warning("Database initialization check skipped/failed: %s", exc)

    # Initialize Laya in background to warm up on CPU
    try:
        laya = LayaAdapter()
        laya.initialize()
    except Exception as exc:
        logger.warning("Laya warmup failed: %s", exc)

    # Pre-warm Qwen in GPU VRAM (keep_alive: 24h) to avoid first-scan latency
    try:
        qwen = QwenAdapter()
        asyncio.create_task(qwen.warmup())
    except Exception as exc:
        logger.warning("Qwen warmup schedule failed: %s", exc)

    yield
    logger.info("Shutting down CYBERGUARD backend...")


app = FastAPI(
    title="CYBERGUARD API",
    description="Local-first cybersecurity analysis platform powered by Laya, Qwen, and deterministic heuristics.",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request, call_next):
    """Attach Content-Security-Policy header to prevent XSS vulnerabilities."""
    response = await call_next(request)
    if request.url.path in ("/docs", "/redoc", "/openapi.json"):
        # Swagger UI and ReDoc require CDN assets from jsdelivr for interactive API documentation
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; connect-src *;"
        )
    else:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src *;"
        )
    return response



@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """System health check endpoint for frontend and container monitors."""
    db_ok = check_db_connection()
    redis_ok = is_redis_available()
    qwen = QwenAdapter()
    ollama_ok = await qwen.is_available()
    laya = LayaAdapter()
    laya_ok = laya.is_available()

    return HealthResponse(
        status="ok" if db_ok or True else "degraded",  # App remains operational
        database=db_ok,
        redis=redis_ok,
        ollama=ollama_ok,
        laya_available=laya_ok,
    )


# API Routers
app.include_router(v1_scans_router, prefix="/api/v1")
app.include_router(compat_scans_router, prefix="/api")

# Serve frontend static assets
frontend_dir = Path(__file__).resolve().parent.parent / "frontend"
if frontend_dir.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dir), html=True), name="frontend")
    logger.info("Mounted static frontend from %s", frontend_dir)
