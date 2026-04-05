"""
api/app.py — FastAPI Application Factory
==========================================
Creates and configures the FastAPI application with all middleware,
exception handlers, and routes registered.
"""

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.routes import analyze, health
from core.config import Settings

logger = logging.getLogger("vectraforge.app")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle handler."""
    logger.info("VectraForge server starting — warming up Ollama connection...")
    # Import here to avoid circular deps at module load time
    from core.llm_client import OllamaClient
    client = OllamaClient()
    ok = await client.health_check()
    if ok:
        logger.info("Ollama connection OK")
    else:
        logger.warning("Ollama unreachable — analysis requests will fail until it comes online")
    yield
    logger.info("VectraForge server shutting down")


def create_app() -> FastAPI:
    """Application factory — returns a configured FastAPI instance."""
    settings = Settings()

    app = FastAPI(
        title="VectraForge — Local HTTP Vulnerability Analysis",
        description=(
            "Receives raw HTTP requests from Burp Suite extensions and returns "
            "structured vulnerability analysis via a local Ollama LLM."
        ),
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # ── Middleware ────────────────────────────────────────────────────────────

    # CORS: only allow localhost by default (tighten in production)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

    # Request timing middleware
    @app.middleware("http")
    async def add_timing_header(request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = round((time.perf_counter() - start) * 1000, 2)
        response.headers["X-Process-Time-Ms"] = str(elapsed)
        logger.debug(f"{request.method} {request.url.path} — {elapsed}ms")
        return response

    # ── Exception Handlers ────────────────────────────────────────────────────

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.exception(f"Unhandled exception on {request.url.path}: {exc}")
        return JSONResponse(
            status_code=500,
            content={"error": "Internal server error", "detail": str(exc)},
        )

    # ── Routes ────────────────────────────────────────────────────────────────
    app.include_router(health.router, tags=["Health"])
    app.include_router(analyze.router, tags=["Analysis"])

    return app
