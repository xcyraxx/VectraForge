"""
api/routes/health.py — Health & Status Endpoints
==================================================
"""

import logging
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from core.llm_client import OllamaClient
from core.config import Settings

logger = logging.getLogger("vectraforge.routes.health")
router = APIRouter()


@router.get("/health", summary="Server health check")
async def health() -> JSONResponse:
    """Basic liveness probe — returns 200 if the server is running."""
    return JSONResponse({"status": "ok", "service": "VectraForge"})


@router.get("/health/full", summary="Full health check including Ollama")
async def health_full() -> JSONResponse:
    """
    Deep health check — verifies Ollama is reachable and the configured
    model is available.
    """
    settings = Settings()
    client = OllamaClient()

    ollama_ok = await client.health_check()
    model_ok = await client.model_available(settings.ollama_model) if ollama_ok else False

    status = "ok" if (ollama_ok and model_ok) else "degraded"
    code = 200 if status == "ok" else 503

    return JSONResponse(
        status_code=code,
        content={
            "status": status,
            "service": "VectraForge",
            "ollama": {
                "reachable": ollama_ok,
                "model": settings.ollama_model,
                "model_loaded": model_ok,
                "base_url": settings.ollama_base_url,
            },
        },
    )


@router.get("/", summary="Root — API info")
async def root() -> JSONResponse:
    return JSONResponse({
        "service": "VectraForge Local Vulnerability Analysis Server",
        "version": "1.0.0",
        "endpoints": {
            "POST /analyze": "Analyze a single HTTP request",
            "POST /analyze/batch": "Analyze up to 10 HTTP requests",
            "GET /health": "Liveness probe",
            "GET /health/full": "Full health check",
            "GET /docs": "Interactive API documentation",
        },
    })
