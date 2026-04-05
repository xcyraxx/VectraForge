"""
api/routes/analyze.py — /analyze Endpoint
===========================================
Primary endpoint: receives a raw HTTP request (or pre-parsed JSON),
runs it through the parser and LLM analysis pipeline, and returns
a structured vulnerability report.
"""

import logging
import uuid
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from core.parser import HTTPRequestParser
from core.analyzer import VulnerabilityAnalyzer
from core.models import AnalysisRequest, AnalysisResponse

logger = logging.getLogger("burpai.routes.analyze")
router = APIRouter()


# ── Request / Response Schemas ────────────────────────────────────────────────

class RawRequestPayload(BaseModel):
    """Payload schema when sending a raw HTTP request as a string."""
    raw_request: str = Field(
        ...,
        description="Full raw HTTP request text (headers + body)",
        min_length=10,
    )
    target_host: Optional[str] = Field(
        None,
        description="Target hostname/IP (used when Host header is absent)",
    )
    is_https: bool = Field(
        False,
        description="Whether the request was captured over HTTPS",
    )
    notes: Optional[str] = Field(
        None,
        description="Analyst notes or context to pass to the LLM",
        max_length=1000,
    )


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    summary="Analyze an HTTP request for vulnerabilities",
    response_description="Structured vulnerability analysis from the local LLM",
)
async def analyze_request(
    payload: RawRequestPayload,
    background_tasks: BackgroundTasks,
    request: Request,
) -> JSONResponse:
    """
    Accepts a raw HTTP request string, parses it into structured components,
    sends it to the local Ollama LLM, and returns a JSON vulnerability report.

    The report includes:
    - Identified vulnerabilities with severity and confidence
    - Specific payload suggestions per vulnerability class
    - Attack strategy recommendations
    - Overall risk score
    """
    request_id = str(uuid.uuid4())[:8]
    client_ip = request.client.host if request.client else "unknown"
    logger.info(f"[{request_id}] Analysis request from {client_ip} — {len(payload.raw_request)} bytes")

    # ── 1. Parse the raw HTTP request ────────────────────────────────────────
    try:
        parser = HTTPRequestParser()
        parsed = parser.parse(
            raw=payload.raw_request,
            target_host=payload.target_host,
            is_https=payload.is_https,
        )
    except ValueError as e:
        logger.warning(f"[{request_id}] Parse error: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to parse HTTP request: {e}")
    except Exception as e:
        logger.exception(f"[{request_id}] Unexpected parse error")
        raise HTTPException(status_code=500, detail=f"Parse error: {e}")

    logger.debug(
        f"[{request_id}] Parsed: {parsed.method} {parsed.url} | "
        f"headers={len(parsed.headers)} params={len(parsed.parameters)} "
        f"cookies={len(parsed.cookies)} body_len={len(parsed.body or '')}"
    )

    # ── 2. Run LLM analysis ───────────────────────────────────────────────────
    try:
        analyzer = VulnerabilityAnalyzer()
        result = await analyzer.analyze(
            parsed_request=parsed,
            analyst_notes=payload.notes,
            request_id=request_id,
        )
    except TimeoutError:
        logger.error(f"[{request_id}] LLM timeout")
        raise HTTPException(status_code=504, detail="LLM analysis timed out — model may be overloaded")
    except ConnectionError as e:
        logger.error(f"[{request_id}] Ollama unreachable: {e}")
        raise HTTPException(status_code=503, detail=f"Ollama service unavailable: {e}")
    except Exception as e:
        logger.exception(f"[{request_id}] Analysis error")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")

    # ── 3. Background: log result summary ────────────────────────────────────
    background_tasks.add_task(
        _log_result_summary,
        request_id=request_id,
        method=parsed.method,
        url=parsed.url,
        vuln_count=len(result.vulnerabilities),
        risk=result.overall_risk_score,
    )

    logger.info(
        f"[{request_id}] Analysis complete — "
        f"{len(result.vulnerabilities)} vulns | risk={result.overall_risk_score}"
    )
    return JSONResponse(content=result.model_dump())


@router.post(
    "/analyze/batch",
    summary="Analyze multiple HTTP requests",
    response_description="List of structured vulnerability analyses",
)
async def analyze_batch(
    payloads: list[RawRequestPayload],
    request: Request,
) -> JSONResponse:
    """
    Batch endpoint — analyze up to 10 HTTP requests in a single call.
    Results are returned in the same order as inputs.
    """
    if len(payloads) > 10:
        raise HTTPException(status_code=400, detail="Batch size limit is 10 requests")

    results = []
    for i, payload in enumerate(payloads):
        request_id = str(uuid.uuid4())[:8]
        try:
            parser = HTTPRequestParser()
            parsed = parser.parse(
                raw=payload.raw_request,
                target_host=payload.target_host,
                is_https=payload.is_https,
            )
            analyzer = VulnerabilityAnalyzer()
            result = await analyzer.analyze(
                parsed_request=parsed,
                analyst_notes=payload.notes,
                request_id=request_id,
            )
            results.append({"index": i, "status": "ok", "analysis": result.model_dump()})
        except Exception as e:
            logger.warning(f"Batch item {i} failed: {e}")
            results.append({"index": i, "status": "error", "detail": str(e)})

    return JSONResponse(content={"batch_results": results, "total": len(results)})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _log_result_summary(request_id: str, method: str, url: str, vuln_count: int, risk: float):
    """Background task: write a one-line summary to the audit log."""
    audit_logger = logging.getLogger("burpai.audit")
    audit_logger.info(
        f"[{request_id}] {method} {url} | vulns={vuln_count} | risk_score={risk}"
    )
