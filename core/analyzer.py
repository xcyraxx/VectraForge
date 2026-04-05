"""
core/analyzer.py — Vulnerability Analyzer
===========================================
Orchestrates the full analysis pipeline:
  1. Build a structured LLM prompt from the parsed request
  2. Call the Ollama LLM via OllamaClient
  3. Parse the LLM's JSON response into AnalysisResponse
  4. Apply heuristic post-processing and scoring

The LLM is instructed to respond ONLY in JSON. If parsing fails we
fall back to a best-effort extraction from raw text.
"""

import json
import logging
import re
import time
from typing import Optional

from core.config import Settings
from core.llm_client import OllamaClient
from core.models import (
    AnalysisRequest,
    AnalysisResponse,
    AttackStrategy,
    Confidence,
    ParsedHTTPRequest,
    PayloadSuggestion,
    Severity,
    Vulnerability,
    VulnClass,
)
from core.prompt_builder import PromptBuilder

logger = logging.getLogger("burpai.analyzer")


class VulnerabilityAnalyzer:
    """
    High-level orchestrator that coordinates prompt building, LLM calls,
    and structured response parsing.
    """

    def __init__(self):
        self.settings = Settings()
        self.client   = OllamaClient()
        self.prompt_builder = PromptBuilder()

    async def analyze(
        self,
        parsed_request: ParsedHTTPRequest,
        analyst_notes: Optional[str] = None,
        request_id: str = "",
    ) -> AnalysisResponse:
        """
        Run the full analysis pipeline and return a structured result.

        Args:
            parsed_request: Structured HTTP request from the parser.
            analyst_notes:  Optional analyst context passed to the LLM.
            request_id:     Short trace ID for logging.

        Returns:
            AnalysisResponse with all findings.
        """
        t0 = time.perf_counter()

        # ── 1. Build prompt ───────────────────────────────────────────────────
        prompt = self.prompt_builder.build(
            request=parsed_request,
            analyst_notes=analyst_notes,
        )
        logger.debug(f"[{request_id}] Prompt length: {len(prompt)} chars")

        # ── 2. Call LLM ───────────────────────────────────────────────────────
        raw_response = await self.client.generate(
            prompt=prompt,
            system_prompt=self._system_prompt(),
        )
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
        logger.debug(f"[{request_id}] LLM responded in {elapsed_ms}ms — {len(raw_response)} chars")

        # ── 3. Parse LLM JSON response ────────────────────────────────────────
        try:
            analysis_data = self._extract_json(raw_response)
        except Exception as e:
            logger.warning(f"[{request_id}] JSON extraction failed ({e}), using fallback")
            analysis_data = self._fallback_parse(raw_response)

        # ── 4. Build structured response ──────────────────────────────────────
        response = self._build_response(
            data=analysis_data,
            parsed_request=parsed_request,
            request_id=request_id,
            elapsed_ms=elapsed_ms,
            raw_llm=raw_response if self.settings.include_raw_llm_output else None,
        )
        return response

    # ── Prompt & parsing ──────────────────────────────────────────────────────

    def _system_prompt(self) -> str:
        return (
            "You are an expert web application penetration tester and security researcher. "
            "You analyze HTTP requests for security vulnerabilities with precision and depth. "
            "You MUST respond ONLY with a valid JSON object — no prose, no markdown fences, "
            "no explanation outside the JSON. "
            "Your analysis must be technically accurate and actionable for a security professional."
        )

    def _extract_json(self, text: str) -> dict:
        """
        Extract and parse a JSON object from LLM output.
        Handles common wrapping patterns like ```json ... ``` fences.
        """
        # Strip markdown code fences if present
        text = re.sub(r"```(?:json)?\s*", "", text).strip()
        text = text.rstrip("`").strip()

        # Try direct parse first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Find the first { ... } block spanning the whole response
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        if brace_match:
            return json.loads(brace_match.group(0))

        raise ValueError("No valid JSON object found in LLM output")

    def _fallback_parse(self, text: str) -> dict:
        """
        Emergency fallback when JSON extraction fails completely.
        Returns a minimal structure with the raw text as a finding.
        """
        logger.warning("Using fallback parser — LLM did not return valid JSON")
        return {
            "overall_risk_score": 5.0,
            "risk_label": "medium",
            "surface_summary": "LLM response could not be parsed as JSON. See raw_llm_output.",
            "vulnerabilities": [],
            "attack_strategies": [],
            "interesting_observations": ["Raw LLM output preserved in raw_llm_output field."],
        }

    def _build_response(
        self,
        data: dict,
        parsed_request: ParsedHTTPRequest,
        request_id: str,
        elapsed_ms: float,
        raw_llm: Optional[str],
    ) -> AnalysisResponse:
        """Convert the parsed LLM dict into a typed AnalysisResponse."""

        vulns = [
            self._parse_vuln(v)
            for v in data.get("vulnerabilities", [])
            if isinstance(v, dict)
        ]

        strategies = [
            self._parse_strategy(s)
            for s in data.get("attack_strategies", [])
            if isinstance(s, dict)
        ]

        risk_score = float(data.get("overall_risk_score", 0.0))
        risk_score = max(0.0, min(10.0, risk_score))

        risk_label_raw = data.get("risk_label", self._score_to_label(risk_score))
        try:
            risk_label = Severity(risk_label_raw.lower())
        except (ValueError, AttributeError):
            risk_label = self._score_to_severity(risk_score)

        return AnalysisResponse(
            request_id=request_id,
            method=parsed_request.method,
            url=parsed_request.url,
            overall_risk_score=risk_score,
            risk_label=risk_label,
            vulnerabilities=vulns,
            attack_strategies=strategies,
            surface_summary=data.get("surface_summary", "No summary provided."),
            interesting_observations=data.get("interesting_observations", []),
            model_used=self.settings.ollama_model,
            analysis_time_ms=elapsed_ms,
            raw_llm_output=raw_llm,
        )

    def _parse_vuln(self, v: dict) -> Vulnerability:
        """Safely parse a vulnerability dict from LLM output."""
        # Map vuln class
        vc_raw = v.get("vuln_class", v.get("type", "other"))
        try:
            vc = VulnClass(vc_raw.lower().replace(" ", "_").replace("-", "_"))
        except ValueError:
            vc = VulnClass.OTHER

        # Map severity
        sev_raw = v.get("severity", "medium")
        try:
            sev = Severity(sev_raw.lower())
        except ValueError:
            sev = Severity.MEDIUM

        # Map confidence
        conf_raw = v.get("confidence", "medium")
        try:
            conf = Confidence(conf_raw.lower())
        except ValueError:
            conf = Confidence.MEDIUM

        # Parse payloads
        payloads = [
            self._parse_payload(p)
            for p in v.get("payload_suggestions", [])
            if isinstance(p, dict)
        ]

        return Vulnerability(
            vuln_class=vc,
            name=v.get("name", vc.value.replace("_", " ").title()),
            severity=sev,
            confidence=conf,
            affected_params=v.get("affected_params", []),
            description=v.get("description", ""),
            evidence=v.get("evidence"),
            cwe_id=v.get("cwe_id"),
            owasp_category=v.get("owasp_category"),
            payload_suggestions=payloads,
            remediation=v.get("remediation"),
        )

    def _parse_payload(self, p: dict) -> PayloadSuggestion:
        return PayloadSuggestion(
            parameter=p.get("parameter", "unknown"),
            payload=p.get("payload", ""),
            encoding=p.get("encoding"),
            description=p.get("description", ""),
            expected_indicator=p.get("expected_indicator"),
        )

    def _parse_strategy(self, s: dict) -> AttackStrategy:
        priority = int(s.get("priority", 3))
        priority = max(1, min(5, priority))
        return AttackStrategy(
            title=s.get("title", "Unknown Strategy"),
            steps=s.get("steps", []),
            tools=s.get("tools", []),
            priority=priority,
        )

    def _score_to_label(self, score: float) -> str:
        if score >= 9.0:  return "critical"
        if score >= 7.0:  return "high"
        if score >= 4.0:  return "medium"
        if score >= 1.0:  return "low"
        return "informational"

    def _score_to_severity(self, score: float) -> Severity:
        label = self._score_to_label(score)
        return Severity(label)
