"""
core/models.py — Pydantic Data Models
=======================================
All data transfer objects (DTOs) used across the pipeline:
  ParsedHTTPRequest   — structured representation of a parsed HTTP request
  AnalysisRequest     — input to the analyzer
  Vulnerability       — single identified vulnerability
  PayloadSuggestion   — attack payload for a vulnerability
  AttackStrategy      — recommended attack approach
  AnalysisResponse    — full LLM analysis result returned to Burp
"""

from __future__ import annotations
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field


# ── Enumerations ──────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "informational"


class Confidence(str, Enum):
    CONFIRMED  = "confirmed"    # 90–100 %
    HIGH       = "high"         # 70–89 %
    MEDIUM     = "medium"       # 40–69 %
    LOW        = "low"          # 10–39 %
    SPECULATIVE= "speculative"  # < 10 %


class VulnClass(str, Enum):
    SQLI          = "sql_injection"
    XSS           = "cross_site_scripting"
    CMDI          = "command_injection"
    SSRF          = "server_side_request_forgery"
    IDOR          = "insecure_direct_object_reference"
    PATH_TRAV     = "path_traversal"
    LFI           = "local_file_inclusion"
    RFI           = "remote_file_inclusion"
    XXE           = "xml_external_entity"
    SSTI          = "server_side_template_injection"
    OPEN_REDIRECT = "open_redirect"
    CSRF          = "cross_site_request_forgery"
    AUTH_BYPASS   = "authentication_bypass"
    BROKEN_AUTH   = "broken_authentication"
    INFO_DISC     = "information_disclosure"
    MISCONFIG     = "security_misconfiguration"
    HEADER_INJ    = "header_injection"
    DESERIALIZATION = "insecure_deserialization"
    OTHER         = "other"


# ── Parsed HTTP Request ───────────────────────────────────────────────────────

class ParsedHTTPRequest(BaseModel):
    """Structured representation of a raw HTTP request after parsing."""
    method:     str                      = Field(..., description="HTTP method (GET, POST, etc.)")
    url:        str                      = Field(..., description="Full reconstructed URL")
    path:       str                      = Field(..., description="URL path component")
    http_version: str                    = Field("HTTP/1.1", description="HTTP version string")
    headers:    dict[str, str]           = Field(default_factory=dict)
    parameters: dict[str, list[str]]     = Field(default_factory=dict, description="Query + body params")
    query_params: dict[str, list[str]]   = Field(default_factory=dict)
    body_params:  dict[str, list[str]]   = Field(default_factory=dict)
    cookies:    dict[str, str]           = Field(default_factory=dict)
    body:       Optional[str]            = Field(None, description="Raw request body")
    content_type: Optional[str]          = Field(None)
    is_https:   bool                     = Field(False)
    host:       Optional[str]            = Field(None)
    json_body:  Optional[Any]            = Field(None, description="Parsed JSON body if applicable")
    xml_body:   Optional[str]            = Field(None, description="Raw XML body if applicable")


# ── Analysis Input / Output ───────────────────────────────────────────────────

class AnalysisRequest(BaseModel):
    """Internal model passed to the VulnerabilityAnalyzer."""
    parsed_request: ParsedHTTPRequest
    analyst_notes:  Optional[str] = None
    request_id:     str           = ""


class PayloadSuggestion(BaseModel):
    """A concrete attack payload to test a vulnerability."""
    parameter:   str  = Field(..., description="Parameter or header to inject into")
    payload:     str  = Field(..., description="The payload string")
    encoding:    Optional[str] = Field(None, description="Required encoding (URL, Base64, etc.)")
    description: str  = Field(..., description="What this payload tests")
    expected_indicator: Optional[str] = Field(
        None,
        description="String or pattern to look for in the response to confirm vuln"
    )


class AttackStrategy(BaseModel):
    """High-level attack approach recommended for this request."""
    title:       str            = Field(..., description="Short strategy name")
    steps:       list[str]      = Field(default_factory=list, description="Ordered attack steps")
    tools:       list[str]      = Field(default_factory=list, description="Recommended tools (sqlmap, ffuf, etc.)")
    priority:    int            = Field(1, ge=1, le=5, description="Priority 1 (highest) to 5 (lowest)")


class Vulnerability(BaseModel):
    """A single identified or suspected vulnerability."""
    vuln_class:       VulnClass          = Field(..., description="Vulnerability class")
    name:             str                = Field(..., description="Human-readable name")
    severity:         Severity           = Field(...)
    confidence:       Confidence         = Field(...)
    affected_params:  list[str]          = Field(default_factory=list, description="Affected parameters/headers")
    description:      str                = Field(..., description="Detailed explanation")
    evidence:         Optional[str]      = Field(None, description="Evidence from the request that triggered this finding")
    cwe_id:           Optional[str]      = Field(None, description="CWE identifier e.g. CWE-89")
    owasp_category:   Optional[str]      = Field(None, description="OWASP Top 10 category")
    payload_suggestions: list[PayloadSuggestion] = Field(default_factory=list)
    remediation:      Optional[str]      = Field(None)


class AnalysisResponse(BaseModel):
    """Complete analysis result returned to the Burp extension."""
    request_id:       str                = Field(..., description="Short trace ID")
    method:           str
    url:              str
    overall_risk_score: float            = Field(..., ge=0.0, le=10.0, description="CVSS-like score 0–10")
    risk_label:       Severity
    vulnerabilities:  list[Vulnerability]= Field(default_factory=list)
    attack_strategies: list[AttackStrategy] = Field(default_factory=list)
    surface_summary:  str                = Field(..., description="LLM's plain-English attack surface summary")
    interesting_observations: list[str]  = Field(default_factory=list)
    model_used:       str                = Field(..., description="Ollama model that produced the analysis")
    analysis_time_ms: Optional[float]    = Field(None)
    raw_llm_output:   Optional[str]      = Field(None, description="Full raw LLM response for debugging")
