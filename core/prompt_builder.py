"""
core/prompt_builder.py — LLM Prompt Builder
=============================================
Constructs the detailed, structured prompt sent to the LLM.
The prompt is carefully engineered to:
  - Provide full request context
  - Direct the LLM to focus on specific vulnerability classes
  - Require a strict JSON output schema
  - Avoid hallucinated findings by requiring evidence references
"""

import json
import logging
from typing import Optional

from core.models import ParsedHTTPRequest

logger = logging.getLogger("vectraforge.prompt_builder")


# ── JSON Schema embedded in the prompt ───────────────────────────────────────

OUTPUT_SCHEMA = """
{
  "overall_risk_score": <float 0.0-10.0>,
  "risk_label": "<critical|high|medium|low|informational>",
  "surface_summary": "<2-3 sentence plain-English description of the attack surface>",
  "interesting_observations": ["<string>", ...],
  "vulnerabilities": [
    {
      "vuln_class": "<sql_injection|cross_site_scripting|command_injection|server_side_request_forgery|insecure_direct_object_reference|path_traversal|local_file_inclusion|remote_file_inclusion|xml_external_entity|server_side_template_injection|open_redirect|cross_site_request_forgery|authentication_bypass|broken_authentication|information_disclosure|security_misconfiguration|header_injection|insecure_deserialization|other>",
      "name": "<human readable name>",
      "severity": "<critical|high|medium|low|informational>",
      "confidence": "<confirmed|high|medium|low|speculative>",
      "affected_params": ["<param or header name>", ...],
      "description": "<detailed technical description>",
      "evidence": "<specific value or pattern from the request that triggers this finding>",
      "cwe_id": "<e.g. CWE-89>",
      "owasp_category": "<e.g. A03:2021 - Injection>",
      "remediation": "<brief remediation advice>",
      "payload_suggestions": [
        {
          "parameter": "<parameter name>",
          "payload": "<exact payload string>",
          "encoding": "<URL|Base64|HTML|none>",
          "description": "<what this payload tests>",
          "expected_indicator": "<string to look for in response>"
        }
      ]
    }
  ],
  "attack_strategies": [
    {
      "title": "<short strategy name>",
      "steps": ["<step 1>", "<step 2>", ...],
      "tools": ["<tool name>", ...],
      "priority": <1-5 integer, 1=highest>
    }
  ]
}
"""


class PromptBuilder:
    """
    Builds the structured analysis prompt from a ParsedHTTPRequest.

    The prompt is designed to maximize the quality of the LLM's security
    analysis by providing full context and strict output requirements.
    """

    def build(
        self,
        request: ParsedHTTPRequest,
        analyst_notes: Optional[str] = None,
    ) -> str:
        """
        Construct the full analysis prompt.

        Args:
            request:        Structured HTTP request.
            analyst_notes:  Optional analyst context.

        Returns:
            Multi-section prompt string ready for the LLM.
        """
        sections = [
            self._header(),
            self._request_summary(request),
            self._headers_section(request),
            self._parameters_section(request),
            self._cookies_section(request),
            self._body_section(request),
            self._analyst_notes_section(analyst_notes),
            self._analysis_instructions(),
            self._output_format(),
        ]
        return "\n\n".join(s for s in sections if s)

    # ── Prompt Sections ───────────────────────────────────────────────────────

    def _header(self) -> str:
        return (
            "# HTTP REQUEST SECURITY ANALYSIS\n"
            "You are a senior penetration tester. Analyze the following HTTP request "
            "for ALL possible security vulnerabilities. Be thorough, specific, and technical.\n"
            "Your response MUST be a single valid JSON object matching the schema provided. "
            "No text before or after the JSON."
        )

    def _request_summary(self, r: ParsedHTTPRequest) -> str:
        lines = [
            "## REQUEST OVERVIEW",
            f"Method:       {r.method}",
            f"URL:          {r.url}",
            f"Protocol:     {r.http_version}",
            f"TLS/HTTPS:    {r.is_https}",
            f"Host:         {r.host or 'unknown'}",
            f"Content-Type: {r.content_type or 'none'}",
        ]
        return "\n".join(lines)

    def _headers_section(self, r: ParsedHTTPRequest) -> str:
        if not r.headers:
            return ""
        lines = ["## HTTP HEADERS"]
        for k, v in r.headers.items():
            # Redact Authorization values but preserve the scheme
            if k.lower() == "authorization":
                scheme = v.split(" ")[0] if " " in v else v
                lines.append(f"  {k}: {scheme} [REDACTED]")
            else:
                lines.append(f"  {k}: {v}")
        return "\n".join(lines)

    def _parameters_section(self, r: ParsedHTTPRequest) -> str:
        parts = []

        if r.query_params:
            parts.append("## QUERY STRING PARAMETERS")
            for k, vals in r.query_params.items():
                parts.append(f"  {k} = {' | '.join(vals)}")

        if r.body_params:
            parts.append("## BODY PARAMETERS")
            for k, vals in r.body_params.items():
                parts.append(f"  {k} = {' | '.join(vals)}")

        return "\n".join(parts) if parts else ""

    def _cookies_section(self, r: ParsedHTTPRequest) -> str:
        if not r.cookies:
            return ""
        lines = ["## COOKIES"]
        for name, value in r.cookies.items():
            lines.append(f"  {name} = {value}")
        return "\n".join(lines)

    def _body_section(self, r: ParsedHTTPRequest) -> str:
        if not r.body:
            return ""

        lines = ["## REQUEST BODY"]

        # For JSON bodies, pretty-print
        if r.json_body is not None:
            lines.append("Content format: JSON")
            lines.append("```json")
            lines.append(json.dumps(r.json_body, indent=2)[:4000])  # Limit size
            lines.append("```")
        elif r.xml_body:
            lines.append("Content format: XML")
            lines.append("```xml")
            lines.append(r.xml_body[:4000])
            lines.append("```")
        else:
            lines.append("Content format: raw/form-encoded")
            lines.append(r.body[:4000])

        return "\n".join(lines)

    def _analyst_notes_section(self, notes: Optional[str]) -> str:
        if not notes:
            return ""
        return f"## ANALYST CONTEXT\n{notes}"

    def _analysis_instructions(self) -> str:
        return """## ANALYSIS INSTRUCTIONS

Examine the request above and identify ALL of the following where applicable:

**1. INJECTION VULNERABILITIES**
   - SQL Injection: Look at every parameter, header, cookie for unsanitized SQL metacharacters
   - Command Injection: Parameters that may be passed to OS commands
   - SSTI: Template syntax in parameters ({{7*7}}, ${7*7}, <%= 7*7 %>)
   - LDAP/XPath/NoSQL injection: Context-appropriate injection patterns
   - Header Injection: CR/LF injection possibilities in header values

**2. CLIENT-SIDE VULNERABILITIES**
   - XSS (Reflected/Stored/DOM): Values reflected in responses, stored data endpoints
   - CSRF: State-changing requests without anti-CSRF tokens
   - Open Redirect: URL parameters that control redirects

**3. ACCESS CONTROL**
   - IDOR: Numeric or predictable object references (IDs, UUIDs)
   - Path Traversal: Directory traversal in file path parameters
   - LFI/RFI: File inclusion parameters
   - Authentication Bypass: Missing/weak auth tokens or logic flaws

**4. SERVER-SIDE VULNERABILITIES**
   - SSRF: Parameters that accept URLs or hostnames
   - XXE: XML bodies without entity disabling
   - Deserialization: Serialized objects in parameters or cookies

**5. INFORMATION DISCLOSURE**
   - Sensitive data in parameters (passwords, tokens, PII)
   - Debug headers or verbose error-triggering patterns
   - Stack trace triggering via malformed input

**6. SECURITY MISCONFIGURATION**
   - Missing security headers (CSP, HSTS, X-Frame-Options)
   - Overly permissive CORS
   - Weak cookie flags (HttpOnly, Secure, SameSite)
   - HTTP instead of HTTPS for sensitive operations

**7. ATTACK SURFACE MAPPING**
   - Identify the most promising attack vectors
   - Note interesting parameters, headers, and behaviors
   - Suggest the most effective attack sequence

For EACH vulnerability found:
- Provide 3-5 specific payload strings targeting that exact parameter
- Include the expected response behavior to confirm exploitation
- Reference the specific request element that triggered the finding"""

    def _output_format(self) -> str:
        return f"## REQUIRED OUTPUT FORMAT\nRespond ONLY with this exact JSON structure:\n```\n{OUTPUT_SCHEMA}\n```"
