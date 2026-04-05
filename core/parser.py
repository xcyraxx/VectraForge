"""
core/parser.py — HTTP Request Parser
======================================
Parses raw HTTP request strings (as captured by Burp Suite) into
a structured ParsedHTTPRequest object.

Handles:
  - Standard HTTP/1.1 requests
  - Query string parameters
  - application/x-www-form-urlencoded bodies
  - multipart/form-data (parameter names only)
  - JSON bodies
  - XML bodies
  - Cookie headers
  - Missing or malformed headers
"""

import json
import logging
import re
import urllib.parse
from typing import Optional

from core.models import ParsedHTTPRequest

logger = logging.getLogger("burpai.parser")


class HTTPRequestParser:
    """
    Parses a raw HTTP request string into a structured ParsedHTTPRequest.

    Designed to be tolerant of real-world Burp-captured traffic which may
    have inconsistent line endings, missing headers, or unusual encodings.
    """

    # Maximum body size we'll attempt to parse (10 MB)
    MAX_BODY_SIZE = 10 * 1024 * 1024

    def parse(
        self,
        raw: str,
        target_host: Optional[str] = None,
        is_https: bool = False,
    ) -> ParsedHTTPRequest:
        """
        Parse a raw HTTP request string.

        Args:
            raw:         Full HTTP request text (request line + headers + body).
            target_host: Fallback hostname if Host header is absent.
            is_https:    Whether the connection was over TLS (affects URL scheme).

        Returns:
            ParsedHTTPRequest with all extracted components.

        Raises:
            ValueError: If the request line is malformed or missing.
        """
        # Normalize line endings
        raw = raw.replace("\r\n", "\n").replace("\r", "\n")

        # Split head (request line + headers) from body
        if "\n\n" in raw:
            head, body_raw = raw.split("\n\n", 1)
        else:
            head, body_raw = raw, ""

        lines = head.split("\n")
        if not lines:
            raise ValueError("Empty request — no lines found")

        # ── Request line ──────────────────────────────────────────────────────
        method, path, http_version = self._parse_request_line(lines[0])

        # ── Headers ───────────────────────────────────────────────────────────
        headers = self._parse_headers(lines[1:])

        # ── Host / URL ────────────────────────────────────────────────────────
        host = headers.get("host") or target_host or "unknown"
        scheme = "https" if is_https else "http"
        url = f"{scheme}://{host}{path}"

        # ── Query parameters ──────────────────────────────────────────────────
        query_params: dict[str, list[str]] = {}
        if "?" in path:
            _, qs = path.split("?", 1)
            query_params = self._parse_query_string(qs)

        # ── Cookies ───────────────────────────────────────────────────────────
        cookies = self._parse_cookies(headers.get("cookie", ""))

        # ── Content type ──────────────────────────────────────────────────────
        content_type = headers.get("content-type", "")

        # ── Body & body parameters ────────────────────────────────────────────
        body = body_raw if body_raw else None
        body_params: dict[str, list[str]] = {}
        json_body = None
        xml_body = None

        if body:
            body = body[: self.MAX_BODY_SIZE]  # Guard against huge bodies
            body_params, json_body, xml_body = self._parse_body(body, content_type)

        # ── Merge all parameters ──────────────────────────────────────────────
        all_params = {**query_params}
        for k, v in body_params.items():
            if k in all_params:
                all_params[k].extend(v)
            else:
                all_params[k] = v

        # ── Path (strip query string) ─────────────────────────────────────────
        clean_path = path.split("?")[0]

        return ParsedHTTPRequest(
            method=method,
            url=url,
            path=clean_path,
            http_version=http_version,
            headers=headers,
            parameters=all_params,
            query_params=query_params,
            body_params=body_params,
            cookies=cookies,
            body=body,
            content_type=content_type or None,
            is_https=is_https,
            host=host,
            json_body=json_body,
            xml_body=xml_body,
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    def _parse_request_line(self, line: str) -> tuple[str, str, str]:
        """
        Parse 'METHOD /path HTTP/1.1' into its three components.
        Raises ValueError for malformed lines.
        """
        parts = line.strip().split(" ", 2)
        if len(parts) < 2:
            raise ValueError(f"Malformed request line: {line!r}")

        method = parts[0].upper()
        path = parts[1] if len(parts) > 1 else "/"
        version = parts[2] if len(parts) > 2 else "HTTP/1.1"

        valid_methods = {
            "GET", "POST", "PUT", "PATCH", "DELETE",
            "HEAD", "OPTIONS", "TRACE", "CONNECT",
        }
        if method not in valid_methods:
            logger.warning(f"Unusual HTTP method: {method!r}")

        return method, path, version

    def _parse_headers(self, lines: list[str]) -> dict[str, str]:
        """
        Parse header lines into a lowercase-key dict.
        Handles multi-line (folded) headers.
        """
        headers: dict[str, str] = {}
        current_key: Optional[str] = None

        for line in lines:
            if not line:
                break  # End of headers
            if line[0] in (" ", "\t") and current_key:
                # Folded header continuation
                headers[current_key] += " " + line.strip()
                continue
            if ":" in line:
                key, _, value = line.partition(":")
                current_key = key.strip().lower()
                headers[current_key] = value.strip()
            # Lines without ':' are silently ignored (malformed)

        return headers

    def _parse_query_string(self, qs: str) -> dict[str, list[str]]:
        """Parse a URL query string into a dict of param → [values]."""
        try:
            parsed = urllib.parse.parse_qs(qs, keep_blank_values=True)
            return dict(parsed)
        except Exception as e:
            logger.warning(f"Query string parse error: {e}")
            return {}

    def _parse_cookies(self, cookie_header: str) -> dict[str, str]:
        """Parse a Cookie header string into a name→value dict."""
        if not cookie_header:
            return {}
        cookies = {}
        for part in cookie_header.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                cookies[name.strip()] = value.strip()
            elif part:
                cookies[part] = ""
        return cookies

    def _parse_body(
        self,
        body: str,
        content_type: str,
    ) -> tuple[dict[str, list[str]], Optional[object], Optional[str]]:
        """
        Attempt to parse the request body based on Content-Type.

        Returns:
            (body_params, json_body, xml_body)
        """
        ct_lower = content_type.lower()
        body_params: dict[str, list[str]] = {}
        json_body = None
        xml_body = None

        if "application/x-www-form-urlencoded" in ct_lower:
            body_params = self._parse_query_string(body)

        elif "application/json" in ct_lower or self._looks_like_json(body):
            try:
                json_body = json.loads(body)
                # Flatten top-level JSON keys into body_params for easier analysis
                if isinstance(json_body, dict):
                    for k, v in json_body.items():
                        body_params[str(k)] = [str(v)]
            except json.JSONDecodeError as e:
                logger.debug(f"JSON parse failed (not fatal): {e}")

        elif "multipart/form-data" in ct_lower:
            # Extract just the field names from multipart data
            body_params = self._parse_multipart_names(body, content_type)

        elif "text/xml" in ct_lower or "application/xml" in ct_lower or self._looks_like_xml(body):
            xml_body = body

        return body_params, json_body, xml_body

    def _looks_like_json(self, text: str) -> bool:
        """Heuristic: does this text start like a JSON object/array?"""
        stripped = text.strip()
        return bool(stripped) and stripped[0] in ("{", "[")

    def _looks_like_xml(self, text: str) -> bool:
        """Heuristic: does this text start with an XML declaration or tag?"""
        stripped = text.strip()
        return stripped.startswith("<?xml") or stripped.startswith("<")

    def _parse_multipart_names(self, body: str, content_type: str) -> dict[str, list[str]]:
        """Extract field names from multipart/form-data body."""
        params: dict[str, list[str]] = {}
        # Extract boundary
        boundary_match = re.search(r"boundary=([^\s;]+)", content_type)
        if not boundary_match:
            return params
        boundary = boundary_match.group(1).strip('"')
        # Find Content-Disposition field names
        for match in re.finditer(r'Content-Disposition:[^\n]*name="([^"]+)"', body, re.IGNORECASE):
            name = match.group(1)
            params.setdefault(name, []).append("[multipart-value]")
        return params
