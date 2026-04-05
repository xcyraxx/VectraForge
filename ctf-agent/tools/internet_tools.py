"""
internet_tools.py — Web search, page fetching, and CTF writeup retrieval.
"""
from __future__ import annotations

import logging
import re
import textwrap
from urllib.parse import quote_plus

import requests

from agent.tool_registry import ToolSpec

logger = logging.getLogger(__name__)

HEADERS = {
    "User-Agent": "CTF-Research-Agent/1.0 (educational security research)",
    "Accept": "text/html,application/xhtml+xml,*/*",
}
DEFAULT_TIMEOUT = 15
MAX_BODY_CHARS = 8000


# ─────────────────────────────────────────── helpers ────────────────────────

def _get(url: str, timeout: int = DEFAULT_TIMEOUT) -> requests.Response:
    return requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)


def _strip_html(html: str) -> str:
    """Naive HTML → plain text stripping."""
    text = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _truncate(text: str, limit: int = MAX_BODY_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n\n[... {len(text)-limit} chars truncated ...]"


# ─────────────────────────────────────────── tools ──────────────────────────

def web_search(query: str, max_results: int = 5) -> str:
    """
    Search the web for CTF writeups and security resources.
    Uses DuckDuckGo HTML scraping (no API key required).
    """
    try:
        url = f"https://html.duckduckgo.com/html/?q={quote_plus(query)}"
        resp = _get(url)
        resp.raise_for_status()

        # Parse result titles and snippets
        titles = re.findall(r'class="result__title"[^>]*>(.*?)</a>', resp.text, re.DOTALL)
        snippets = re.findall(r'class="result__snippet"[^>]*>(.*?)</span>', resp.text, re.DOTALL)
        links = re.findall(r'class="result__url"[^>]*>(.*?)</span>', resp.text, re.DOTALL)

        results = []
        for i, (t, s, l) in enumerate(zip(titles, snippets, links)):
            if i >= max_results:
                break
            title = re.sub(r"<[^>]+>", "", t).strip()
            snippet = re.sub(r"<[^>]+>", "", s).strip()
            link = l.strip()
            results.append(f"[{i+1}] {title}\n    URL: {link}\n    {snippet}\n")

        return "\n".join(results) if results else "No search results found."
    except Exception as exc:
        logger.warning("web_search failed: %s", exc)
        return f"Search failed: {exc}"


def fetch_webpage(url: str) -> str:
    """Fetch and return plain text content of a webpage."""
    try:
        resp = _get(url)
        resp.raise_for_status()
        text = _strip_html(resp.text)
        return _truncate(text)
    except Exception as exc:
        return f"Failed to fetch {url}: {exc}"


def extract_web_text(url: str) -> str:
    """
    Fetch a URL and extract readable text, focusing on article/code content.
    Tries to identify CTF writeup sections.
    """
    try:
        resp = _get(url)
        resp.raise_for_status()
        html = resp.text

        # Try to find main article content
        for pattern in [
            r'<article[^>]*>(.*?)</article>',
            r'<div[^>]*class="[^"]*post[^"]*"[^>]*>(.*?)</div>',
            r'<main[^>]*>(.*?)</main>',
            r'<div[^>]*class="[^"]*content[^"]*"[^>]*>(.*?)</div>',
        ]:
            match = re.search(pattern, html, re.DOTALL | re.IGNORECASE)
            if match:
                text = _strip_html(match.group(1))
                if len(text) > 200:
                    return _truncate(f"[Extracted article content]\n\n{text}")

        # Fallback: full page
        return _truncate(_strip_html(html))
    except Exception as exc:
        return f"Failed to extract from {url}: {exc}"


def search_ctf_writeups(challenge_name: str, category: str = "", keywords: str = "") -> str:
    """
    Specialised CTF writeup search across ctftime.org, GitHub, and security blogs.
    Constructs targeted queries to find relevant techniques and solutions.
    """
    base_terms = f"CTF writeup {challenge_name}"
    if category:
        base_terms += f" {category}"
    if keywords:
        base_terms += f" {keywords}"

    queries = [
        base_terms,
        f"site:ctftime.org {challenge_name}",
        f"site:github.com CTF {challenge_name} writeup",
        f"CTF {category} {keywords} solution exploit",
    ]

    all_results = []
    for q in queries[:2]:  # limit to 2 queries to avoid rate limiting
        result = web_search(q, max_results=3)
        all_results.append(f"Query: {q}\n{result}")

    return "\n\n---\n\n".join(all_results)


def summarize_writeup(url: str) -> str:
    """Fetch a CTF writeup and extract the key technique/solution steps."""
    content = extract_web_text(url)
    if content.startswith("Failed"):
        return content

    # Look for key sections
    lines = content.splitlines()
    interesting = []
    keywords = ["flag", "exploit", "payload", "vulnerability", "overflow", "injection",
                 "decode", "decrypt", "hidden", "solution", "approach", "ctf{", "flag{"]

    for i, line in enumerate(lines):
        if any(kw in line.lower() for kw in keywords):
            start = max(0, i - 1)
            end = min(len(lines), i + 3)
            interesting.append("\n".join(lines[start:end]))

    if interesting:
        return f"=== Writeup Key Sections (from {url}) ===\n\n" + "\n\n---\n\n".join(interesting[:10])

    return f"=== Full Writeup Text (from {url}) ===\n\n{content[:3000]}"


# ─────────────────────────────────────────── tool specs ─────────────────────

INTERNET_TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="web_search",
        description="Search the web for CTF writeups, techniques and security resources",
        input_schema={"query": "string", "max_results": "int (optional, default=5)"},
        fn=web_search,
        category="internet",
    ),
    ToolSpec(
        name="fetch_webpage",
        description="Fetch and return the text content of a webpage by URL",
        input_schema={"url": "string"},
        fn=fetch_webpage,
        category="internet",
    ),
    ToolSpec(
        name="extract_web_text",
        description="Fetch URL and extract main article/writeup content",
        input_schema={"url": "string"},
        fn=extract_web_text,
        category="internet",
    ),
    ToolSpec(
        name="search_ctf_writeups",
        description="Targeted search for CTF writeups on ctftime, GitHub, and blogs",
        input_schema={"challenge_name": "string", "category": "string (optional)", "keywords": "string (optional)"},
        fn=search_ctf_writeups,
        category="internet",
    ),
    ToolSpec(
        name="summarize_writeup",
        description="Fetch a writeup URL and extract the key solution technique",
        input_schema={"url": "string"},
        fn=summarize_writeup,
        category="internet",
    ),
]
