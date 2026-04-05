# VectraForge — Local LLM HTTP Vulnerability Analysis Server

> **For authorized security research and penetration testing only.**
> Only use against systems you own or have explicit written permission to test.

A production-grade local AI server that integrates with Burp Suite and uses
**Ollama + DeepSeek-R1 8B** to perform deep vulnerability analysis on captured
HTTP requests — fully offline, no cloud services.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  Burp Suite (Parrot OS)                                      │
│  ┌──────────────────────────────────┐                        │
│  │  VectraForge Jython Extension         │                        │
│  │  • Context menu hook             │                        │
│  │  • Request serializer            │                        │
│  │  • Results UI (tabbed panel)     │                        │
│  └──────────────┬───────────────────┘                        │
└─────────────────┼───────────────────────────────────────────┘
                  │  HTTP POST /analyze
                  │  { raw_request, target_host, is_https }
                  ▼
┌─────────────────────────────────────────────────────────────┐
│  VectraForge FastAPI Server (Manjaro / any Linux host)           │
│                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐  │
│  │   Parser    │───▶│  Prompt     │───▶│   Ollama        │  │
│  │  (parser.py)│    │  Builder    │    │   Client        │  │
│  │             │    │             │    │  (llm_client.py)│  │
│  │ • Request   │    │ • Structured│    │                 │  │
│  │   line      │    │   context   │    │  DeepSeek-R1 8B │  │
│  │ • Headers   │    │ • Vuln      │    │  via Ollama     │  │
│  │ • Params    │    │   checklist │    │  RTX 5060 8GB   │  │
│  │ • Cookies   │    │ • JSON      │    │                 │  │
│  │ • Body      │    │   schema    │    │                 │  │
│  └─────────────┘    └─────────────┘    └────────┬────────┘  │
│                                                  │           │
│  ┌───────────────────────────────────────────────▼────────┐  │
│  │   Analyzer (analyzer.py)                               │  │
│  │   • JSON extraction from LLM output                   │  │
│  │   • Vulnerability model mapping                       │  │
│  │   • Risk scoring                                      │  │
│  │   • AnalysisResponse → JSON                           │  │
│  └────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Folder Structure

```
vectra-forge-server/
├── main.py                     # Entry point — starts uvicorn
├── requirements.txt
├── .env.example                # Config template
│
├── api/
│   ├── app.py                  # FastAPI factory + middleware
│   └── routes/
│       ├── analyze.py          # POST /analyze, POST /analyze/batch
│       └── health.py           # GET /health, GET /health/full
│
├── core/
│   ├── config.py               # Pydantic settings (env vars / .env)
│   ├── models.py               # All Pydantic data models
│   ├── parser.py               # Raw HTTP → ParsedHTTPRequest
│   ├── prompt_builder.py       # ParsedHTTPRequest → LLM prompt
│   ├── analyzer.py             # Orchestrator: parse → LLM → response
│   └── llm_client.py           # Async Ollama HTTP client
│
├── utils/
│   └── logger.py               # Logging setup (console + rotating file)
│
├── burp_extension/
│   └── VectraForgeExtension.py      # Jython Burp Suite extension
│
├── tests/
│   └── test_parser.py          # Parser unit tests
│
└── logs/                       # Auto-created — vectraforge.log + audit.log
```

---

## Prerequisites

### On the AI Host (Manjaro)

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Pull DeepSeek-R1 8B
ollama pull deepseek-r1:8b

# 3. Verify GPU acceleration
ollama run deepseek-r1:8b "Say hello"
# You should see ~30+ tokens/sec with RTX 5060

# 4. Install Python 3.11+
python3 --version   # Should be 3.11 or higher
```

### On the Pentest Host (Parrot OS)
- Burp Suite Pro or Community
- Jython 2.7 standalone JAR
  - Download from: https://www.jython.org/download
  - Configure in Burp: Extender > Options > Python Environment

---

## Installation & Setup

```bash
# Clone / create the project
cd ~/tools
# (copy project files here)

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env if your Ollama runs on a different port/host
```

---

## Running the Server

```bash
# Activate venv
source .venv/bin/activate

# Start with defaults (localhost:8000, 4 workers)
python main.py

# Custom options
python main.py --host 0.0.0.0 --port 8000 --workers 2 --log-level debug

# Development mode with hot-reload
python main.py --reload --log-level debug
```

The server will start and print startup info:
```
2024-01-15 10:23:11 INFO  vectraforge.main: VectraForge Server starting up
2024-01-15 10:23:11 INFO  vectraforge.main: Listening on http://127.0.0.1:8000
2024-01-15 10:23:12 INFO  vectraforge.app:  Ollama connection OK
```

---

## Burp Suite Extension Setup

1. In Burp Suite go to: **Extender > Extensions > Add**
2. Set Extension type: **Python**
3. Select: `burp_extension/VectraForgeExtension.py`
4. Go to the **VectraForge** tab that appears in Burp's main panel

**Using the extension:**
1. In Proxy History, right-click any request
2. Select **"Analyze with VectraForge"**
3. Wait 10–60 seconds for DeepSeek-R1 to analyze
4. Results appear in the VectraForge tab across 5 sub-tabs:
   - **Summary** — risk score, surface overview
   - **Vulns** — detailed findings with CWE/OWASP refs
   - **Payloads** — ready-to-use attack payloads
   - **Strategy** — ordered attack recommendations
   - **Raw JSON** — full structured output

---

## API Reference

### `POST /analyze`

Analyze a single HTTP request.

**Request body:**
```json
{
  "raw_request": "GET /search?q=test HTTP/1.1\r\nHost: example.com\r\n\r\n",
  "target_host": "example.com",
  "is_https": false,
  "notes": "Focus on SQLi — this endpoint queries the products table"
}
```

**Response (200):**
```json
{
  "request_id": "a3f8c2d1",
  "method": "GET",
  "url": "http://example.com/search?q=test",
  "overall_risk_score": 7.5,
  "risk_label": "high",
  "surface_summary": "Search endpoint with unsanitized query parameter 'q' passed directly to database query...",
  "interesting_observations": [
    "No WAF headers detected",
    "Application uses direct SQL string concatenation pattern"
  ],
  "vulnerabilities": [
    {
      "vuln_class": "sql_injection",
      "name": "SQL Injection — Search Parameter",
      "severity": "high",
      "confidence": "high",
      "affected_params": ["q"],
      "description": "The 'q' parameter is likely interpolated directly into a SQL query without parameterization...",
      "evidence": "q=test — no input sanitization headers, typical search pattern",
      "cwe_id": "CWE-89",
      "owasp_category": "A03:2021 - Injection",
      "remediation": "Use parameterized queries / prepared statements",
      "payload_suggestions": [
        {
          "parameter": "q",
          "payload": "' OR '1'='1",
          "encoding": "URL",
          "description": "Classic OR-based boolean injection to bypass WHERE clause",
          "expected_indicator": "All products returned regardless of search term"
        },
        {
          "parameter": "q",
          "payload": "'; SELECT SLEEP(5)--",
          "encoding": "URL",
          "description": "Time-based blind injection to confirm SQL execution",
          "expected_indicator": "Response delayed by ~5 seconds"
        }
      ]
    }
  ],
  "attack_strategies": [
    {
      "title": "SQL Injection Exploitation Chain",
      "steps": [
        "Confirm injection with ' (single quote) and observe error",
        "Determine number of columns with ORDER BY 1-- through ORDER BY N--",
        "Use UNION SELECT to extract database version and schema",
        "Enumerate tables and extract credentials",
        "Attempt OS command execution via xp_cmdshell / INTO OUTFILE"
      ],
      "tools": ["sqlmap", "burp intruder", "manual testing"],
      "priority": 1
    }
  ],
  "model_used": "deepseek-r1:8b",
  "analysis_time_ms": 8432.1
}
```

### `POST /analyze/batch`

Analyze up to 10 requests at once.

### `GET /health`

Liveness probe — returns `{"status": "ok"}`.

### `GET /health/full`

Full health check including Ollama connectivity and model availability.

### `GET /docs`

Interactive Swagger UI for exploring the API.

---

## Performance Considerations

| Hardware | Expected throughput |
|----------|---------------------|
| RTX 5060 8GB (your setup) | ~25–40 tok/s → ~15–30s per analysis |
| CPU only (fallback) | ~3–8 tok/s → 60–120s per analysis |

**Optimization tips:**
- Set `--workers 1` if using GPU (avoid VRAM contention between workers)
- Increase `LLM_TIMEOUT_SECONDS` to 300 for very large requests
- Use `POST /analyze/batch` for multiple requests to reuse model cache
- Set `OLLAMA_MODEL=deepseek-r1:8b` (not `deepseek-r1:14b`) for RTX 5060

---

## Security Considerations

1. **Bind to localhost only** (`HOST=127.0.0.1`) — never expose to the network
2. **No API authentication** is implemented — the server is designed for local use only
3. **Input size limits** — 10 MB max request body, configurable via `MAX_REQUEST_BODY_BYTES`
4. **LLM outputs are not sanitized** — treat analysis as advisory, not ground truth
5. **Audit logging** — all analysis requests are logged to `logs/audit.log`

---

## Future Extensions

- **Auto-fuzzing** — generate Burp Intruder payloads from AI suggestions automatically
- **Nuclei template generation** — convert findings to Nuclei YAML templates
- **SQLMap integration** — one-click launch SQLMap with AI-suggested parameters
- **Findings database** — persist all findings to SQLite for cross-session analysis
- **Diff analysis** — compare two requests and highlight changed attack surface
- **Custom model support** — swap DeepSeek for any Ollama-supported model via `.env`

---

## Running Tests

```bash
source .venv/bin/activate
pytest tests/ -v
```
