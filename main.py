"""
VectraForge Server — Main Entry Point
=================================
Local AI-powered HTTP vulnerability analysis server.
Receives raw HTTP requests from Burp Suite extensions and returns
structured vulnerability analysis via a local Ollama LLM.

Usage:
    python main.py [--host 127.0.0.1] [--port 8000] [--workers 4]
"""

import argparse
import logging
import sys
import uvicorn

from api.app import create_app
from utils.logger import setup_logging


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="VectraForge — Local LLM HTTP Vulnerability Analysis Server"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    parser.add_argument("--workers", type=int, default=4, help="Uvicorn worker count (default: 4)")
    parser.add_argument("--log-level", default="info", choices=["debug", "info", "warning", "error"])
    parser.add_argument("--reload", action="store_true", help="Enable hot-reload (dev only)")
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging(args.log_level.upper())

    logger = logging.getLogger("vectraforge.main")
    logger.info("=" * 60)
    logger.info("  VectraForge Server starting up")
    logger.info(f"  Listening on http://{args.host}:{args.port}")
    logger.info(f"  Workers: {args.workers}")
    logger.info("=" * 60)

    app = create_app()

    uvicorn.run(
        "api.app:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        workers=args.workers if not args.reload else 1,
        reload=args.reload,
        log_level=args.log_level,
        limit_max_requests=10_000,
        timeout_keep_alive=30,
    )


if __name__ == "__main__":
    main()
