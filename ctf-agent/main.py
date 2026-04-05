#!/usr/bin/env python3
"""
main.py — CLI entrypoint for the autonomous CTF solver agent.

Usage examples:
  python main.py --name "challenge_name" --file chall.bin --desc "find the flag"
  python main.py --name "web_chall" --url "http://10.10.10.5:8080" --category web
  python main.py --name "crypto1" --file cipher.txt --category crypto
  python main.py --name "steg_chall" --file image.png
  python main.py --config path/to/config.yaml --name "foo" --file bar.zip
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

# Add project root to sys.path so relative imports work
sys.path.insert(0, str(Path(__file__).parent))

from agent.controller import AgentController, Challenge


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Autonomous CTF Solving Agent — powered by a local LLM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--name", required=True, help="Challenge name (used for workspace)")
    p.add_argument("--file", nargs="*", default=[], help="Challenge file(s) to analyse")
    p.add_argument("--url", default="", help="Challenge URL (for web challenges)")
    p.add_argument("--desc", default="", help="Challenge description text")
    p.add_argument(
        "--category",
        choices=["reverse", "pwn", "web", "crypto", "forensics", "steg", "osint", "misc"],
        default="",
        help="Force challenge category (auto-detected if omitted)",
    )
    p.add_argument(
        "--config",
        default="workspace/config/config.yaml",
        help="Path to config.yaml",
    )
    p.add_argument("--verbose", "-v", action="store_true", help="Enable DEBUG logging")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Build challenge object
    challenge = Challenge(
        name=args.name,
        description=args.desc,
        files=args.file or [],
        url=args.url,
        category=args.category,
    )

    print(f"\n{'='*60}")
    print(f"  CTF AGENT — Challenge: {challenge.name}")
    print(f"  Category: {challenge.category or '(auto-detect)'}")
    if challenge.files:
        print(f"  Files: {', '.join(challenge.files)}")
    if challenge.url:
        print(f"  URL: {challenge.url}")
    print(f"{'='*60}\n")

    # Initialise controller
    try:
        controller = AgentController(config_path=args.config)
    except FileNotFoundError as exc:
        print(f"[ERROR] Config not found: {exc}")
        sys.exit(1)

    # Solve
    flag = controller.solve(challenge)

    print(f"\n{'='*60}")
    if flag:
        print(f"  ★  FLAG FOUND: {flag}")
    else:
        print("  ✗  Agent did not find the flag within the iteration limit.")
        print("  Check workspace/logs/ for the full reasoning trace.")
    print(f"{'='*60}\n")

    sys.exit(0 if flag else 1)


if __name__ == "__main__":
    main()
