"""
example_workflows.py — Demonstrate how to use the CTF agent programmatically.

Run individual examples:
  python example_workflows.py steg
  python example_workflows.py crypto
  python example_workflows.py web
  python example_workflows.py pwn
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


# ─────────────────────────────────────── Example 1: Steganography ───────────

def run_steg_example():
    """Example: PNG steganography challenge."""
    from agent.controller import AgentController, Challenge

    challenge = Challenge(
        name="hidden_message",
        description="We found this image at the crime scene. There might be hidden data inside.",
        files=["workspace/challenges/example.png"],  # replace with real file
        category="steg",
    )

    agent = AgentController()
    flag = agent.solve(challenge)
    print(f"Result: {flag}")


# ─────────────────────────────────────── Example 2: Crypto ──────────────────

def run_crypto_example():
    """Example: Vigenère + base64 cipher challenge."""
    from agent.controller import AgentController, Challenge

    challenge = Challenge(
        name="cryptic_message",
        description="We intercepted this encrypted message: VGhpcyBpcyBhIHRlc3Q=",
        files=[],
        category="crypto",
        extra={"ciphertext": "VGhpcyBpcyBhIHRlc3Q="},
    )

    agent = AgentController()
    flag = agent.solve(challenge)
    print(f"Result: {flag}")


# ─────────────────────────────────────── Example 3: Web ─────────────────────

def run_web_example():
    """Example: Web challenge with SQL injection."""
    from agent.controller import AgentController, Challenge

    challenge = Challenge(
        name="login_bypass",
        description="Can you bypass the login form? The admin flag is in the database.",
        url="http://localhost:5000/login",
        category="web",
    )

    agent = AgentController()
    flag = agent.solve(challenge)
    print(f"Result: {flag}")


# ─────────────────────────────────────── Example 4: Reverse ─────────────────

def run_reverse_example():
    """Example: Binary reverse engineering challenge."""
    from agent.controller import AgentController, Challenge

    challenge = Challenge(
        name="crackme",
        description="This binary checks for a secret password. Find it.",
        files=["workspace/challenges/crackme"],
        category="reverse",
    )

    agent = AgentController()
    flag = agent.solve(challenge)
    print(f"Result: {flag}")


# ─────────────────────────────────────── Example 5: Direct tool test ────────

def run_tool_tests():
    """Test individual tools without running the full agent."""
    from agent.tool_registry import ToolRegistry
    from tools.crypto_tools import CRYPTO_TOOLS
    from tools.forensics_tools import FORENSICS_TOOLS
    from tools.internet_tools import INTERNET_TOOLS
    from tools.reverse_tools import REVERSE_TOOLS

    reg = ToolRegistry()
    for t in CRYPTO_TOOLS + FORENSICS_TOOLS + INTERNET_TOOLS + REVERSE_TOOLS:
        reg.register(t)

    # Test cipher analysis
    print("=== Cipher Analysis ===")
    result = reg.execute("analyze_cipher", "VGhpcyBpcyBhIHRlc3Q=")
    print(result[:500])

    # Test frequency analysis
    print("\n=== Frequency Analysis ===")
    result = reg.execute("frequency_analysis", "Gur dhvpx oebja sbk whzcf bire gur ynml qbt")
    print(result[:500])

    # Test web search (requires network)
    print("\n=== Web Search ===")
    result = reg.execute("web_search", "CTF steganography LSB PNG writeup")
    print(result[:500])


# ─────────────────────────────────────── dispatcher ─────────────────────────

EXAMPLES = {
    "steg": run_steg_example,
    "crypto": run_crypto_example,
    "web": run_web_example,
    "pwn": run_reverse_example,
    "tools": run_tool_tests,
}

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "tools"
    fn = EXAMPLES.get(mode)
    if fn:
        fn()
    else:
        print(f"Unknown example '{mode}'. Choose from: {list(EXAMPLES)}")
        sys.exit(1)
