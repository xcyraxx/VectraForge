"""
reverse_tools.py — Static analysis tools for binary reverse engineering.
"""
from __future__ import annotations


import subprocess
from pathlib import Path

from agent.tool_registry import ToolSpec


# ─────────────────────────────────────────── helpers ────────────────────────

def _run(cmd: list[str], timeout: int = 30, input_data: bytes | None = None) -> str:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            input=input_data,
        )
        out = proc.stdout.decode("utf-8", errors="replace")
        err = proc.stderr.decode("utf-8", errors="replace")
        combined = out + ("\n[STDERR]\n" + err if err.strip() else "")
        return combined.strip() or "(no output)"
    except FileNotFoundError:
        return f"ERROR: Command not found: {cmd[0]}. Install the required tool."
    except subprocess.TimeoutExpired:
        return f"TIMEOUT: command exceeded {timeout}s"


# ─────────────────────────────────────────── tools ──────────────────────────

def strings(binary_path: str) -> str:
    """Extract printable strings from a binary file."""
    return _run(["strings", "-n", "6", binary_path])


def disassemble(binary_path: str, function: str = "main") -> str:
    """Disassemble a specific function using radare2."""
    script = f"aaa; s {function}; pdf"
    return _run(["r2", "-q", "-c", script, binary_path], timeout=45)


def analyze_binary(binary_path: str) -> str:
    """Full static analysis: file type, protections, imports, functions."""
    results = []

    results.append("=== file ===")
    results.append(_run(["file", binary_path]))

    results.append("\n=== checksec ===")
    results.append(_run(["checksec", "--file=" + binary_path]))

    results.append("\n=== nm (symbols) ===")
    results.append(_run(["nm", "-D", binary_path]))

    results.append("\n=== radare2 info ===")
    results.append(_run(["r2", "-q", "-c", "iI; il; ia", binary_path], timeout=30))

    results.append("\n=== strings (top 50) ===")
    raw = strings(binary_path)
    lines = raw.splitlines()
    results.append("\n".join(lines[:50]) + (f"\n... ({len(lines)-50} more)" if len(lines) > 50 else ""))

    return "\n".join(results)


def decompile_function(binary_path: str, function: str = "main") -> str:
    """Decompile a function to pseudo-C using radare2 with r2ghidra or pdc."""
    # Try r2ghidra first, fall back to pdc
    r2_cmd = f"aaa; s {function}; pdg"
    result = _run(["r2", "-q", "-c", r2_cmd, binary_path], timeout=60)
    if "ERROR" in result or "not found" in result.lower():
        r2_cmd = f"aaa; s {function}; pdc"
        result = _run(["r2", "-q", "-c", r2_cmd, binary_path], timeout=60)
    return result


def find_cross_references(binary_path: str, symbol: str) -> str:
    """Find all cross-references to a given symbol or address."""
    r2_cmd = f"aaa; axt {symbol}"
    return _run(["r2", "-q", "-c", r2_cmd, binary_path], timeout=30)


def ltrace_run(binary_path: str, args: str = "") -> str:
    """Trace library calls during binary execution."""
    cmd = ["ltrace", "-s", "200", binary_path] + (args.split() if args else [])
    return _run(cmd, timeout=15)


def objdump_headers(binary_path: str) -> str:
    """Display ELF section headers and program headers."""
    return _run(["objdump", "-x", binary_path])


# ─────────────────────────────────────────── tool specs ─────────────────────

REVERSE_TOOLS: list[ToolSpec] = [
    ToolSpec(
        name="strings",
        description="Extract printable strings from any file (min length 6)",
        input_schema={"binary_path": "string"},
        fn=strings,
        category="reverse",
    ),
    ToolSpec(
        name="disassemble",
        description="Disassemble a function in a binary using radare2 (default: main)",
        input_schema={"binary_path": "string", "function": "string (optional, default=main)"},
        fn=disassemble,
        category="reverse",
    ),
    ToolSpec(
        name="analyze_binary",
        description="Full static analysis: file type, security flags, symbols, imports, strings",
        input_schema={"binary_path": "string"},
        fn=analyze_binary,
        category="reverse",
    ),
    ToolSpec(
        name="decompile_function",
        description="Decompile a binary function to pseudo-C via radare2/ghidra",
        input_schema={"binary_path": "string", "function": "string (optional, default=main)"},
        fn=decompile_function,
        category="reverse",
    ),
    ToolSpec(
        name="find_cross_references",
        description="Find all cross-references to a symbol or address in a binary",
        input_schema={"binary_path": "string", "symbol": "string"},
        fn=find_cross_references,
        category="reverse",
    ),
    ToolSpec(
        name="ltrace_run",
        description="Run binary and trace library calls to observe runtime behaviour",
        input_schema={"binary_path": "string", "args": "string (optional)"},
        fn=ltrace_run,
        category="reverse",
    ),
    ToolSpec(
        name="objdump_headers",
        description="Display ELF section and program headers via objdump",
        input_schema={"binary_path": "string"},
        fn=objdump_headers,
        category="reverse",
    ),
]
