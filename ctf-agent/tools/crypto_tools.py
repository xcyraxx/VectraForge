"""
crypto_tools.py — Cryptography analysis and solving tools.
"""
from __future__ import annotations

import base64
import binascii
import collections
import math
import string
import subprocess
from typing import Optional

from agent.tool_registry import ToolSpec


# ─────────────────────────────────────────── helpers ────────────────────────

COMMON_ENCODINGS = ["base64", "base32", "base16", "hex", "rot13", "url", "binary"]


def _try_decode(data: str) -> list[tuple[str, str]]:
    """Attempt multiple decoding schemes and return successes."""
    results = []
    data = data.strip()

    try:
        dec = base64.b64decode(data + "==").decode("utf-8", errors="replace")
        if dec.isprintable():
            results.append(("base64", dec))
    except Exception:
        pass

    try:
        dec = base64.b32decode(data + "=" * (-len(data) % 8)).decode("utf-8", errors="replace")
        if dec.isprintable():
            results.append(("base32", dec))
    except Exception:
        pass

    try:
        dec = bytes.fromhex(data.replace(" ", "").replace(":", "")).decode("utf-8", errors="replace")
        if dec.isprintable():
            results.append(("hex", dec))
    except Exception:
        pass

    try:
        import urllib.parse
        dec = urllib.parse.unquote(data)
        if dec != data:
            results.append(("url_decode", dec))
    except Exception:
        pass

    return results


# ─────────────────────────────────────────── tools ──────────────────────────

def analyze_cipher(ciphertext: str) -> str:
    """Comprehensive analysis of ciphertext: detect type, attempt decoding, show statistics."""
    lines = ["=== Cipher Analysis ==="]
    ct = ciphertext.strip()

    # Length and character set
    charset = set(ct.replace(" ", "").replace("\n", ""))
    lines.append(f"Length: {len(ct)}")
    lines.append(f"Unique chars: {len(charset)}")
    lines.append(f"Charset sample: {''.join(sorted(charset))[:60]}")

    # Check if it's pure numbers
    if all(c.isdigit() or c in " ," for c in ct):
        lines.append("Type hint: Possible ASCII codes or number cipher")

    # Check base64
    b64_chars = set(string.ascii_letters + string.digits + "+/=")
    if charset <= b64_chars and len(ct) % 4 <= 2:
        lines.append("Type hint: Possible Base64")

    # Check hex
    hex_chars = set("0123456789abcdefABCDEF \n:")
    if charset <= hex_chars:
        lines.append("Type hint: Possible hex encoding")

    # Frequency analysis
    freq = collections.Counter(c for c in ct.lower() if c.isalpha())
    top_5 = freq.most_common(5)
    lines.append(f"\nTop 5 character frequencies: {top_5}")

    # Index of Coincidence (IoC)
    n = sum(freq.values())
    if n > 0:
        ioc = sum(v * (v - 1) for v in freq.values()) / (n * (n - 1)) if n > 1 else 0
        lines.append(f"Index of Coincidence: {ioc:.4f} (English ~0.065, random ~0.038)")
        if ioc > 0.060:
            lines.append("→ Likely monoalphabetic or simple substitution cipher")
        elif 0.040 < ioc < 0.060:
            lines.append("→ Likely polyalphabetic cipher (Vigenère, etc.)")
        else:
            lines.append("→ Likely stream cipher or modern symmetric encryption")

    # Auto-decode attempts
    decoded = _try_decode(ct)
    if decoded:
        lines.append("\n=== Auto-decoded ===")
        for enc, result in decoded:
            lines.append(f"{enc}: {result[:200]}")

    return "\n".join(lines)


def frequency_analysis(text: str) -> str:
    """Perform letter frequency analysis to aid substitution cipher solving."""
    letters_only = [c.lower() for c in text if c.isalpha()]
    if not letters_only:
        return "No alphabetic characters found."

    freq = collections.Counter(letters_only)
    total = len(letters_only)

    english_order = "etaoinshrdlcumwfgypbvkjxqz"

    lines = ["Letter Frequency Analysis (vs English order: etaoinshrdlcumwfgypbvkjxqz)"]
    lines.append(f"Total letters: {total}\n")

    cipher_order = "".join(c for c, _ in freq.most_common())
    lines.append(f"Cipher order:  {cipher_order}")
    lines.append(f"English order: {english_order}\n")

    lines.append("Frequency table:")
    for char, count in freq.most_common():
        bar = "█" * int(count / total * 60)
        lines.append(f"  {char}: {count:4d} ({count/total*100:5.1f}%) {bar}")

    # Caesar brute-force
    lines.append("\n=== Caesar brute-force ===")
    for shift in range(26):
        candidate = "".join(
            chr((ord(c) - ord("a") - shift) % 26 + ord("a")) if c.isalpha() else c
            for c in text.lower()
        )
        lines.append(f"  ROT{shift:2d}: {candidate[:80]}")

    return "\n".join(lines)


def detect_cipher_type(text: str) -> str:
    """Heuristically detect the most likely cipher type."""
    t = text.strip()

    checks = []

    # Base64
    import re
    if re.fullmatch(r"[A-Za-z0-9+/=\n]+", t) and len(t) % 4 <= 2:
        checks.append("Base64 encoding")

    # Hex
    if re.fullmatch(r"[0-9a-fA-F\s:]+", t) and len(t.replace(" ", "").replace(":", "")) % 2 == 0:
        checks.append("Hexadecimal encoding")

    # Morse
    if re.fullmatch(r"[.\-/ \n]+", t):
        checks.append("Morse code")

    # Binary
    if re.fullmatch(r"[01 \n]+", t) and len(t.replace(" ", "")) % 8 == 0:
        checks.append("Binary encoding")

    # RSA-style (large numbers)
    if re.search(r"\d{30,}", t):
        checks.append("RSA / large-number cipher")

    # Caesar / monoalphabetic
    freq = collections.Counter(c.lower() for c in t if c.isalpha())
    if freq:
        n = sum(freq.values())
        ioc = sum(v * (v - 1) for v in freq.values()) / (n * (n - 1)) if n > 1 else 0
        if ioc > 0.06:
            checks.append(f"Monoalphabetic/Caesar cipher (IoC={ioc:.3f})")
        elif 0.04 < ioc <= 0.06:
            checks.append(f"Polyalphabetic cipher - Vigenère? (IoC={ioc:.3f})")

    return "\n".join(checks) if checks else "Could not determine cipher type definitively."


def run_crypto_solver(ciphertext: str, cipher_type: str = "auto") -> str:
    """Attempt to automatically solve common ciphers (caesar, vigenere, morse, base*)."""
    import re

    results = []
    ct = ciphertext.strip()

    # --- Morse ---
    if re.fullmatch(r"[.\-/ \n]+", ct):
        morse_map = {
            ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
            "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
            "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
            ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
            "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
            "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
            "...--": "3", "....-": "4", ".....": "5", "-....": "6",
            "--...": "7", "---..": "8", "----.": "9",
        }
        words = ct.split("  ") if "  " in ct else ct.split("/")
        decoded_words = []
        for word in words:
            chars = "".join(morse_map.get(sym.strip(), "?") for sym in word.split())
            decoded_words.append(chars)
        results.append(f"Morse: {' '.join(decoded_words)}")

    # --- Binary ---
    if re.fullmatch(r"[01 \n]+", ct) and len(ct.replace(" ", "")) % 8 == 0:
        bits = ct.replace(" ", "").replace("\n", "")
        try:
            decoded = "".join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
            results.append(f"Binary: {decoded}")
        except Exception:
            pass

    # --- Base64 / 32 / 16 ---
    decoded = _try_decode(ct)
    for enc, val in decoded:
        results.append(f"{enc}: {val[:200]}")

    # --- Caesar all shifts ---
    if re.fullmatch(r"[A-Za-z\s.,!?]+", ct):
        for shift in range(1, 26):
            candidate = "".join(
                chr((ord(c.upper()) - 65 - shift) % 26 + 65) if c.isalpha() else c
                for c in ct
            )
            # Score by common English words
            score = sum(1 for w in ["the", "and", "flag", "ctf", "is", "are"] if w in candidate.lower())
            if score >= 2:
                results.append(f"Caesar ROT{shift}: {candidate[:120]}")

    return "\n".join(results) if results else "No automatic solution found. Try manual analysis."


def test_common_keys(ciphertext: str) -> str:
    """Test common/weak keys against the ciphertext (XOR, Vigenère)."""
    results = []
    ct_bytes = ciphertext.encode("latin-1")

    # Single-byte XOR
    results.append("=== Single-byte XOR brute force ===")
    candidates = []
    for key in range(256):
        decrypted = bytes(b ^ key for b in ct_bytes)
        try:
            text = decrypted.decode("utf-8")
            score = sum(1 for c in text.lower() if c in "etaoinshrdlucmf ")
            candidates.append((score, key, text[:80]))
        except Exception:
            pass
    for score, key, preview in sorted(candidates, reverse=True)[:5]:
        results.append(f"  XOR 0x{key:02x}: {preview}")

    return "\n".join(results)


def rsa_small_exponent(n: str, e: str, c: str) -> str:
    """Attempt RSA small-exponent attack (e=3 cube root) and small-n factorisation."""
    import sympy

    results = []
    N = int(n.strip())
    E = int(e.strip())
    C = int(c.strip())

    # Small e attack
    if E == 3:
        for k in range(100):
            candidate = C + k * N
            root = round(candidate ** (1 / 3))
            for r in [root - 1, root, root + 1]:
                if r ** 3 == candidate:
                    try:
                        flag = r.to_bytes((r.bit_length() + 7) // 8, "big").decode("utf-8")
                        results.append(f"Small-e attack (k={k}): {flag}")
                    except Exception:
                        results.append(f"Small-e attack (k={k}): m={r}")
                    break

    # Factorise N if small
    if N.bit_length() < 256:
        results.append("Attempting factorisation...")
        factors = sympy.factorint(N)
        if len(factors) == 2:
            p, q = list(factors.keys())
            phi = (p - 1) * (q - 1)
            d = pow(E, -1, phi)
            m = pow(C, d, N)
            try:
                flag = m.to_bytes((m.bit_length() + 7) // 8, "big").decode("utf-8")
                results.append(f"Factored! p={p}, q={q}, m={flag}")
            except Exception:
                results.append(f"Factored! p={p}, q={q}, m={m}")

    return "\n".join(results) if results else "No RSA attacks succeeded."


# ─────────────────────────────────────────── tool specs ─────────────────────

CRYPTO_TOOLS: list[ToolSpec] = [
    ToolSpec("analyze_cipher", "Full analysis of ciphertext: encoding, IoC, auto-decode attempts", {"ciphertext": "string"}, analyze_cipher, "crypto"),
    ToolSpec("frequency_analysis", "Letter frequency analysis + Caesar brute force", {"text": "string"}, frequency_analysis, "crypto"),
    ToolSpec("detect_cipher_type", "Heuristic detection of cipher type (base64, hex, morse, RSA, Caesar, Vigenère…)", {"text": "string"}, detect_cipher_type, "crypto"),
    ToolSpec("run_crypto_solver", "Automatically solve common ciphers (morse, binary, base*, caesar)", {"ciphertext": "string", "cipher_type": "string (optional, default=auto)"}, run_crypto_solver, "crypto"),
    ToolSpec("test_common_keys", "Brute-force single-byte XOR and test common weak keys", {"ciphertext": "string"}, test_common_keys, "crypto"),
    ToolSpec("rsa_small_exponent", "RSA small exponent and factorisation attacks", {"n": "string", "e": "string", "c": "string"}, rsa_small_exponent, "crypto"),
]
