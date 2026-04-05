"""
steg_tools.py — Steganography analysis and extraction tools.
"""
from __future__ import annotations


import subprocess
import tempfile
from pathlib import Path

from agent.tool_registry import ToolSpec


def _run(cmd: list[str], timeout: int = 30, input_bytes: bytes | None = None) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, input=input_bytes)
        out = proc.stdout.decode("utf-8", errors="replace")
        err = proc.stderr.decode("utf-8", errors="replace")
        return (out + ("\n[STDERR]\n" + err if err.strip() else "")).strip() or "(no output)"
    except FileNotFoundError:
        return f"ERROR: {cmd[0]} not found."
    except subprocess.TimeoutExpired:
        return f"TIMEOUT after {timeout}s"


# ─────────────────────────────────────────── tools ──────────────────────────

def analyze_image(file_path: str) -> str:
    """Comprehensive image analysis: identify format, metadata, anomalies."""
    results = []

    results.append("=== file ===")
    results.append(_run(["file", file_path]))

    results.append("\n=== exiftool ===")
    results.append(_run(["exiftool", file_path]))

    results.append("\n=== identify (ImageMagick) ===")
    results.append(_run(["identify", "-verbose", file_path]))

    results.append("\n=== strings (top 30) ===")
    raw = _run(["strings", "-n", "5", file_path])
    results.append("\n".join(raw.splitlines()[:30]))

    results.append("\n=== binwalk (signatures) ===")
    results.append(_run(["binwalk", file_path]))

    return "\n".join(results)


def steg_extract(file_path: str, password: str = "") -> str:
    """Extract hidden data using steghide (supports JPEG/BMP/WAV)."""
    cmd = ["steghide", "extract", "-sf", file_path, "-f", "-p", password]
    result = _run(cmd)
    if "wrote extracted data" in result.lower():
        # Read the extracted file if named in output
        import re
        match = re.search(r'wrote extracted data to "(.+?)"', result)
        if match:
            extracted_path = match.group(1)
            try:
                content = Path(extracted_path).read_text(errors="replace")
                result += f"\n\nExtracted content:\n{content[:2000]}"
            except Exception:
                pass
    return result


def check_lsb(file_path: str) -> str:
    """Check LSB (Least Significant Bit) steganography in images using zsteg or manual method."""
    # Try zsteg first (PNG/BMP)
    result = _run(["zsteg", "-a", file_path], timeout=30)
    if "not found" in result.lower() or "ERROR" in result:
        # Manual LSB check via Python
        code = f"""
try:
    from PIL import Image
    img = Image.open('{file_path}')
    pixels = list(img.getdata())
    lsb_bits = ''
    for px in pixels[:1000]:
        if isinstance(px, int):
            lsb_bits += str(px & 1)
        else:
            for channel in px[:3]:
                lsb_bits += str(channel & 1)
    # Try to decode as ASCII bytes
    chars = []
    for i in range(0, len(lsb_bits) - 7, 8):
        byte = int(lsb_bits[i:i+8], 2)
        if 32 <= byte < 127:
            chars.append(chr(byte))
    print('LSB data (first 200 printable chars):', ''.join(chars[:200]))
except Exception as e:
    print('PIL error:', e)
"""
        result = _run(["python3", "-c", code])
    return result


def run_stegsolve(file_path: str, plane: str = "0") -> str:
    """Apply bit plane and colour channel analysis (mimics StegSolve)."""
    code = f"""
from PIL import Image
import sys

img = Image.open('{file_path}').convert('RGB')
width, height = img.size
pixels = list(img.getdata())

print(f'Image: {{width}}x{{height}} RGB')

for bit in range(8):
    bits = ''
    for r, g, b in pixels[:512]:
        bits += str((r >> bit) & 1)
        bits += str((g >> bit) & 1)
        bits += str((b >> bit) & 1)

    # Try to decode as ASCII
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte_val = int(bits[i:i+8], 2)
        if 32 <= byte_val < 127:
            chars.append(chr(byte_val))
    text = ''.join(chars)
    if any(w in text.lower() for w in ['flag', 'ctf', 'key']):
        print(f'BIT {{bit}} — INTERESTING: {{text[:200]}}')
    elif len(text) > 20:
        print(f'BIT {{bit}} — printable: {{text[:100]}}')
    else:
        print(f'BIT {{bit}} — no printable data')
"""
    return _run(["python3", "-c", code])


def extract_metadata(file_path: str) -> str:
    """Extract all metadata from any file type using exiftool."""
    return _run(["exiftool", "-a", "-u", "-g", file_path])


def audio_steg(file_path: str) -> str:
    """Analyse audio file for steganography (spectrum, DeepSound, MP3Stego)."""
    results = []
    results.append("=== file info ===")
    results.append(_run(["file", file_path]))
    results.append("\n=== strings ===")
    results.append(_run(["strings", "-n", "5", file_path]))
    results.append("\n=== binwalk ===")
    results.append(_run(["binwalk", file_path]))
    results.append("\n=== stegsnow/mp3stego hint ===")
    results.append("For WAV: try steghide. For MP3: try mp3stego. Spectral analysis: use Sonic Visualiser.")
    return "\n".join(results)


def binwalk_carve(file_path: str) -> str:
    """Extract embedded files from an image using binwalk."""
    out_dir = f"/tmp/binwalk_carve_{Path(file_path).stem}"
    result = _run(["binwalk", "-e", "-M", "--directory", out_dir, file_path], timeout=30)
    # List what was extracted
    try:
        extracted = list(Path(out_dir).rglob("*"))
        if extracted:
            result += f"\n\nExtracted files:\n" + "\n".join(str(p) for p in extracted[:20])
    except Exception:
        pass
    return result


# ─────────────────────────────────────────── tool specs ─────────────────────

STEG_TOOLS: list[ToolSpec] = [
    ToolSpec("analyze_image", "Comprehensive image analysis: format, metadata, strings, binwalk", {"file_path": "string"}, analyze_image, "steg"),
    ToolSpec("steg_extract", "Extract hidden data using steghide (JPEG/BMP/WAV)", {"file_path": "string", "password": "string (optional)"}, steg_extract, "steg"),
    ToolSpec("check_lsb", "Check for LSB steganography using zsteg or PIL", {"file_path": "string"}, check_lsb, "steg"),
    ToolSpec("run_stegsolve", "Bit-plane and colour-channel analysis (StegSolve-style)", {"file_path": "string", "plane": "string (optional, bit plane 0-7)"}, run_stegsolve, "steg"),
    ToolSpec("extract_metadata", "Extract all metadata with exiftool (-a -u -g)", {"file_path": "string"}, extract_metadata, "steg"),
    ToolSpec("audio_steg", "Analyse audio file for steganography and embedded data", {"file_path": "string"}, audio_steg, "steg"),
    ToolSpec("binwalk_carve", "Extract embedded files from any binary/image using binwalk", {"file_path": "string"}, binwalk_carve, "steg"),
]
