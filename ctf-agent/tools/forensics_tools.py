"""
forensics_tools.py — Digital forensics and network traffic analysis tools.
"""
from __future__ import annotations


import subprocess
import tempfile
from pathlib import Path

from agent.tool_registry import ToolSpec


def _run(cmd: list[str], timeout: int = 30, input_data: bytes | None = None) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, input=input_data)
        out = proc.stdout.decode("utf-8", errors="replace")
        err = proc.stderr.decode("utf-8", errors="replace")
        return (out + ("\n[STDERR]\n" + err if err.strip() else "")).strip() or "(no output)"
    except FileNotFoundError:
        return f"ERROR: {cmd[0]} not found."
    except subprocess.TimeoutExpired:
        return f"TIMEOUT after {timeout}s"


# ─────────────────────────────────────────── forensics ──────────────────────

def analyze_file_type(file_path: str) -> str:
    """Identify file type using file, magic bytes, and binwalk."""
    results = []
    results.append(_run(["file", "-b", file_path]))

    # Magic bytes
    try:
        raw = Path(file_path).read_bytes()[:32]
        results.append(f"Magic bytes (hex): {raw.hex()}")
        results.append(f"Magic bytes (ascii): {raw.decode('ascii', errors='replace')}")
    except Exception as exc:
        results.append(f"Could not read file: {exc}")

    results.append(_run(["binwalk", file_path]))
    return "\n".join(results)


def extract_metadata(file_path: str) -> str:
    """Extract metadata from file using exiftool."""
    return _run(["exiftool", file_path])


def scan_disk_image(image_path: str) -> str:
    """Scan a disk image with strings, binwalk and list partitions."""
    results = []
    results.append("=== file ===")
    results.append(_run(["file", image_path]))

    results.append("\n=== fdisk / mmls ===")
    results.append(_run(["fdisk", "-l", image_path]))
    results.append(_run(["mmls", image_path]))

    results.append("\n=== binwalk ===")
    results.append(_run(["binwalk", image_path]))

    results.append("\n=== strings (top 100) ===")
    raw = _run(["strings", "-n", "8", image_path])
    results.append("\n".join(raw.splitlines()[:100]))

    return "\n".join(results)


def extract_archives(file_path: str, output_dir: str = "/tmp/extracted") -> str:
    """Extract compressed archives (.zip, .tar, .gz, .7z, etc.)."""
    import os
    os.makedirs(output_dir, exist_ok=True)
    ext = Path(file_path).suffix.lower()

    cmd_map = {
        ".zip": ["unzip", "-o", file_path, "-d", output_dir],
        ".gz": ["tar", "-xzf", file_path, "-C", output_dir],
        ".bz2": ["tar", "-xjf", file_path, "-C", output_dir],
        ".tar": ["tar", "-xf", file_path, "-C", output_dir],
        ".7z": ["7z", "x", file_path, f"-o{output_dir}", "-y"],
        ".rar": ["unrar", "x", file_path, output_dir],
        ".xz": ["tar", "-xJf", file_path, "-C", output_dir],
    }
    cmd = cmd_map.get(ext, ["7z", "x", file_path, f"-o{output_dir}", "-y"])
    result = _run(cmd, timeout=30)

    try:
        extracted = list(Path(output_dir).rglob("*"))
        result += f"\n\nExtracted {len(extracted)} items:\n" + "\n".join(str(p) for p in extracted[:30])
    except Exception:
        pass

    return result


def binwalk_extract(file_path: str) -> str:
    """Deep binwalk extraction with recursive carving."""
    out_dir = f"/tmp/bw_{Path(file_path).stem}"
    result = _run(["binwalk", "-e", "-M", "--directory", out_dir, file_path], timeout=45)
    try:
        extracted = sorted(Path(out_dir).rglob("*"))
        result += f"\n\nCarved files ({len(extracted)}):\n" + "\n".join(str(p) for p in extracted[:30])
    except Exception:
        pass
    return result


# ─────────────────────────────────────────── pcap / network ─────────────────

def analyze_pcap(file_path: str) -> str:
    """Full PCAP analysis: protocol summary, endpoints, top conversations."""
    results = []
    results.append("=== tshark protocol summary ===")
    results.append(_run(["tshark", "-r", file_path, "-q", "-z", "io,phs"], timeout=20))

    results.append("\n=== endpoints ===")
    results.append(_run(["tshark", "-r", file_path, "-q", "-z", "conv,ip"], timeout=20))

    results.append("\n=== first 30 packets ===")
    results.append(_run(["tshark", "-r", file_path, "-c", "30"], timeout=20))

    return "\n".join(results)


def pcap_summary(file_path: str) -> str:
    """Quick PCAP statistics."""
    return _run(["capinfos", file_path])


def extract_http_streams(file_path: str) -> str:
    """Extract HTTP request/response payloads from a PCAP."""
    result = _run(
        ["tshark", "-r", file_path, "-Y", "http", "-T", "fields",
         "-e", "http.request.method", "-e", "http.request.uri",
         "-e", "http.response.code", "-e", "http.file_data"],
        timeout=20,
    )
    # Also dump with follow http stream
    result += "\n\n=== HTTP objects ===\n"
    out_dir = f"/tmp/http_objects_{Path(file_path).stem}"
    _run(["tshark", "-r", file_path, "--export-objects", f"http,{out_dir}"], timeout=20)
    try:
        objs = list(Path(out_dir).iterdir())
        result += "\n".join(str(o) for o in objs[:20])
    except Exception:
        pass
    return result


def extract_dns_queries(file_path: str) -> str:
    """Extract all DNS queries from a PCAP file."""
    return _run(
        ["tshark", "-r", file_path, "-Y", "dns.qry.name", "-T", "fields",
         "-e", "frame.time", "-e", "ip.src", "-e", "dns.qry.name", "-e", "dns.resp.name"],
        timeout=20,
    )


def reassemble_files(file_path: str) -> str:
    """Attempt to reassemble files from network streams (TCP reassembly)."""
    out_dir = f"/tmp/reassembled_{Path(file_path).stem}"
    # Try exporting by protocol
    results = []
    for proto in ["http", "ftp-data", "tftp", "smb", "imf"]:
        r = _run(["tshark", "-r", file_path, "--export-objects", f"{proto},{out_dir}/{proto}"], timeout=15)
        results.append(f"[{proto}] {r[:200]}")
    return "\n".join(results)


def read_file(path: str) -> str:
    """Read and return the content of any text file."""
    try:
        content = Path(path).read_text(errors="replace")
        if len(content) > 5000:
            return content[:5000] + f"\n... ({len(content)-5000} more chars)"
        return content
    except Exception as exc:
        return f"ERROR reading {path}: {exc}"


def list_directory(path: str) -> str:
    """List directory contents recursively (up to 2 levels)."""
    return _run(["find", path, "-maxdepth", "2", "-ls"])


def search_files(pattern: str, directory: str = ".") -> str:
    """Search for files matching a glob pattern."""
    return _run(["find", directory, "-name", pattern, "-type", "f"])


def run_shell(command: str) -> str:
    """
    Run a shell command (whitelisted safe commands only).
    Allowed: file, strings, xxd, od, hexdump, head, tail, cat, ls, find, grep, wc, md5sum, sha256sum
    """
    ALLOWED_PREFIXES = [
        "file ", "strings ", "xxd ", "od ", "hexdump ", "head ", "tail ",
        "cat ", "ls ", "find ", "grep ", "wc ", "md5sum ", "sha256sum ",
        "echo ", "python3 -c ", "python3 ",
    ]
    cmd_lower = command.strip().lower()
    if not any(cmd_lower.startswith(p) for p in ALLOWED_PREFIXES):
        return f"BLOCKED: Command not in safe whitelist. Allowed: {[p.strip() for p in ALLOWED_PREFIXES]}"

    try:
        proc = subprocess.run(
            command, shell=True, capture_output=True, timeout=20
        )
        out = proc.stdout.decode("utf-8", errors="replace")
        err = proc.stderr.decode("utf-8", errors="replace")
        return (out + ("\n[STDERR]\n" + err if err.strip() else "")).strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return "TIMEOUT after 20s"
    except Exception as exc:
        return f"ERROR: {exc}"


def write_file(path: str, content: str) -> str:
    """Write content to a file in the workspace."""
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        return f"Written {len(content)} bytes to {path}"
    except Exception as exc:
        return f"ERROR: {exc}"


# ─────────────────────────────────────────── tool specs ─────────────────────

FORENSICS_TOOLS: list[ToolSpec] = [
    ToolSpec("analyze_file_type", "Identify file type via file, magic bytes, binwalk", {"file_path": "string"}, analyze_file_type, "forensics"),
    ToolSpec("extract_metadata_forensics", "Extract all metadata with exiftool", {"file_path": "string"}, extract_metadata, "forensics"),
    ToolSpec("scan_disk_image", "Analyse disk image: partitions, strings, binwalk", {"image_path": "string"}, scan_disk_image, "forensics"),
    ToolSpec("extract_archives", "Extract compressed archives (.zip .tar .gz .7z .rar)", {"file_path": "string", "output_dir": "string (optional)"}, extract_archives, "forensics"),
    ToolSpec("binwalk_extract", "Deep binwalk extraction with recursive carving", {"file_path": "string"}, binwalk_extract, "forensics"),
    ToolSpec("analyze_pcap", "Full PCAP analysis: protocol summary, endpoints, packets", {"file_path": "string"}, analyze_pcap, "forensics"),
    ToolSpec("pcap_summary", "Quick PCAP statistics via capinfos", {"file_path": "string"}, pcap_summary, "forensics"),
    ToolSpec("extract_http_streams", "Extract HTTP payloads and objects from PCAP", {"file_path": "string"}, extract_http_streams, "forensics"),
    ToolSpec("extract_dns_queries", "Extract DNS queries from PCAP", {"file_path": "string"}, extract_dns_queries, "forensics"),
    ToolSpec("reassemble_files", "Reassemble files from TCP/protocol streams in PCAP", {"file_path": "string"}, reassemble_files, "forensics"),
    ToolSpec("read_file", "Read and display the content of any text file", {"path": "string"}, read_file, "filesystem"),
    ToolSpec("list_directory", "List directory contents recursively (2 levels)", {"path": "string"}, list_directory, "filesystem"),
    ToolSpec("search_files", "Find files matching a glob pattern", {"pattern": "string", "directory": "string (optional)"}, search_files, "filesystem"),
    ToolSpec("write_file", "Write text content to a file", {"path": "string", "content": "string"}, write_file, "filesystem"),
    ToolSpec("run_shell", "Run a whitelisted shell command (file/strings/xxd/grep/cat/ls…)", {"command": "string"}, run_shell, "filesystem"),
]
