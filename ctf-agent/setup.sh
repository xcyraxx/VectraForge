#!/usr/bin/env bash
# setup.sh — Install all dependencies for the CTF Agent
# Run as a regular user; will use sudo for system packages.
set -euo pipefail

echo "╔══════════════════════════════════════╗"
echo "║     CTF Agent — Setup Script         ║"
echo "╚══════════════════════════════════════╝"

# ─── Python dependencies ──────────────────────────────────────────────────
echo "[1/4] Installing Python packages..."
pip install --break-system-packages -r requirements.txt 2>/dev/null \
  || pip install -r requirements.txt

# ─── System tools (Debian/Ubuntu) ─────────────────────────────────────────
echo "[2/4] Installing system security tools..."
if command -v apt-get &>/dev/null; then
  sudo apt-get update -q
  sudo apt-get install -y -q \
    radare2 \
    binwalk \
    steghide \
    exiftool \
    tshark \
    wireshark-common \
    gdb \
    ltrace \
    strace \
    foremost \
    p7zip-full \
    unrar \
    gobuster \
    dirb \
    sqlmap \
    patchelf \
    file \
    xxd \
    zsteg \
    imagemagick \
    ffmpeg \
    strings \
    || true
elif command -v brew &>/dev/null; then
  brew install radare2 binwalk steghide exiftool tshark sqlmap foremost p7zip || true
fi

# ─── Pwntools checksec ────────────────────────────────────────────────────
echo "[3/4] Setting up pwntools..."
python3 -c "import pwn; print('pwntools OK')" 2>/dev/null || pip install pwntools

# ─── ROPgadget ────────────────────────────────────────────────────────────
pip install ropgadget 2>/dev/null || true

# ─── Workspace directories ────────────────────────────────────────────────
echo "[4/4] Creating workspace directories..."
mkdir -p workspace/{challenges,logs,config}
mkdir -p /tmp/ctf_sandbox
mkdir -p /tmp/binwalk_out

echo ""
echo "✓ Setup complete!"
echo ""
echo "Start the local LLM:"
echo "  ollama run mistral"
echo "  # or: llama.cpp server on port 8080"
echo ""
echo "Run the agent:"
echo "  python main.py --name 'challenge' --file chall.bin --desc 'find the flag'"
