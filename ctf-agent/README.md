# CTF Agent — Autonomous CTF Solver

A production-grade autonomous AI agent for solving Capture The Flag challenges
using a local LLM (via llama.cpp / Ollama) and a rich tool ecosystem.

---

## Architecture

```
Challenge Input
      ↓
WorkspaceManager      ← isolates each run
      ↓
AgentController       ← orchestrates everything
      ↓
LLMInterface          ← talks to local LLM at localhost:8080
      ↓
ToolRegistry          ← routes Action → tool function
      ↓
Tool Modules          ← reverse / pwn / web / crypto / steg / forensics / internet
      ↓
Observation           ← returned to LLM context
      ↓
ContextManager        ← manages prompt window, truncates large outputs
      ↓
AgentMemory           ← persists findings, flags, tested inputs, failed tools
```

---

## Project Structure

```
ctf-agent/
├── main.py                      ← CLI entrypoint
├── example_workflows.py         ← programmatic usage examples
├── requirements.txt
├── setup.sh
│
├── agent/
│   ├── controller.py            ← main reasoning loop
│   ├── llm_interface.py         ← local LLM API client
│   ├── memory.py                ← structured knowledge store
│   ├── context_manager.py       ← prompt assembly + truncation
│   ├── tool_registry.py         ← tool routing + execution
│   └── workspace_manager.py     ← per-challenge directory lifecycle
│
├── tools/
│   ├── reverse_tools.py         ← strings, radare2, disassembly
│   ├── pwn_tools.py             ← checksec, pwntools, angr, AFL++
│   ├── web_tools.py             ← HTTP, sqlmap, gobuster, XSS
│   ├── crypto_tools.py          ← frequency analysis, cipher detection, RSA
│   ├── steg_tools.py            ← steghide, zsteg, LSB, binwalk
│   ├── forensics_tools.py       ← PCAP, disk images, archives, filesystem
│   └── internet_tools.py        ← DuckDuckGo search, writeup retrieval
│
└── workspace/
    ├── config/config.yaml
    ├── challenges/              ← per-challenge workspaces created here
    └── logs/                    ← agent.log + per-iteration reasoning traces
```

---

## Quick Start

### 1. Start the local LLM

```bash
# Option A: Ollama
ollama serve
ollama pull mistral   # or codellama, deepseek-coder, etc.

# Option B: llama.cpp server
./llama-server -m model.gguf --port 8080 --host 0.0.0.0
```

### 2. Install dependencies

```bash
chmod +x setup.sh
./setup.sh
```

### 3. Run on a challenge

```bash
# Binary reverse engineering
python main.py --name crackme --file ./crackme --desc "find the password"

# Web challenge
python main.py --name login --url http://target:5000 --category web

# Steganography
python main.py --name hidden --file challenge.png

# Cryptography
python main.py --name cipher --file encrypted.txt --category crypto

# Force verbose output
python main.py -v --name myctf --file chall.bin
```

---

## Agent Reasoning Protocol

Every LLM response must follow this format:

```
Thought: I see this is a PNG file. It might contain hidden LSB data.
Action: check_lsb
Input: challenge.png

Observation: [tool output appears here]

Thought: zsteg found hidden text in the blue channel LSB...
Action: run_shell
Input: cat /tmp/zsteg_output.txt

...

Final Answer: flag{h1dd3n_1n_pl41n_s1ght}
```

---

## Tool Categories

| Category   | Tools |
|------------|-------|
| Reverse    | strings, disassemble, analyze_binary, decompile_function, find_cross_references, ltrace_run, objdump_headers |
| Pwn        | run_binary, checksec, generate_pwntools_exploit, fuzz_binary, symbolic_execution, crash_analysis, find_rop_gadgets, cyclic_offset |
| Web        | send_http_request, crawl_website, discover_endpoints, test_sql_injection, test_xss, test_command_injection, analyze_http_response |
| Crypto     | analyze_cipher, frequency_analysis, detect_cipher_type, run_crypto_solver, test_common_keys, rsa_small_exponent |
| Steg       | analyze_image, steg_extract, check_lsb, run_stegsolve, extract_metadata, audio_steg, binwalk_carve |
| Forensics  | analyze_file_type, scan_disk_image, extract_archives, binwalk_extract, analyze_pcap, extract_http_streams, extract_dns_queries |
| Filesystem | read_file, write_file, list_directory, search_files, run_shell |
| Internet   | web_search, fetch_webpage, extract_web_text, search_ctf_writeups, summarize_writeup |

---

## Memory System

The agent maintains structured memory across iterations:

- **artifacts** — discovered files and their types
- **strings** — interesting extracted strings (passwords, keys, tokens)
- **endpoints** — discovered URLs and API routes
- **flags** — flag candidates extracted from tool outputs
- **techniques** — writeup strategies retrieved from the internet
- **hypothesis** — current working theories
- **failed_tools** — tools that errored (not retried)
- **tested_inputs** — inputs already tried

Memory is injected into every LLM context call and persisted to `memory.json`.

---

## Stall Recovery

If the agent makes no progress for N iterations (`stall_threshold` in config):

1. The system automatically injects a hint to search for writeups
2. The LLM calls `search_ctf_writeups` or `web_search`
3. Retrieved techniques are stored in memory under `technique`
4. The LLM adapts the technique to the current challenge

---

## Configuration

`workspace/config/config.yaml`:

```yaml
llm:
  base_url: "http://localhost:8080/v1"
  model: "local-model"
  temperature: 0.2
  max_tokens: 4096

agent:
  max_iterations: 40
  tool_timeout: 60
  stall_threshold: 4    # iterations before triggering writeup search

tools:
  safe_shell: true      # only whitelist shell commands
  network_allowed: true
```

---

## Extending with New Tools

```python
from agent.tool_registry import ToolSpec

def my_custom_tool(file_path: str) -> str:
    # ... analysis logic ...
    return "result string"

MY_TOOL = ToolSpec(
    name="my_tool",
    description="Does something useful",
    input_schema={"file_path": "string"},
    fn=my_custom_tool,
    category="misc",
)

# In controller.py _register_all_tools():
from tools.my_module import MY_TOOL
self.registry.register(MY_TOOL)
```

---

## Supported LLM Models (recommended)

| Model | Best For |
|-------|----------|
| mistral-7b | General CTF, fast |
| codellama-13b | Reverse / Pwn (code heavy) |
| deepseek-coder-7b | Exploit generation |
| llama3-8b | Web / OSINT |
| phi-3-medium | Crypto / Forensics |

---

## Logs and Output

Each challenge run creates:

```
workspace/challenges/<name>_<timestamp>/
├── artifacts/          ← copied challenge files
├── outputs/
│   ├── result.json     ← flag + memory summary
│   └── memory.json     ← full knowledge store
└── logs/
    ├── iter_001.txt    ← LLM reasoning at each step
    ├── iter_002.txt
    └── ...
```

`workspace/logs/agent.log` — global structured log with timestamps.
