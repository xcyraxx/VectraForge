"""
controller.py — Autonomous CTF agent reasoning loop.

Flow:
  1. Receive challenge input
  2. Initialise workspace
  3. Classify challenge type
  4. Build prompt context
  5. Send to LLM
  6. Parse Thought / Action / Input
  7. Validate + execute tool
  8. Summarise output
  9. Update memory
  10. Repeat until Final Answer or iteration limit
"""
from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from agent.context_manager import ContextManager
from agent.llm_interface import LLMInterface
from agent.memory import AgentMemory
from agent.tool_registry import ToolRegistry
from agent.workspace_manager import WorkspaceManager

logger = logging.getLogger(__name__)


# ────────────────────────────────────────── challenge dataclass ─────────────

@dataclass
class Challenge:
    name: str
    description: str = ""
    files: list[str] = field(default_factory=list)
    url: str = ""
    category: str = ""          # auto-detected if empty
    extra: dict = field(default_factory=dict)


# ────────────────────────────────────────── type detection ──────────────────

CATEGORY_SIGNATURES = {
    "web": [".php", ".html", ".js", "http://", "https://", "login", "sql", "xss"],
    "pwn": [".elf", "binary", "overflow", "exploit", "pwn", "nc ", "netcat"],
    "reverse": [".exe", ".elf", ".dll", ".so", "crackme", "keygen", "reverse"],
    "crypto": [".pem", ".key", "encrypt", "cipher", "rsa", "aes", "decode"],
    "forensics": [".pcap", ".pcapng", ".img", ".dd", ".vmdk", "memory", "disk"],
    "steg": [".png", ".jpg", ".jpeg", ".bmp", ".wav", ".mp3", "steganography", "image"],
    "osint": ["osint", "person", "username", "social", "find", "locate"],
}

EXT_TO_CATEGORY = {
    ".pcap": "forensics", ".pcapng": "forensics", ".img": "forensics",
    ".png": "steg", ".jpg": "steg", ".jpeg": "steg", ".bmp": "steg",
    ".wav": "steg", ".mp3": "steg",
    ".elf": "reverse", ".exe": "reverse", ".dll": "reverse",
    ".pem": "crypto", ".key": "crypto",
    ".zip": "forensics", ".gz": "forensics", ".tar": "forensics",
}


def detect_category(challenge: Challenge) -> str:
    if challenge.category:
        return challenge.category

    combined = (challenge.description + " " + " ".join(challenge.files) + " " + challenge.url).lower()

    # Extension-based
    for f in challenge.files:
        ext = Path(f).suffix.lower()
        if ext in EXT_TO_CATEGORY:
            return EXT_TO_CATEGORY[ext]

    # URL → web
    if challenge.url:
        return "web"

    # Keyword-based scoring
    scores = {cat: 0 for cat in CATEGORY_SIGNATURES}
    for cat, keywords in CATEGORY_SIGNATURES.items():
        for kw in keywords:
            if kw in combined:
                scores[cat] += 1

    best = max(scores, key=scores.get)
    if scores[best] > 0:
        return best

    return "misc"


# ────────────────────────────────────────── response parser ─────────────────

class LLMResponseParser:
    THOUGHT_RE = re.compile(r"Thought\s*:\s*(.*?)(?=Action\s*:|Final Answer\s*:|$)", re.DOTALL | re.IGNORECASE)
    ACTION_RE  = re.compile(r"Action\s*:\s*(\S+)", re.IGNORECASE)
    INPUT_RE   = re.compile(r"Input\s*:\s*(.*?)(?=Thought\s*:|Action\s*:|Observation\s*:|Final Answer\s*:|$)", re.DOTALL | re.IGNORECASE)
    FINAL_RE   = re.compile(r"Final Answer\s*:\s*(.*)", re.IGNORECASE | re.DOTALL)
    FLAG_RE    = re.compile(r"[A-Za-z0-9_]{1,10}\{[^}]{3,80}\}", re.IGNORECASE)

    def parse(self, text: str) -> dict:
        result = {
            "thought": "",
            "action": None,
            "input": "",
            "final_answer": None,
            "flag_candidates": [],
            "raw": text,
        }

        final_match = self.FINAL_RE.search(text)
        if final_match:
            result["final_answer"] = final_match.group(1).strip()

        thought_match = self.THOUGHT_RE.search(text)
        if thought_match:
            result["thought"] = thought_match.group(1).strip()

        action_match = self.ACTION_RE.search(text)
        if action_match:
            result["action"] = action_match.group(1).strip()

        input_match = self.INPUT_RE.search(text)
        if input_match:
            result["input"] = input_match.group(1).strip()

        # Scan for flag patterns anywhere in the text
        result["flag_candidates"] = list(set(self.FLAG_RE.findall(text)))

        return result


# ────────────────────────────────────────── agent controller ────────────────

class AgentController:
    def __init__(self, config_path: str = "workspace/config/config.yaml"):
        with open(config_path) as f:
            self.cfg = yaml.safe_load(f)

        self.llm = LLMInterface(self.cfg["llm"])
        self.memory = AgentMemory(self.cfg["agent"]["memory_max_entries"])
        self.context = ContextManager(
            max_chars=self.cfg["agent"]["context_max_chars"],
            output_dir=Path(self.cfg["paths"]["logs"]) / "observations",
        )
        self.workspace = WorkspaceManager(self.cfg["paths"]["challenges"])
        self.registry = ToolRegistry()
        self.parser = LLMResponseParser()

        self._register_all_tools()
        self._setup_logging()

    # ------------------------------------------------------------------ setup
    def _setup_logging(self) -> None:
        level = getattr(logging, self.cfg["agent"]["log_level"], logging.INFO)
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(
                    Path(self.cfg["paths"]["logs"]) / "agent.log",
                    encoding="utf-8",
                ),
            ],
        )

    def _register_all_tools(self) -> None:
        from tools.crypto_tools import CRYPTO_TOOLS
        from tools.forensics_tools import FORENSICS_TOOLS
        from tools.internet_tools import INTERNET_TOOLS
        from tools.pwn_tools import PWN_TOOLS
        from tools.reverse_tools import REVERSE_TOOLS
        from tools.steg_tools import STEG_TOOLS
        from tools.web_tools import WEB_TOOLS

        for tools_list in [REVERSE_TOOLS, PWN_TOOLS, WEB_TOOLS, CRYPTO_TOOLS,
                            STEG_TOOLS, FORENSICS_TOOLS, INTERNET_TOOLS]:
            self.registry.register_all(tools_list)

        logger.info("Registered %d tools", len(self.registry.list_tools()))

    # ------------------------------------------------------------------ solve
    def solve(self, challenge: Challenge) -> Optional[str]:
        """Main entry point. Returns the flag if found, None otherwise."""
        # Detect category
        challenge.category = detect_category(challenge)
        logger.info("Challenge '%s' | Category: %s", challenge.name, challenge.category)

        # Init workspace
        ws = self.workspace.init(challenge.name)
        if challenge.files:
            self.workspace.copy_challenge_files(*challenge.files)

        # Build initial challenge info
        challenge_info = self._build_challenge_info(challenge, ws)

        # Reset context
        self.context.reset()

        # Inject tool catalog into memory
        self.memory.add("meta", "tool_catalog", self.registry.tool_catalog(), source="init")
        self.memory.add("meta", "workspace", str(ws), source="init")
        if challenge.files:
            for f in challenge.files:
                self.memory.add("artifact", f, "challenge file", source="init")
        if challenge.url:
            self.memory.add("endpoint", challenge.url, "challenge URL", source="init")

        # Reasoning loop
        max_iter = self.cfg["agent"]["max_iterations"]
        stall_threshold = self.cfg["agent"]["stall_threshold"]
        tool_timeout = self.cfg["agent"]["tool_timeout"]
        last_new_artifact_iter = 0
        observation: Optional[str] = None

        for iteration in range(1, max_iter + 1):
            logger.info("─── Iteration %d / %d ───", iteration, max_iter)

            # Stall detection → trigger search
            if iteration - last_new_artifact_iter >= stall_threshold and iteration > stall_threshold:
                logger.info("Stall detected — injecting writeup search hint")
                observation = (
                    f"[SYSTEM] You have not discovered new artifacts for {stall_threshold} iterations. "
                    f"Consider searching for CTF writeups about this challenge type. "
                    f"Use: web_search or search_ctf_writeups"
                )

            # Build messages
            messages = self.context.build_messages(
                challenge_info=challenge_info,
                memory_summary=self.memory.build_summary(),
                new_observation=observation,
            )

            # LLM inference
            try:
                response_text = self.llm.complete(
                    messages,
                    system_prompt=self.context.system_prompt(),
                )
            except RuntimeError as exc:
                logger.error("LLM failure: %s", exc)
                break

            logger.debug("LLM response:\n%s", response_text)
            self.context.add_assistant_turn(response_text)
            self._log_iteration(iteration, response_text, ws)

            # Parse response
            parsed = self.parser.parse(response_text)

            # Record flag candidates from LLM output
            for flag in parsed["flag_candidates"]:
                self.memory.record_flag_candidate(flag)

            # Final answer?
            if parsed["final_answer"]:
                logger.info("★ FINAL ANSWER: %s", parsed["final_answer"])
                self._save_results(challenge, parsed["final_answer"], ws)
                return parsed["final_answer"]

            # Execute tool
            if not parsed["action"]:
                logger.warning("No action found in LLM response — asking LLM to continue")
                observation = "Please provide your next Thought and Action."
                continue

            tool_name = parsed["action"]
            tool_input = parsed["input"]

            logger.info("Action: %s | Input: %s", tool_name, tool_input[:100])

            observation = self.registry.execute(
                tool_name, tool_input, timeout=tool_timeout
            )

            # Update memory from observation
            new_entries = self._extract_memory_from_observation(tool_name, tool_input, observation)
            if new_entries:
                last_new_artifact_iter = iteration

            logger.info("Observation (%d chars)", len(observation))

        logger.warning("Max iterations reached without finding a flag.")
        flags = self.memory.get_category("flag")
        if flags:
            best = flags[-1].value
            logger.info("Returning best flag candidate: %s", best)
            return best
        return None

    # ------------------------------------------------------------------ helpers
    def _build_challenge_info(self, challenge: Challenge, ws: Path) -> str:
        lines = [
            f"Challenge Name: {challenge.name}",
            f"Category: {challenge.category}",
        ]
        if challenge.description:
            lines.append(f"Description: {challenge.description}")
        if challenge.files:
            lines.append(f"Files: {', '.join(challenge.files)}")
        if challenge.url:
            lines.append(f"URL: {challenge.url}")
        lines.append(f"Workspace: {ws}")
        lines.append(f"\n{self.registry.tool_catalog()}")
        return "\n".join(lines)

    def _extract_memory_from_observation(self, tool: str, inp: str, obs: str) -> int:
        """Extract interesting findings from tool output and store in memory."""
        import re
        count = 0

        # Flag patterns
        flags = re.findall(r"[A-Za-z0-9_]{1,10}\{[^}]{3,80}\}", obs)
        for f in flags:
            self.memory.record_flag_candidate(f)
            self.memory.add("flag", f, f"found by {tool}", source=tool)
            count += 1

        # URLs
        urls = re.findall(r"https?://[^\s\"'<>]+", obs)
        for u in urls[:5]:
            self.memory.add("endpoint", u, f"discovered by {tool}", source=tool)
            count += 1

        # Strings (interesting lines)
        for line in obs.splitlines()[:50]:
            if any(kw in line.lower() for kw in ["password", "secret", "key", "token", "admin", "flag"]):
                self.memory.add("string", line.strip()[:120], f"from {tool}", source=tool)
                count += 1

        # Record tested inputs
        if inp:
            self.memory.record_tested_input(inp)

        # Record failed tools
        if obs.startswith("ERROR") or obs.startswith("TIMEOUT"):
            self.memory.record_failed_tool(tool)

        return count

    def _log_iteration(self, iteration: int, response: str, ws: Path) -> None:
        log_file = ws / "logs" / f"iter_{iteration:03d}.txt"
        log_file.write_text(response, encoding="utf-8")

    def _save_results(self, challenge: Challenge, flag: str, ws: Path) -> None:
        result = {
            "challenge": challenge.name,
            "category": challenge.category,
            "flag": flag,
            "memory_summary": self.memory.build_summary(),
        }
        out = ws / "outputs" / "result.json"
        out.write_text(json.dumps(result, indent=2))
        logger.info("Results saved → %s", out)
        self.memory.save(ws / "outputs" / "memory.json")
