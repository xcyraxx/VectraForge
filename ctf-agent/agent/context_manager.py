"""
context_manager.py — Assembles and trims the prompt context sent to the LLM.

Responsibilities:
  • Build system prompt with role + instructions
  • Inject challenge info + memory summary
  • Maintain conversation history with token-aware truncation
  • Store full tool outputs on disk; inject summaries into context
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an elite autonomous CTF (Capture the Flag) solving agent.
You analyse cybersecurity challenges across Reverse Engineering, Binary Exploitation (Pwn),
Web Exploitation, Cryptography, Forensics, Steganography, OSINT and Misc categories.

You reason step-by-step and call specialised tools to investigate challenges.
You MUST follow this strict format for every response:

Thought: <your reasoning about the current situation and next step>
Action: <tool_name>
Input: <tool input — a single value or JSON object>

When you have found the flag (format: flag{...} or CTF{...} or similar), respond with:

Final Answer: <the complete flag>

Rules:
- Never guess a flag without evidence.
- Always inspect the challenge files before attempting exploitation.
- If stuck for more than 3 iterations, search for relevant CTF writeups.
- Adapt retrieved techniques; never blindly copy them.
- Keep tool inputs concise and valid.
- One Action per response only.
"""


class ContextManager:
    def __init__(self, max_chars: int = 12_000, output_dir: Optional[Path] = None):
        self.max_chars = max_chars
        self.output_dir = output_dir or Path("/tmp/ctf_context")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._history: list[dict] = []          # {"role": ..., "content": ...}
        self._obs_counter = 0

    # ------------------------------------------------------------------ public
    def system_prompt(self) -> str:
        return SYSTEM_PROMPT

    def build_messages(
        self,
        challenge_info: str,
        memory_summary: str,
        new_observation: Optional[str] = None,
    ) -> list[dict]:
        """
        Return the messages list to send to the LLM.
        Context order: challenge_info + memory, then conversation history.
        """
        context_header = (
            f"=== CHALLENGE INFO ===\n{challenge_info}\n\n"
            f"{memory_summary}\n\n"
            f"=== CONVERSATION ==="
        )

        if new_observation:
            obs_short = self._store_observation(new_observation)
            self._history.append({"role": "user", "content": f"Observation: {obs_short}"})

        messages = [{"role": "user", "content": context_header}]
        messages.extend(self._trim_history())
        return messages

    def add_assistant_turn(self, text: str) -> None:
        self._history.append({"role": "assistant", "content": text})

    def reset(self) -> None:
        self._history.clear()
        self._obs_counter = 0

    # ------------------------------------------------------------------ private
    def _store_observation(self, raw: str) -> str:
        """Save full output to disk; return a truncated/summary version."""
        self._obs_counter += 1
        fname = self.output_dir / f"obs_{self._obs_counter:04d}.txt"
        fname.write_text(raw)

        limit = 3000
        if len(raw) <= limit:
            return raw

        head = raw[:limit // 2]
        tail = raw[-(limit // 2):]
        return (
            f"{head}\n\n[... {len(raw) - limit} chars truncated — "
            f"full output saved to {fname} ...]\n\n{tail}"
        )

    def _trim_history(self) -> list[dict]:
        """Trim history so total character count stays under max_chars."""
        total = 0
        trimmed = []
        for msg in reversed(self._history):
            total += len(msg["content"])
            if total > self.max_chars:
                break
            trimmed.insert(0, msg)
        if len(trimmed) < len(self._history):
            logger.debug(
                "Context trimmed: keeping %d / %d messages",
                len(trimmed),
                len(self._history),
            )
        return trimmed
