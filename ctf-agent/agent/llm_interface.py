"""
llm_interface.py — Local LLM communication layer (OpenAI-compatible API)
"""
from __future__ import annotations

import json
import logging
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)


class LLMInterface:
    """Wraps an OpenAI-compatible local inference endpoint."""

    def __init__(self, cfg: dict):
        self.base_url = cfg["base_url"].rstrip("/")
        self.model = cfg["model"]
        self.temperature = cfg.get("temperature", 0.2)
        self.max_tokens = cfg.get("max_tokens", 4096)
        self.timeout = cfg.get("timeout", 120)
        self.retries = cfg.get("retries", 3)
        self.endpoint = f"{self.base_url}/chat/completions"

    # ------------------------------------------------------------------
    def complete(
        self,
        messages: list[dict],
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
    ) -> str:
        """Send messages to the LLM and return the assistant reply text."""
        payload_messages: list[dict] = []

        if system_prompt:
            payload_messages.append({"role": "system", "content": system_prompt})

        payload_messages.extend(messages)

        payload = {
            "model": self.model,
            "messages": payload_messages,
            "temperature": temperature if temperature is not None else self.temperature,
            "max_tokens": self.max_tokens,
        }

        last_exc: Exception | None = None
        for attempt in range(1, self.retries + 1):
            try:
                resp = requests.post(
                    self.endpoint,
                    json=payload,
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                data = resp.json()
                content: str = data["choices"][0]["message"]["content"]
                logger.debug("LLM response (%d chars)", len(content))
                return content
            except requests.RequestException as exc:
                last_exc = exc
                logger.warning("LLM request attempt %d/%d failed: %s", attempt, self.retries, exc)
                time.sleep(2 * attempt)

        raise RuntimeError(f"LLM unreachable after {self.retries} attempts: {last_exc}")

    # ------------------------------------------------------------------
    def summarize(self, text: str, context_hint: str = "") -> str:
        """Ask the LLM to produce a concise summary of a long text blob."""
        prompt = (
            f"Summarize the following tool output concisely for a CTF analyst. "
            f"Focus on security-relevant findings.{' Context: ' + context_hint if context_hint else ''}\n\n"
            f"OUTPUT:\n{text[:6000]}"
        )
        return self.complete([{"role": "user", "content": prompt}])
