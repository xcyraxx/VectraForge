"""
core/llm_client.py — Ollama LLM Client
========================================
Async HTTP client for communicating with the local Ollama instance.

Features:
  - Async/await with httpx
  - Configurable timeout per request
  - Retry with exponential backoff
  - Health check & model availability check
  - Streaming support (optional)
  - Request size limiting
"""

import asyncio
import logging
from typing import Optional

import httpx

from core.config import Settings

logger = logging.getLogger("vectraforge.llm_client")


class OllamaClient:
    """
    Async client for the Ollama local LLM API.

    Thread-safe: creates a new httpx.AsyncClient per request to avoid
    event-loop conflicts in multi-worker uvicorn deployments.
    """

    def __init__(self):
        self.settings = Settings()
        self.base_url = self.settings.ollama_base_url.rstrip("/")
        self.model    = self.settings.ollama_model
        self.timeout  = self.settings.llm_timeout_seconds
        self.max_retries = self.settings.llm_max_retries

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> str:
        """
        Send a prompt to Ollama and return the text response.

        Uses the /api/generate endpoint with stream=False for simplicity.
        For very large responses, streaming can be enabled via generate_stream().

        Args:
            prompt:        User prompt text.
            system_prompt: Optional system instruction.
            temperature:   Sampling temperature (low = more deterministic).
            max_tokens:    Max tokens to generate.

        Returns:
            Raw text response from the model.

        Raises:
            ConnectionError: If Ollama is unreachable.
            TimeoutError:    If the request exceeds the configured timeout.
        """
        payload = {
            "model":  self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
                # Keep the model warm between requests
                "keep_alive": "10m",
            },
        }
        if system_prompt:
            payload["system"] = system_prompt

        for attempt in range(1, self.max_retries + 1):
            try:
                logger.debug(f"LLM call attempt {attempt}/{self.max_retries}")
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    response = await client.post(
                        f"{self.base_url}/api/generate",
                        json=payload,
                    )
                    response.raise_for_status()
                    data = response.json()
                    text = data.get("response", "")
                    logger.debug(
                        f"LLM stats — eval_count={data.get('eval_count')} "
                        f"eval_duration={data.get('eval_duration')}"
                    )
                    return text

            except httpx.ConnectError as e:
                msg = f"Cannot reach Ollama at {self.base_url}: {e}"
                if attempt == self.max_retries:
                    raise ConnectionError(msg)
                logger.warning(f"{msg} — retrying in {attempt}s...")
                await asyncio.sleep(attempt)

            except httpx.TimeoutException as e:
                msg = f"Ollama request timed out after {self.timeout}s: {e}"
                if attempt == self.max_retries:
                    raise TimeoutError(msg)
                logger.warning(f"{msg} — retrying in {attempt * 2}s...")
                await asyncio.sleep(attempt * 2)

            except httpx.HTTPStatusError as e:
                # 4xx errors are not retryable
                logger.error(f"Ollama HTTP error {e.response.status_code}: {e.response.text}")
                raise ConnectionError(f"Ollama API error {e.response.status_code}: {e.response.text}")

            except Exception as e:
                logger.exception(f"Unexpected LLM client error on attempt {attempt}")
                if attempt == self.max_retries:
                    raise

        raise RuntimeError("LLM generate: exhausted all retries")  # Should not reach here

    async def generate_stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
    ):
        """
        Generator version of generate() for streaming large responses.
        Yields text chunks as they arrive from Ollama.
        """
        import json as _json

        payload = {
            "model":  self.model,
            "prompt": prompt,
            "stream": True,
        }
        if system_prompt:
            payload["system"] = system_prompt

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            async with client.stream("POST", f"{self.base_url}/api/generate", json=payload) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if line:
                        try:
                            chunk = _json.loads(line)
                            if token := chunk.get("response"):
                                yield token
                            if chunk.get("done"):
                                break
                        except _json.JSONDecodeError:
                            continue

    async def health_check(self) -> bool:
        """Return True if Ollama is reachable."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                return resp.status_code == 200
        except Exception:
            return False

    async def model_available(self, model_name: str) -> bool:
        """Return True if the specified model is pulled and available."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                resp.raise_for_status()
                models = [m["name"] for m in resp.json().get("models", [])]
                # Check both exact match and without tag suffix
                return any(
                    m == model_name or m.startswith(model_name.split(":")[0])
                    for m in models
                )
        except Exception:
            return False

    async def list_models(self) -> list[str]:
        """Return a list of available model names."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                resp.raise_for_status()
                return [m["name"] for m in resp.json().get("models", [])]
        except Exception:
            return []
