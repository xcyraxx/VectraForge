"""
core/config.py — Application Configuration
============================================
All configuration is loaded from environment variables with sensible
defaults. Create a .env file in the project root to override.

Example .env:
    OLLAMA_BASE_URL=http://127.0.0.1:11434
    OLLAMA_MODEL=deepseek-r1:8b
    LLM_TIMEOUT_SECONDS=120
    LOG_LEVEL=INFO
"""

from functools import lru_cache
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings. All fields can be overridden via environment
    variables or a .env file in the project root.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Ollama ────────────────────────────────────────────────────────────────
    ollama_base_url: str = Field(
        default="http://127.0.0.1:11434",
        description="Ollama API base URL",
    )
    ollama_model: str = Field(
        default="deepseek-r1:8b",
        description="Ollama model tag to use for analysis",
    )

    # ── LLM Behavior ──────────────────────────────────────────────────────────
    llm_timeout_seconds: float = Field(
        default=180.0,
        description="Seconds to wait for LLM response before timeout",
    )
    llm_max_retries: int = Field(
        default=3,
        description="Number of LLM call retries on transient failure",
    )
    llm_temperature: float = Field(
        default=0.1,
        description="LLM sampling temperature (lower = more deterministic)",
    )
    llm_max_tokens: int = Field(
        default=4096,
        description="Maximum tokens to generate per analysis",
    )

    # ── Server ────────────────────────────────────────────────────────────────
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8000)
    workers: int = Field(default=4)

    # ── Security ──────────────────────────────────────────────────────────────
    allowed_origins: list[str] = Field(
        default=["http://localhost", "http://127.0.0.1"],
        description="CORS allowed origins",
    )
    max_request_body_bytes: int = Field(
        default=10 * 1024 * 1024,  # 10 MB
        description="Max raw HTTP request body size",
    )

    # ── Logging ───────────────────────────────────────────────────────────────
    log_level: str = Field(default="INFO")
    log_to_file: bool = Field(default=True)
    log_dir: str = Field(default="logs")

    # ── Debug ─────────────────────────────────────────────────────────────────
    include_raw_llm_output: bool = Field(
        default=False,
        description="Include raw LLM output in API responses (useful for debugging)",
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
