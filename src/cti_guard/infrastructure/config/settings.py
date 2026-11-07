"""Application settings (pydantic-settings). Secrets only come from the environment."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings loaded from environment variables and an optional .env file."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    app_name: str = "CTI Guard"
    app_version: str = "0.2.0"
    app_env: Literal["development", "staging", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"

    database_url: str = "sqlite:///./threat_intel.db"

    nvd_api_key: SecretStr = SecretStr("")
    otx_api_key: SecretStr = SecretStr("")

    scraper_user_agent: str = "cti-guard/0.2 (research prototype)"
    scraper_rate_limit_seconds: int = Field(default=2, ge=1)
    scraper_max_retries: int = Field(default=3, ge=1, le=10)
    scraper_timeout_seconds: int = Field(default=30, ge=5, le=300)

    # LLM extractor
    llm_provider: Literal["ollama", "openai_compat"] = "ollama"
    llm_model: str = "gpt-oss:120b-cloud"
    ollama_host: str = "http://localhost:11434"
    ollama_api_key: SecretStr = SecretStr("")
    llm_base_url: str = ""
    llm_api_key: SecretStr = SecretStr("")
    llm_max_output_tokens: int = Field(default=6144, ge=64, le=16384)
    llm_timeout_seconds: int = Field(default=120, ge=5, le=900)

    api_cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:8000"])

    @field_validator("api_cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: str | list[str]) -> list[str]:
        """Accept a comma-separated string or a list."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @property
    def has_nvd_api_key(self) -> bool:
        return bool(self.nvd_api_key.get_secret_value())

    @property
    def has_otx_api_key(self) -> bool:
        return bool(self.otx_api_key.get_secret_value())

    @property
    def cache_dir(self) -> Path:
        return Path("./threat_intel_cache")


settings = Settings()
