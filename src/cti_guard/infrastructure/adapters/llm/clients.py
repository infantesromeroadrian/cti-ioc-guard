"""LLM client port and implementations (Ollama native client, OpenAI-compatible HTTP, cache).

The Ollama adapter uses the native client on purpose: ``options.num_predict`` is honoured by
Ollama, whereas OpenAI-style ``max_completion_tokens`` (what langchain-openai sends) is
silently ignored by Ollama and Groq. The OpenAI-compatible adapter sends ``max_tokens``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx


class LLMError(RuntimeError):
    """Any failure talking to the model backend."""


@dataclass(frozen=True)
class ModelInfo:
    """Exact model identity, recorded in metrics.json."""

    provider: str
    model: str
    digest: str = ""
    server_version: str = ""


class LLMClient(Protocol):
    """Port: one structured-output call. The model has no tools and no side effects."""

    def info(self) -> ModelInfo: ...

    def chat_json(self, system: str, user: str, schema: dict[str, Any], max_tokens: int) -> str:
        """Return the raw JSON text produced by the model."""
        ...


class OllamaClient:
    """Native Ollama client (local daemon or Ollama Cloud with ``OLLAMA_API_KEY``)."""

    def __init__(
        self,
        model: str,
        host: str = "http://localhost:11434",
        api_key: str = "",
        timeout: float = 120.0,
        think: str | None = "low",
    ) -> None:
        import ollama

        headers = {"Authorization": f"Bearer {api_key}"} if api_key else None
        self._client = ollama.Client(host=host, headers=headers, timeout=timeout)
        self.model = model
        self.host = host
        self.think = think

    def info(self) -> ModelInfo:
        digest = ""
        try:
            for item in self._client.list().models:
                if item.model == self.model:
                    digest = (getattr(item, "digest", "") or "")[:12]
        except Exception:  # pragma: no cover - informational only
            digest = ""
        version = ""
        try:
            version = httpx.get(f"{self.host}/api/version", timeout=5).json().get("version", "")
        except Exception:  # pragma: no cover - informational only
            version = ""
        return ModelInfo("ollama", self.model, digest, version)

    def chat_json(self, system: str, user: str, schema: dict[str, Any], max_tokens: int) -> str:
        kwargs: dict[str, Any] = {}
        if self.think:
            kwargs["think"] = self.think
        try:
            resp = self._client.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                format=schema,
                options={"temperature": 0, "seed": 0, "num_predict": max_tokens},
                **kwargs,
            )
        except Exception as exc:
            raise LLMError(f"ollama call failed: {exc}") from exc
        return str(resp.message.content or "")


class OpenAICompatClient:
    """Minimal OpenAI-compatible client (``/v1/chat/completions``) using ``max_tokens``."""

    def __init__(
        self,
        model: str,
        base_url: str,
        api_key: str = "",
        timeout: float = 120.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.model = model
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._http = httpx.Client(
            base_url=base_url.rstrip("/"), headers=headers, timeout=timeout, transport=transport
        )

    def info(self) -> ModelInfo:
        return ModelInfo("openai_compat", self.model)

    def chat_json(self, system: str, user: str, schema: dict[str, Any], max_tokens: int) -> str:
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "max_tokens": max_tokens,
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": "output", "schema": schema, "strict": True},
            },
        }
        try:
            resp = self._http.post("/chat/completions", json=body)
            resp.raise_for_status()
            return str(resp.json()["choices"][0]["message"]["content"] or "")
        except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
            raise LLMError(f"openai-compatible call failed: {exc}") from exc


class CachingClient:
    """Disk cache keyed by (model, prompts, schema, max_tokens): deterministic reruns."""

    def __init__(self, inner: LLMClient, cache_dir: Path) -> None:
        self.inner = inner
        self.cache_dir = cache_dir
        cache_dir.mkdir(parents=True, exist_ok=True)
        self.hits = 0
        self.misses = 0

    def info(self) -> ModelInfo:
        return self.inner.info()

    def chat_json(self, system: str, user: str, schema: dict[str, Any], max_tokens: int) -> str:
        model = self.inner.info().model
        key_src = json.dumps([model, system, user, schema, max_tokens], sort_keys=True)
        path = self.cache_dir / f"{hashlib.sha256(key_src.encode()).hexdigest()}.json"
        if path.exists():
            self.hits += 1
            return str(json.loads(path.read_text())["output"])
        self.misses += 1
        out = self.inner.chat_json(system, user, schema, max_tokens)
        path.write_text(json.dumps({"model": model, "output": out}))
        return out


def build_client(
    provider: str,
    model: str,
    *,
    ollama_host: str = "http://localhost:11434",
    ollama_api_key: str = "",
    base_url: str = "",
    api_key: str = "",
    timeout: float = 120.0,
    think: str | None = "low",
) -> LLMClient:
    """Factory used by the CLI/eval; keys come from the environment, never from code."""
    if provider == "ollama":
        return OllamaClient(model, ollama_host, ollama_api_key, timeout, think)
    if provider == "openai_compat":
        if not base_url:
            raise ValueError("LLM_BASE_URL is required for provider openai_compat")
        return OpenAICompatClient(model, base_url, api_key, timeout)
    raise ValueError(f"unknown LLM provider: {provider}")
