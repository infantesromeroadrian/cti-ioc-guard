"""Test doubles for the LLM client port."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from cti_guard.infrastructure.adapters.llm.clients import LLMError, ModelInfo


class FakeLLM:
    """Scriptable client: ``handler(system, user, schema)`` returns the raw model text."""

    def __init__(self, handler: Callable[[str, str, dict[str, Any]], str]) -> None:
        self.handler = handler
        self.calls: list[tuple[str, str, dict[str, Any], int]] = []

    def info(self) -> ModelInfo:
        return ModelInfo("fake", "fake-1")

    def chat_json(self, system: str, user: str, schema: dict[str, Any], max_tokens: int) -> str:
        self.calls.append((system, user, schema, max_tokens))
        return self.handler(system, user, schema)


def indicators(*items: tuple[str, str]) -> str:
    return json.dumps({"indicators": [{"type": t, "value": v} for t, v in items]})


def severity(level: str) -> str:
    return json.dumps({"severity": level, "rationale": "test"})


def broken(*_args: Any) -> str:
    raise LLMError("boom")
