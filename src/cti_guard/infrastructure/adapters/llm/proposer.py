"""LLM proposer: turns untrusted text into *candidate* indicators and a severity opinion.

Nothing returned here is trusted. The caller must run the deterministic verifier.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field

from pydantic import ValidationError

from cti_guard.domain.entities import IOCType
from cti_guard.infrastructure.adapters.llm import prompts
from cti_guard.infrastructure.adapters.llm.clients import LLMClient, LLMError
from cti_guard.infrastructure.adapters.llm.schemas import (
    WIRE_TO_IOC_TYPE,
    ExtractionOutput,
    SeverityOutput,
)
from cti_guard.security.spotlight import new_nonce, wrap_untrusted
from cti_guard.security.verifier import Candidate

HEAD_CHARS = 6000


def chunk_text(text: str, size: int = 4000, overlap: int = 200) -> list[tuple[int, str]]:
    """Split on line boundaries into ``(offset, chunk)`` pairs covering the whole text."""
    if len(text) <= size:
        return [(0, text)]
    chunks: list[tuple[int, str]] = []
    pos = 0
    while pos < len(text):
        end = min(len(text), pos + size)
        if end < len(text):
            nl = text.rfind("\n", pos + size // 2, end)
            end = nl + 1 if nl != -1 else end
        chunks.append((pos, text[pos:end]))
        if end >= len(text):
            break
        pos = max(end - overlap, pos + 1)
    return chunks


_FENCE = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.DOTALL)


def parse_json(raw: str) -> object:
    """Parse model output, tolerating a markdown fence (the schema validation stays strict)."""
    match = _FENCE.match(raw)
    return json.loads(match.group(1) if match else raw)


def seeded_nonce_fn(secret: str) -> Callable[[str], str]:
    """Deterministic-but-secret nonce (for reproducible evals); production uses random nonces."""

    def fn(payload: str) -> str:
        return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]

    return fn


@dataclass
class ProposalResult:
    """Raw proposals for one document."""

    candidates: list[Candidate] = field(default_factory=list)
    llm_severity: str | None = None
    errors: list[str] = field(default_factory=list)
    chunks: int = 0


class LLMProposer:
    """Calls the model per chunk (extraction) and once on the document head (severity)."""

    def __init__(
        self,
        client: LLMClient,
        *,
        hardened: bool = True,
        chunk_size: int = 3000,
        overlap: int = 200,
        max_output_tokens: int = 6144,
        nonce_fn: Callable[[str], str] | None = None,
    ) -> None:
        self.client = client
        self.hardened = hardened
        self.chunk_size = chunk_size
        self.overlap = overlap
        self.max_output_tokens = max_output_tokens
        self.nonce_fn = nonce_fn

    def _render(self, text: str) -> tuple[str, str]:
        """Return (system_nonce_suffix_free_user_message, nonce)."""
        if not self.hardened:
            return prompts.NAIVE_USER_TEMPLATE.format(document=text), ""
        nonce = self.nonce_fn(text) if self.nonce_fn else new_nonce()
        return prompts.HARDENED_USER_TEMPLATE.format(document=wrap_untrusted(text, nonce)), nonce

    def _call(self, system: str, text: str, schema: dict, max_tokens: int) -> str:
        user, nonce = self._render(text)
        if nonce:
            system = system.replace("{NONCE}", nonce)
        return self.client.chat_json(system, user, schema, max_tokens)

    def propose(self, text: str, *, with_severity: bool = True) -> ProposalResult:
        result = ProposalResult()
        system = prompts.HARDENED_EXTRACT_SYSTEM if self.hardened else prompts.NAIVE_EXTRACT_SYSTEM
        schema = ExtractionOutput.model_json_schema()
        for _offset, chunk in chunk_text(text, self.chunk_size, self.overlap):
            result.chunks += 1
            out = None
            for attempt in range(2):  # one retry, then fail closed for this chunk
                try:
                    raw = self._call(system, chunk, schema, self.max_output_tokens)
                    out = ExtractionOutput.model_validate(parse_json(raw))
                    break
                except (LLMError, ValidationError, json.JSONDecodeError) as exc:
                    if attempt == 1:
                        result.errors.append(f"extract: {type(exc).__name__}")
            if out is None:
                continue
            for item in out.indicators:
                ioc_type: IOCType = WIRE_TO_IOC_TYPE[item.type]
                result.candidates.append(Candidate(ioc_type, item.value))
        if with_severity:
            sev_system = (
                prompts.HARDENED_SEVERITY_SYSTEM if self.hardened else prompts.NAIVE_SEVERITY_SYSTEM
            )
            try:
                raw = self._call(
                    sev_system, text[:HEAD_CHARS], SeverityOutput.model_json_schema(), 512
                )
                result.llm_severity = SeverityOutput.model_validate(parse_json(raw)).severity
            except (LLMError, ValidationError, json.JSONDecodeError) as exc:
                result.errors.append(f"severity: {type(exc).__name__}")
        return result
