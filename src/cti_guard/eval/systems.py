"""Systems under evaluation: regex baselines and the five cumulative LLM defence levels.

Levels (each adds one control to the previous one):
  llm_d0_naive      naive prompt, raw model output
  llm_d1_spotlight  + spotlighting (nonce delimiters + datamarking) and a pure-function prompt
  llm_d2_verifier   + deterministic verifier (type allow-list, syntax, literal presence)
                    + severity evidence floor
  llm_d3_span_veto  + indicators inside suspected-injection spans are refused
  llm_d4_quarantine + documents that trip injection heuristics are quarantined (no output)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from cti_guard.application.guarded_extraction import DefenseConfig, GuardedExtractor
from cti_guard.domain.entities import IOCType
from cti_guard.eval.corpus import Key
from cti_guard.infrastructure.adapters.extractors import RegexIOCExtractor
from cti_guard.infrastructure.adapters.llm.clients import LLMClient
from cti_guard.infrastructure.adapters.llm.proposer import LLMProposer, ProposalResult
from cti_guard.infrastructure.adapters.llm.schemas import WIRE_TO_IOC_TYPE
from cti_guard.security import injection
from cti_guard.security.refang import refang
from cti_guard.security.verifier import canonicalize

TYPE_TO_WIRE: dict[IOCType, str] = {v: k for k, v in WIRE_TO_IOC_TYPE.items()}
LLM_LEVELS = (
    "llm_d0_naive",
    "llm_d1_spotlight",
    "llm_d2_verifier",
    "llm_d3_span_veto",
    "llm_d4_quarantine",
)
REGEX_SYSTEMS = ("regex", "regex_refang")
ALL_SYSTEMS = (*REGEX_SYSTEMS, *LLM_LEVELS)


@dataclass
class Output:
    """What one system produced for one document."""

    iocs: set[Key] = field(default_factory=set)
    severity: str | None = None
    quarantined: bool = False
    errors: int = 0


def _to_key(ioc_type: IOCType, value: str) -> Key | None:
    wire = TYPE_TO_WIRE.get(ioc_type)
    if wire is None:
        return None
    canon = canonicalize(ioc_type, value)
    return (wire, canon) if canon else None


def run_regex(text: str, *, with_refang: bool) -> Output:
    logging.getLogger().setLevel(logging.ERROR)
    src = refang(text).text if with_refang else text
    out = Output()
    for ioc in RegexIOCExtractor().extract_from_text(src, "eval"):
        key = _to_key(ioc.ioc_type, ioc.value)
        if key:
            out.iocs.add(key)
    return out


class LLMSystems:
    """Runs the model once per prompt style and replays deterministic stages per level."""

    def __init__(self, client: LLMClient, nonce_fn) -> None:
        self.naive = LLMProposer(client, hardened=False)
        self.hard = LLMProposer(client, hardened=True, nonce_fn=nonce_fn)

    def propose(self, text: str) -> tuple[ProposalResult, ProposalResult]:
        return self.naive.propose(text), self.hard.propose(text)

    def levels(
        self, text: str, proposals: tuple[ProposalResult, ProposalResult]
    ) -> dict[str, Output]:
        naive, hard = proposals
        cfgs = {
            "llm_d0_naive": (naive, DefenseConfig.none(), self.naive),
            "llm_d1_spotlight": (hard, DefenseConfig.none(), self.hard),
            "llm_d2_verifier": (hard, DefenseConfig(True, False, False, True), self.hard),
            "llm_d3_span_veto": (hard, DefenseConfig(True, True, False, True), self.hard),
        }
        outs: dict[str, Output] = {}
        for name, (prop, cfg, proposer) in cfgs.items():
            res = GuardedExtractor(proposer, cfg).finalize(text, prop.candidates, prop.llm_severity)
            outs[name] = Output(_keys(res.accepted), res.severity, False, len(prop.errors))
        if injection.scan(text).suspicious:
            outs["llm_d4_quarantine"] = Output(set(), None, True, 0)
        else:
            d3 = outs["llm_d3_span_veto"]
            outs["llm_d4_quarantine"] = Output(set(d3.iocs), d3.severity, False, d3.errors)
        return outs


def _keys(accepted) -> set[Key]:
    out: set[Key] = set()
    for a in accepted:
        wire = TYPE_TO_WIRE.get(a.ioc_type)
        if wire:
            out.add((wire, a.value))
    return out
