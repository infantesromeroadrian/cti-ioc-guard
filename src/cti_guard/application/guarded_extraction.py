"""Guarded extraction: LLM proposes, deterministic controls decide.

Pipeline for one untrusted document::

    scan for injection ──► quarantine? ──yes──► no LLM call, nothing is emitted
            │ no
            ▼
    LLM proposer (spotlighted prompt, pure function, structured output)
            │ candidates
            ▼
    deterministic verifier (type allow-list, syntax, literal presence, span veto)
            │ verified IOCs with provenance
            ▼
    severity = max(LLM opinion, evidence floor)      alerts only from verified IOCs
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from cti_guard.domain.entities import IOC, IOCConfidence
from cti_guard.infrastructure.adapters.llm.proposer import LLMProposer
from cti_guard.security import injection, policy
from cti_guard.security.verifier import Accepted, Candidate, Rejected, verify


@dataclass(frozen=True)
class DefenseConfig:
    """Which defences are active (used by the ablation in the evaluation)."""

    verifier: bool = True
    span_veto: bool = True
    quarantine: bool = True
    severity_floor: bool = True

    @classmethod
    def none(cls) -> DefenseConfig:
        return cls(False, False, False, False)


@dataclass
class ExtractionResult:
    """Outcome for one document."""

    accepted: list[Accepted] = field(default_factory=list)
    rejected: list[Rejected] = field(default_factory=list)
    severity: str | None = None
    quarantined: bool = False
    injection_rules: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_iocs(self, document_id: str, extractor: str, text: str) -> list[IOC]:
        """Convert accepted indicators into domain IOCs with provenance."""
        now = datetime.utcnow()
        return [
            IOC(
                value=a.value,
                ioc_type=a.ioc_type,
                confidence=IOCConfidence.MEDIUM,
                source_document_id=document_id,
                extracted_at=now,
                context=text[max(0, a.start - 80) : a.end + 80],
                start=a.start,
                end=a.end,
                extractor=extractor,
                verified=True,
            )
            for a in self.accepted
        ]


class GuardedExtractor:
    """Runs the full guarded pipeline for one document."""

    def __init__(self, proposer: LLMProposer, defenses: DefenseConfig | None = None) -> None:
        self.proposer = proposer
        self.defenses = defenses or DefenseConfig()

    def run(self, text: str, *, with_severity: bool = True) -> ExtractionResult:
        result = ExtractionResult()
        report = injection.scan(text)
        result.injection_rules = report.rules
        if self.defenses.quarantine and report.suspicious:
            result.quarantined = True
            return result

        proposal = self.proposer.propose(text, with_severity=with_severity)
        result.errors = proposal.errors
        return self.finalize(text, proposal.candidates, proposal.llm_severity, result)

    def finalize(
        self,
        text: str,
        candidates: list[Candidate],
        llm_severity: str | None,
        result: ExtractionResult | None = None,
    ) -> ExtractionResult:
        """Apply the post-LLM deterministic stages (separate so evals can replay raw outputs)."""
        result = result or ExtractionResult()
        if self.defenses.verifier:
            blocked = injection.scan(text).spans if self.defenses.span_veto else []
            result.accepted, result.rejected = verify(candidates, text, blocked)
        else:
            from cti_guard.security.verifier import canonicalize

            seen: set[tuple[object, str]] = set()
            for cand in candidates:
                canon = canonicalize(cand.ioc_type, cand.value) or cand.value
                if (cand.ioc_type, canon) not in seen:
                    seen.add((cand.ioc_type, canon))
                    result.accepted.append(Accepted(cand.ioc_type, canon, -1, -1))
        if llm_severity is not None or self.defenses.severity_floor:
            if self.defenses.severity_floor:
                result.severity = policy.final_severity(llm_severity, len(result.accepted))
            else:
                result.severity = llm_severity
        return result
