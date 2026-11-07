"""Deterministic severity policy: the LLM may raise severity but never lower the evidence floor."""

from __future__ import annotations

SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")


def rank(severity: str) -> int:
    """Ordinal of a severity label; unknown labels rank as ``info``."""
    try:
        return SEVERITIES.index(severity)
    except ValueError:
        return 0


def evidence_floor(verified_ioc_count: int) -> str:
    """Minimum severity implied by deterministic evidence.

    A document from which at least one indicator was deterministically verified is actionable
    and cannot be rated below ``medium`` by model output alone.
    """
    return "medium" if verified_ioc_count > 0 else "info"


def final_severity(llm_severity: str | None, verified_ioc_count: int) -> str:
    """Combine the model's opinion with the evidence floor (max of both)."""
    floor = evidence_floor(verified_ioc_count)
    if llm_severity is None:
        return floor
    return llm_severity if rank(llm_severity) >= rank(floor) else floor
