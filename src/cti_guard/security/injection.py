"""Heuristic detector of indirect prompt injection in untrusted feed content.

This is a *tripwire*, not a guarantee: heuristics miss paraphrased or encoded attacks and can
fire on benign text that merely discusses prompt injection. It is one layer among several
(see docs/threat-model.md); its precision/recall on the evaluation corpus is reported in
metrics.json rather than assumed.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

# (rule id, category, regex). Categories: override | directive | role_marker | obfuscation.
_RULES: list[tuple[str, str, str]] = [
    (
        "override_previous",
        "override",
        r"\b(?:ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(?:previous|prior|above|"
        r"earlier|preceding|all|any|your|the)\b[^.\n]{0,30}\b(?:instructions?|prompts?|rules?|"
        r"guidelines?|context|directions?)\b",
    ),
    ("new_instructions", "override", r"\bnew\s+(?:instructions?|task|rules?)\s*:"),
    (
        "persona_switch",
        "override",
        r"\byou\s+are\s+now\b|\bpretend\s+(?:to\s+be|you)\b|"
        r"\bact\s+as\s+(?:if\s+you|an?\s+(?:ai|assistant|language\s+model|llm|system|different))",
    ),
    (
        "mentions_model_internals",
        "override",
        r"\b(?:system\s+prompt|developer\s+message|your\s+instructions|"
        r"as\s+an\s+ai\b)",
    ),
    (
        "suppress_output",
        "directive",
        r"\b(?:do\s*n[o']?t|never|must\s+not|should\s+not|stop)\b[^.\n]{0,30}\b(?:report|list|"
        r"include|extract|output|return|mention|flag)\b[^.\n]{0,40}\b(?:ioc|iocs|indicators?|"
        r"hashes|hash|domains?|ips?|urls?|anything)\b",
    ),
    (
        "omit_indicators",
        "directive",
        r"\b(?:omit|skip|exclude|leave\s+out|discard|drop)\b[^.\n]{0,40}\b(?:ioc|iocs|"
        r"indicators?|hashes|domains?|ips?|urls?)\b",
    ),
    (
        "force_indicator",
        "directive",
        # Needs an explicit modal/adverb: advisories legitimately say "include additional IOCs".
        r"\b(?:also|additionally|must|should|please|now)\s+(?:add|include|append|insert|report|"
        r"list|output)\b[^.\n]{0,40}\b(?:following|extra)\b[^.\n]{0,30}"
        r"\b(?:ioc|iocs|indicators?|domains?|ips?|urls?|hashes)\b",
    ),
    (
        "force_severity",
        "directive",
        r"\b(?:set|mark|rate|classify|label|treat|assess|score)\b[^.\n]{0,50}\b(?:severity|"
        r"as|report|advisory|threat)\b[^.\n]{0,40}\b(?:benign|harmless|low|informational|info|"
        r"false\s+positive|not\s+(?:a\s+)?threat|no\s+risk)\b",
    ),
    (
        "severity_must_be",
        "directive",
        r"\bseverity\b[^.\n]{0,20}\b(?:must|should|has\s+to|is\s+to)\s+be\b",
    ),
    (
        "output_format_hijack",
        "directive",
        r"\b(?:respond|reply|answer|output)\s+(?:only\s+)?(?:with|exactly|in)\b[^.\n]{0,40}"
        r"\b(?:json|empty|nothing|the\s+following)\b",
    ),
    (
        "chat_template_token",
        "role_marker",
        r"<\|?(?:im_start|im_end|system|assistant|endoftext)\|?>|\[/?INST\]|<</?SYS>>",
    ),
    (
        "role_line",
        "role_marker",
        r"(?im)^\s*(?:system|assistant|developer)\s*(?:message)?\s*:",
    ),
    ("markdown_system_header", "role_marker", r"(?im)^\s*#{2,}\s*(?:system|instructions?)\b"),
]
_COMPILED = [(rid, cat, re.compile(pat, re.IGNORECASE)) for rid, cat, pat in _RULES]

_INVISIBLE_RANGES = [
    (0x200B, 0x200F),  # zero-width, LRM/RLM
    (0x202A, 0x202E),  # bidi embedding/override
    (0x2060, 0x2064),  # word joiner and invisible operators
    (0x2066, 0x2069),  # bidi isolates
    (0xFEFF, 0xFEFF),  # BOM / zero-width no-break space
    (0xE0000, 0xE007F),  # Unicode tag characters (ASCII smuggling)
]


@dataclass(frozen=True)
class Finding:
    """One heuristic hit, with its span in the analysed text."""

    rule: str
    category: str
    start: int
    end: int


@dataclass(frozen=True)
class InjectionReport:
    """Result of scanning a document."""

    findings: tuple[Finding, ...]

    @property
    def suspicious(self) -> bool:
        return bool(self.findings)

    @property
    def spans(self) -> list[tuple[int, int]]:
        return [(f.start, f.end) for f in self.findings]

    @property
    def rules(self) -> list[str]:
        return sorted({f.rule for f in self.findings})


def _is_invisible(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in _INVISIBLE_RANGES)


def _invisible(start: int, end: int, n: int, ctx: int) -> Finding:
    return Finding("invisible_characters", "obfuscation", max(0, start - ctx), min(n, end + ctx))


def scan(text: str, context_chars: int = 200) -> InjectionReport:
    """Scan ``text`` and return heuristic findings.

    Each finding span is widened by ``context_chars`` on both sides: injected payloads carry
    their attacker-chosen indicators next to the trigger phrase, and the verifier refuses to
    attribute provenance to anything inside those spans.
    """
    normalized = unicodedata.normalize("NFKC", text)
    # NFKC can change lengths; only trust offsets when it did not.
    haystack = normalized if len(normalized) == len(text) else text
    findings: list[Finding] = []
    for rid, category, regex in _COMPILED:
        for m in regex.finditer(haystack):
            findings.append(
                Finding(
                    rid,
                    category,
                    max(0, m.start() - context_chars),
                    min(len(text), m.end() + context_chars),
                )
            )
    run_start: int | None = None
    for i, ch in enumerate(text):
        if _is_invisible(ch):
            if run_start is None:
                run_start = i
        elif run_start is not None:
            findings.append(_invisible(run_start, i, len(text), context_chars))
            run_start = None
    if run_start is not None:
        findings.append(_invisible(run_start, len(text), len(text), context_chars))
    return InjectionReport(tuple(findings))
