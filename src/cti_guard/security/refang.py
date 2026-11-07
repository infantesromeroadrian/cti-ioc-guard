"""Refanging with offset provenance.

CTI reports routinely "defang" indicators (``hxxp://evil[.]example``) so that they are not
clickable. To compare and verify indicators we need their canonical (refanged) form, but
provenance must point at the *literal* characters of the source document. ``refang`` returns
the canonical text together with a per-character map back to the original offsets.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

# Each rule is (regex, replacement function over the matched text).
_RULES: list[tuple[str, Callable[[str], str]]] = [
    (r"\[\s*://\s*\]", lambda _m: "://"),
    (r"\[\s*:\s*\]", lambda _m: ":"),
    (r"\[\s*\.\s*\]", lambda _m: "."),
    (r"\(\s*\.\s*\)", lambda _m: "."),
    (r"\{\s*\.\s*\}", lambda _m: "."),
    (r"\[\s*dot\s*\]", lambda _m: "."),
    (r"\(\s*dot\s*\)", lambda _m: "."),
    (r"\[\s*@\s*\]", lambda _m: "@"),
    (r"\[\s*at\s*\]", lambda _m: "@"),
    (r"\bhxxps?(?=(?:://|\[))", lambda m: "http" + m[4:]),
    (r"\bh\*\*ps?(?=://)", lambda m: "http" + m[3:]),
    (r"\bfxps?(?=://)", lambda m: "ftp" + m[3:]),
]
_COMBINED = re.compile(
    "|".join(f"(?P<r{i}>{pat})" for i, (pat, _) in enumerate(_RULES)), re.IGNORECASE
)


@dataclass(frozen=True)
class RefangedText:
    """Canonical text plus a map from each canonical char back to the original span."""

    text: str
    starts: tuple[int, ...]  # starts[i] = original start offset of canonical char i
    ends: tuple[int, ...]  # ends[i] = original end offset (exclusive) of canonical char i

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        """Map a canonical [start, end) span to the original [start, end) span."""
        if not 0 <= start < end <= len(self.text):
            raise ValueError("span out of range")
        return self.starts[start], self.ends[end - 1]


def refang(text: str) -> RefangedText:
    """Refang ``text`` while keeping offsets traceable to the original string."""
    out: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    pos = 0
    for match in _COMBINED.finditer(text):
        for i in range(pos, match.start()):
            out.append(text[i])
            starts.append(i)
            ends.append(i + 1)
        replacement = _RULES[int(match.lastgroup[1:])][1](match.group(0))  # type: ignore[index]
        for ch in replacement:
            out.append(ch)
            starts.append(match.start())
            ends.append(match.end())
        pos = match.end()
    for i in range(pos, len(text)):
        out.append(text[i])
        starts.append(i)
        ends.append(i + 1)
    return RefangedText("".join(out), tuple(starts), tuple(ends))


def refang_value(value: str) -> str:
    """Canonical form of a single indicator value (as an LLM or a report may write it)."""
    return refang(value.strip()).text
