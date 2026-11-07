"""Spotlighting: mark untrusted text as data (delimiting + datamarking).

Follows the "spotlighting" family of defences against indirect prompt injection (Hines et al.,
2024): the untrusted document is wrapped in per-call random delimiters and every whitespace
run inside it is replaced by a marker character, so the model can tell document tokens from
instruction tokens. Indicators contain no whitespace, so their literal values are untouched
and can still be verified against the original text.
"""

from __future__ import annotations

import re
import secrets

DATAMARK = "ˆ"  # modifier letter circumflex accent: rare in CTI prose
_WS = re.compile(r"\s+")


def datamark(text: str) -> str:
    """Replace each whitespace run with the datamark."""
    return _WS.sub(DATAMARK, text)


def new_nonce() -> str:
    """Unguessable delimiter id, fresh for every call (the attacker cannot close the tag)."""
    return secrets.token_hex(8)


def wrap_untrusted(text: str, nonce: str) -> str:
    """Wrap datamarked text in nonce-tagged delimiters. Occurrences of the tag are neutralised."""
    safe = datamark(text).replace(f"untrusted_document_{nonce}", "untrusted_document_REDACTED")
    return f"<untrusted_document_{nonce}>\n{safe}\n</untrusted_document_{nonce}>"
