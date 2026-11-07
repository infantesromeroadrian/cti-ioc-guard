"""Deterministic IOC verifier: the LLM proposes, this module decides.

A proposed indicator is accepted only if it (1) has an allow-listed type, (2) is syntactically
valid for that type and (3) appears *literally* in the source document (modulo defanging), with
a provenance span that does not fall inside a suspected injection span.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from cti_guard.domain.entities import IOCType
from cti_guard.security.refang import RefangedText, refang, refang_value

ALLOWED_TYPES: frozenset[IOCType] = frozenset(
    {
        IOCType.IP_ADDRESS,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.FILE_HASH_MD5,
        IOCType.FILE_HASH_SHA1,
        IOCType.FILE_HASH_SHA256,
        IOCType.CVE_ID,
    }
)

_HASH_LEN = {
    IOCType.FILE_HASH_MD5: 32,
    IOCType.FILE_HASH_SHA1: 40,
    IOCType.FILE_HASH_SHA256: 64,
}
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_TLD = re.compile(r"^(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
# Common file extensions that look like TLDs: "payload.exe" is a file name, not a domain.
_FILE_LIKE_TLDS = frozenset(
    [
        "exe",
        "dll",
        "php",
        "js",
        "json",
        "txt",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "pdf",
        "bat",
        "ps1",
        "msi",
        "tmp",
        "log",
        "html",
        "htm",
        "png",
        "jpg",
        "jpeg",
        "gif",
        "ini",
        "cfg",
        "conf",
        "sys",
        "dat",
        "bin",
        "lnk",
        "vbs",
        "jar",
        "class",
        "cpp",
        "hpp",
        "xml",
        "csv",
        "md",
        "yml",
        "yaml",
        "pyc",
        "rar",
        "iso",
        "img",
        "dmp",
        "bak",
    ]
)
_URL_SCHEMES = frozenset({"http", "https", "ftp"})
_HEX_RUN = re.compile(r"[0-9A-Fa-f]+")
_SHA256_LABEL = re.compile(r"sha-?256", re.IGNORECASE)


def is_hash_fragment(text: str, start: int, end: int) -> bool:
    """True if the hex string at [start, end) is a piece of a longer hash wrapped by layout.

    PDF/HTML tables often break a SHA-256 into pieces separated by whitespace. A piece must not
    be accepted as an MD5/SHA-1: it is a fragment when whitespace-separated neighbouring hex runs
    join with it into 64 hex characters (a new line only counts when a SHA-256 label precedes).
    """
    label_ctx = text[max(0, start - 40) : start]
    allow_newline = bool(_SHA256_LABEL.search(label_ctx))
    sep = r"[ \t\u00a0\r\n]{1,3}" if allow_newline else r"[ \t\u00a0]{1,3}"
    runs = [(start, end)]
    left, right = start, end
    for _ in range(3):
        m = re.search(rf"([0-9A-Fa-f]+){sep}$", text[max(0, left - 70) : left])
        if not m:
            break
        base = max(0, left - 70)
        runs.insert(0, (base + m.start(1), base + m.end(1)))
        left = base + m.start(1)
    for _ in range(3):
        m = re.match(rf"{sep}([0-9A-Fa-f]+)", text[right : right + 70])
        if not m:
            break
        runs.append((right + m.start(1), right + m.end(1)))
        right = right + m.end(1)
    own = runs.index((start, end))
    for i in range(len(runs)):
        for j in range(i, len(runs)):
            if i <= own <= j and j > i and sum(b - a for a, b in runs[i : j + 1]) == 64:
                return True
    return False


_WORD = re.compile(r"[A-Za-z0-9_]")


@dataclass(frozen=True)
class Candidate:
    """A proposed indicator (type + value) coming from an untrusted proposer."""

    ioc_type: IOCType
    value: str


@dataclass(frozen=True)
class Accepted:
    """Indicator that passed every deterministic check."""

    ioc_type: IOCType
    value: str  # canonical form
    start: int  # offsets in the ORIGINAL source text
    end: int


@dataclass(frozen=True)
class Rejected:
    """Indicator rejected, with a machine-readable reason."""

    ioc_type: IOCType
    value: str
    reason: str  # type_not_allowed | invalid_syntax | not_in_source | only_in_injection_span


Span = tuple[int, int]


def canonicalize(ioc_type: IOCType, value: str) -> str | None:
    """Return the canonical form of ``value`` or ``None`` if it is syntactically invalid."""
    raw = refang_value(value).strip()
    if not raw or any(c.isspace() for c in raw):
        return None
    if ioc_type is IOCType.IP_ADDRESS:
        try:
            return str(ipaddress.ip_address(raw.strip("[]")))
        except ValueError:
            return None
    if ioc_type in _HASH_LEN:
        low = raw.lower()
        if len(low) != _HASH_LEN[ioc_type] or not re.fullmatch(r"[0-9a-f]+", low):
            return None
        return None if len(set(low)) == 1 else low
    if ioc_type is IOCType.CVE_ID:
        up = raw.upper()
        return up if _CVE.fullmatch(up) else None
    if ioc_type is IOCType.DOMAIN:
        return _canonical_domain(raw)
    if ioc_type is IOCType.URL:
        return _canonical_url(raw)
    return None


def _canonical_domain(raw: str) -> str | None:
    host = raw.lower().rstrip(".")
    if len(host) > 253 or "." not in host:
        return None
    labels = host.split(".")
    if not all(_LABEL.fullmatch(label) for label in labels):
        return None
    tld = labels[-1]
    if not _TLD.fullmatch(tld) or tld in _FILE_LIKE_TLDS:
        return None
    return host


def _canonical_url(raw: str) -> str | None:
    if len(raw) > 2048:
        return None
    try:
        parts = urlsplit(raw)
        port = parts.port  # raises ValueError if invalid
    except ValueError:
        return None
    if parts.scheme.lower() not in _URL_SCHEMES or not parts.hostname:
        return None
    host = parts.hostname
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if _canonical_domain(host) is None:
            return None
    netloc = host.lower() + (f":{port}" if port else "")
    rest = raw[len(parts.scheme) + 3 + len(parts.netloc) :]
    return f"{parts.scheme.lower()}://{netloc}{rest}"


def _boundary_ok(ioc_type: IOCType, text: str, start: int, end: int) -> bool:
    before = text[start - 1] if start > 0 else ""
    after = text[end] if end < len(text) else ""
    if ioc_type is IOCType.URL:
        return not (before and _WORD.fullmatch(before)) and not (
            after and re.fullmatch(r"[A-Za-z0-9_/%?&=#~+-]", after)
        )
    # Do not match inside a longer token ("evil.com" inside "notevil.com", or an IP inside a
    # longer dotted number, or a hash inside a longer hex string).
    if before and (_WORD.fullmatch(before) or before in "-@"):
        return False
    if before == "." and start > 1 and _WORD.fullmatch(text[start - 2]):
        return False
    if after and (_WORD.fullmatch(after) or after == "-"):
        return False
    return not (after == "." and end + 1 < len(text) and _WORD.fullmatch(text[end + 1]))


def find_occurrences(
    ioc_type: IOCType, canon: str, rt: RefangedText, reject_fragments: bool = True
) -> list[Span]:
    hay = rt.text
    needle = canon
    if len(hay.lower()) == len(hay):  # case-insensitive search (host/hash/CVE casing varies)
        hay, needle = hay.lower(), canon.lower()
    spans: list[Span] = []
    pos = hay.find(needle)
    while pos != -1:
        end = pos + len(needle)
        if _boundary_ok(ioc_type, hay, pos, end) and not (
            reject_fragments
            and ioc_type in _HASH_LEN
            and len(needle) < 64
            and is_hash_fragment(rt.text, pos, end)
        ):
            spans.append(rt.original_span(pos, end))
        pos = hay.find(needle, pos + 1)
    return spans


def _overlaps(span: Span, blocked: list[Span]) -> bool:
    return any(span[0] < b_end and b_start < span[1] for b_start, b_end in blocked)


def verify(
    candidates: list[Candidate],
    source_text: str,
    blocked_spans: list[Span] | None = None,
) -> tuple[list[Accepted], list[Rejected]]:
    """Verify proposed indicators against ``source_text``.

    ``blocked_spans`` are original-text spans flagged as suspected injections; an indicator
    that only occurs inside them is rejected.
    """
    rt = refang(source_text)
    blocked = blocked_spans or []
    accepted: dict[tuple[IOCType, str], Accepted] = {}
    rejected: list[Rejected] = []
    for cand in candidates:
        if cand.ioc_type not in ALLOWED_TYPES:
            rejected.append(Rejected(cand.ioc_type, cand.value, "type_not_allowed"))
            continue
        canon = canonicalize(cand.ioc_type, cand.value)
        if canon is None:
            rejected.append(Rejected(cand.ioc_type, cand.value, "invalid_syntax"))
            continue
        key = (cand.ioc_type, canon)
        if key in accepted:
            continue
        spans = find_occurrences(cand.ioc_type, canon, rt)
        if not spans:
            rejected.append(Rejected(cand.ioc_type, cand.value, "not_in_source"))
            continue
        clean = [s for s in spans if not _overlaps(s, blocked)]
        if not clean:
            rejected.append(Rejected(cand.ioc_type, cand.value, "only_in_injection_span"))
            continue
        accepted[key] = Accepted(cand.ioc_type, canon, clean[0][0], clean[0][1])
    return list(accepted.values()), rejected
