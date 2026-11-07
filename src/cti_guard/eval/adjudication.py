"""Adjudication of extracted indicators that are absent from the reference STIX.

The STIX written by the advisory authors is the independent reference for *recall*. Extractors
also return indicators that STIX does not list; some are real (STIX is not exhaustive), some are
benign mentions. Precision is therefore reported twice: strictly against STIX, and after
adjudication. Verdicts come from fixed rules (below, documented in corpus/ANNOTATION.md) or from a
manual judgement that is recorded case by case in ``corpus/adjudication.jsonl``.
"""

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from urllib.parse import urlsplit

from cti_guard.domain.entities import IOCType
from cti_guard.eval.corpus import Key, Report
from cti_guard.eval.systems import TYPE_TO_WIRE
from cti_guard.security.refang import refang
from cti_guard.security.verifier import canonicalize, find_occurrences

WIRE_TO_TYPE: dict[str, IOCType] = {v: k for k, v in TYPE_TO_WIRE.items()}

Verdict = str  # "TP" | "FP"
BENIGN_SUFFIXES = (
    ".gov", ".mil", ".edu", ".gov.uk", ".gov.au", ".gc.ca", ".govt.nz", ".gov.pl", ".gov.it",
    "cisa.gov", "cisecurity.org", "microsoft.com", "google.com", "github.com", "mitre.org",
    "virustotal.com", "wikipedia.org", "w3.org", "apache.org", "mozilla.org", "oracle.com",
)  # fmt: skip
FILE_LIKE_LABELS = ("secretsdump.py", "ntds.dit")


def _host(key: Key) -> str:
    t, v = key
    if t == "url":
        try:
            return (urlsplit(v).hostname or "").lower()
        except ValueError:
            return ""
    return v.lower() if t == "domain" else ""


def rule_verdict(key: Key, gold: set[Key]) -> tuple[Verdict, str] | None:
    """Deterministic verdicts. ``None`` means: needs a manual decision."""
    t, v = key
    if canonicalize(WIRE_TO_TYPE[t], v) != v:
        return "FP", "A5_invalid_syntax_or_not_canonical"
    gold_hosts = {_host(g) for g in gold if g[0] == "url"}
    if t in ("domain", "ip") and v in gold_hosts:
        return "TP", "A1_host_of_reference_url"
    if t in ("domain", "url"):
        host = _host(key)
        if any(
            host == s.lstrip(".") or host.endswith(s if s.startswith(".") else "." + s)
            for s in BENIGN_SUFFIXES
        ):
            return "FP", "A2_benign_authority_or_vendor_domain"
        if any(host == f or host.endswith("." + f) for f in FILE_LIKE_LABELS):
            return "FP", "A3_file_name_not_domain"
    if t == "ip":
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            return "FP", "A5_invalid_syntax"
        if not ip.is_global:
            return "FP", "A4_non_global_address"
    return None


def load_adjudication(path: Path) -> dict[tuple[str, str, str], dict]:
    out: dict[tuple[str, str, str], dict] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rec = json.loads(line)
                out[(rec["id"], rec["type"], rec["value"])] = rec
    return out


def resolve(
    report: Report, pred: set[Key], recorded: dict[tuple[str, str, str], dict]
) -> tuple[set[Key], set[Key], set[Key]]:  # (TP, FP incl. dual-use tools, pending)
    """Split ``pred - gold`` into (adjudicated TP, adjudicated FP, unadjudicated)."""
    gold = set(report.gold)
    tp: set[Key] = set()
    tool: set[Key] = set()
    fp: set[Key] = set()
    pending: set[Key] = set()
    rt = refang(report.text)
    for key in pred - gold:
        if key[0] in WIRE_TO_TYPE and not find_occurrences(WIRE_TO_TYPE[key[0]], key[1], rt):
            fp.add(key)  # A6 (absent) / A7 (hash fragment): never a valid indicator
            continue
        rec = recorded.get((report.report_id, *key))
        verdict = rec["verdict"] if rec else None
        if verdict is None:
            rv = rule_verdict(key, gold)
            verdict = rv[0] if rv else None
        if verdict == "TP":
            tp.add(key)
        elif verdict == "TOOL":
            tool.add(key)
            fp.add(key)  # dual-use tool: never counted as TP; reported separately
        elif verdict == "FP":
            fp.add(key)
        else:
            pending.add(key)
    return tp, fp, pending
