"""Corpus loading. Texts live OUTSIDE the repo (default ~/datasets/cti-llm/corpus/texts)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_DATA_DIR = Path.home() / "datasets" / "cti-llm"
WIRE_TYPES = ("ip", "domain", "url", "md5", "sha1", "sha256", "cve")

Key = tuple[str, str]  # (wire type, canonical value)


@dataclass
class Report:
    """One labelled report."""

    report_id: str
    text: str
    gold: dict[Key, tuple[int, int]] = field(default_factory=dict)  # key -> (start, end)
    meta: dict[str, object] = field(default_factory=dict)


class CorpusError(RuntimeError):
    """Corpus files missing or inconsistent."""


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_corpus(
    repo_corpus_dir: Path, data_dir: Path = DEFAULT_DATA_DIR, *, strict_sha: bool = True
) -> list[Report]:
    """Load manifest + gold from the repo and the texts from ``data_dir/corpus/texts``."""
    manifest_path = repo_corpus_dir / "manifest.jsonl"
    gold_path = repo_corpus_dir / "gold.jsonl"
    if not manifest_path.exists() or not gold_path.exists():
        raise CorpusError(f"missing manifest/gold in {repo_corpus_dir}")
    gold_by_id: dict[str, list[dict]] = {}
    for line in gold_path.read_text().splitlines():
        if line.strip():
            rec = json.loads(line)
            gold_by_id[rec["id"]] = rec["iocs"]
    reports: list[Report] = []
    for line in manifest_path.read_text().splitlines():
        if not line.strip():
            continue
        meta = json.loads(line)
        rid = meta["id"]
        text_path = data_dir / "corpus" / "texts" / f"{rid}.txt"
        if not text_path.exists():
            raise CorpusError(
                f"text for {rid} not found at {text_path}; run scripts/fetch_corpus.py"
            )
        text = text_path.read_text(encoding="utf-8")
        if strict_sha and sha256_text(text) != meta["text_sha256"]:
            raise CorpusError(
                f"sha256 mismatch for {rid}: the source page changed or was re-normalised"
            )
        gold = {
            (g["type"], g["value"]): (g.get("start", -1), g.get("end", -1))
            for g in gold_by_id.get(rid, [])
        }
        reports.append(Report(rid, text, gold, meta))
    return reports
