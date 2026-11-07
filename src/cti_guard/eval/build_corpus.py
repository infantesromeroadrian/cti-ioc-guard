"""One-off corpus construction (maintainer tool; consumers only need ``eval.fetch``).

Candidates are CISA cybersecurity advisories listed in ``corpus/candidates.txt``. For each one
the page and the STIX files linked from it are read from the Internet Archive snapshot (immutable,
so hashes are stable), the reference IOC are taken from the STIX written by the advisory's
authors, and only IOC that literally occur in the normalised page body count as *reachable*.
Selection: advisories with >= ``min_ioc`` reachable IOC, stratified by year, fixed seed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import re
import time
from pathlib import Path
from urllib.parse import urljoin

import httpx

from cti_guard.eval.corpus import DEFAULT_DATA_DIR, sha256_text
from cti_guard.eval.fetch import html_to_text
from cti_guard.eval.stix import stix1_xml_iocs, stix_iocs
from cti_guard.eval.systems import TYPE_TO_WIRE
from cti_guard.security.refang import refang
from cti_guard.security.verifier import find_occurrences

WIRE_TO_TYPE = {v: k for k, v in TYPE_TO_WIRE.items()}
WAYBACK = "https://web.archive.org/web/2026id_/"
STIX_LINK = re.compile(r'href="([^"]*stix[^"]*\.(?:json|xml))"', re.IGNORECASE)


def _get(client: httpx.Client, url: str, cache: Path) -> tuple[bytes, str] | None:
    meta = cache.with_suffix(cache.suffix + ".url")
    if cache.exists() and meta.exists():
        return cache.read_bytes(), meta.read_text()
    for attempt in range(3):
        try:
            r = client.get(WAYBACK + url)
            if r.status_code == 200:
                cache.write_bytes(r.content)
                meta.write_text(str(r.url))
                time.sleep(1.0)
                return r.content, str(r.url)
            if r.status_code == 404:
                return None
        except httpx.HTTPError:
            pass
        time.sleep(3 * (attempt + 1))
    return None


def locate(gold: set[tuple[str, str]], text: str) -> dict[tuple[str, str], tuple[int, int]]:
    """Reachable gold IOC -> (start, end) in ``text`` (original, defanged-aware offsets)."""
    rt = refang(text)
    out: dict[tuple[str, str], tuple[int, int]] = {}
    for wire, value in gold:
        spans = find_occurrences(WIRE_TO_TYPE[wire], value, rt, reject_fragments=False)
        if spans:
            out[(wire, value)] = spans[0]
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m cti_guard.eval.build_corpus")
    root = Path(__file__).resolve().parents[3] / "corpus"
    ap.add_argument("--corpus-dir", type=Path, default=root)
    ap.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    ap.add_argument("--target", type=int, default=40)
    ap.add_argument("--min-ioc", type=int, default=5)
    ap.add_argument("--seed", type=int, default=20261107)
    args = ap.parse_args(argv)

    raw = args.data_dir / "corpus" / "raw"
    texts = args.data_dir / "corpus" / "texts"
    raw.mkdir(parents=True, exist_ok=True)
    texts.mkdir(parents=True, exist_ok=True)
    built: list[dict] = []
    with httpx.Client(
        follow_redirects=True, timeout=90, headers={"User-Agent": "cti-guard-eval/0.2 (research)"}
    ) as c:
        for url in (args.corpus_dir / "candidates.txt").read_text().split():
            rid = url.rsplit("/", 1)[1]
            page = _get(c, url, raw / f"{rid}.html")
            if not page:
                continue
            html = page[0].decode("utf-8", "replace")
            links = sorted(set(STIX_LINK.findall(html)))
            json_links = [link for link in links if link.lower().endswith(".json")]
            use = json_links or [link for link in links if link.lower().endswith(".xml")]
            if not use:
                continue
            gold: set[tuple[str, str]] = set()
            files = []
            for link in use:
                full = urljoin("https://www.cisa.gov", link)
                got = _get(
                    c, full, raw / f"{rid}.{hashlib.sha1(full.encode()).hexdigest()[:8]}.stix"
                )
                if not got:
                    continue
                body = got[0].decode("utf-8", "replace")
                try:
                    gold |= (
                        stix_iocs(body) if link.lower().endswith(".json") else stix1_xml_iocs(body)
                    )
                except Exception as exc:  # malformed bundle: skip file, keep going
                    print("stix parse error", rid, link, type(exc).__name__)
                    continue
                files.append(
                    {
                        "url": full,
                        "archive_url": got[1],
                        "sha256": hashlib.sha256(got[0]).hexdigest(),
                    }
                )
            text = html_to_text(html)
            located = locate(gold, text)
            if len(located) < args.min_ioc:
                continue
            built.append(
                {
                    "id": rid,
                    "year": 2000 + int(rid[2:4]),
                    "url": url,
                    "archive_url": page[1],
                    "stix_format": "json" if json_links else "xml",
                    "stix_files": files,
                    "stix_total": len(gold),
                    "reachable": len(located),
                    "chars": len(text),
                    "text_sha256": sha256_text(text),
                    "_text": text,
                    "_gold": located,
                }
            )
    # Stratified selection by year, fixed seed
    rng = random.Random(args.seed)
    by_year: dict[int, list[dict]] = {}
    for b in built:
        by_year.setdefault(b["year"], []).append(b)
    chosen: list[dict] = []
    years = sorted(by_year)
    quota = {y: max(1, round(args.target * len(by_year[y]) / len(built))) for y in years}
    for y in years:
        pool = sorted(by_year[y], key=lambda b: b["id"])
        rng.shuffle(pool)
        chosen += pool[: quota[y]]
    chosen.sort(key=lambda b: b["id"])
    chosen = chosen[: args.target]
    with (
        (args.corpus_dir / "manifest.jsonl").open("w") as mf,
        (args.corpus_dir / "gold.jsonl").open("w") as gf,
    ):
        for b in chosen:
            (texts / f"{b['id']}.txt").write_text(b["_text"], encoding="utf-8")
            gold = [
                {"type": t, "value": v, "start": s, "end": e}
                for (t, v), (s, e) in sorted(b["_gold"].items(), key=lambda kv: kv[1])
            ]
            meta = {k: v for k, v in b.items() if not k.startswith("_")}
            mf.write(json.dumps(meta) + "\n")
            gf.write(json.dumps({"id": b["id"], "source": "stix", "iocs": gold}) + "\n")
    print(
        f"candidates with STIX and >= {args.min_ioc} reachable IOC: {len(built)}; selected {len(chosen)}"
    )
    print("by year:", {y: sum(1 for b in chosen if b["year"] == y) for y in years})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
