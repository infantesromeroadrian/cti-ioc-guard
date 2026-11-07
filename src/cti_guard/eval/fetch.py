"""Download the evaluation corpus and verify it against manifest hashes.

``python -m cti_guard.eval.fetch`` reads ``corpus/manifest.jsonl`` (URL + sha256 of the
normalised text), downloads each page to ``~/datasets/cti-llm/corpus/raw`` and writes the
normalised text to ``.../corpus/texts``. Nothing is written inside the repository. Needs the
``eval`` extra (beautifulsoup4, lxml).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

import httpx

from cti_guard.eval.corpus import DEFAULT_DATA_DIR, sha256_text

_DROP_TAGS = ("script", "style", "noscript", "nav", "footer", "header", "form", "svg", "iframe")


def html_to_text(html: str) -> str:
    """Deterministic HTML -> text: main content only, one block per line, whitespace collapsed."""
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "lxml")
    for tag in soup(_DROP_TAGS):
        tag.decompose()
    root = soup.find("main") or soup.find("article") or soup.body or soup
    lines: list[str] = []
    for block in root.find_all(["h1", "h2", "h3", "h4", "p", "li", "tr", "pre", "td", "th"]):
        if block.name in ("td", "th") and block.find_parent("tr"):
            continue  # rows are emitted once through their <tr>
        cells = block.find_all(["td", "th"]) if block.name == "tr" else None
        raw = (
            " | ".join(c.get_text(" ", strip=True) for c in cells)
            if cells
            else block.get_text(" ", strip=True)
        )
        text = re.sub(r"[ \t\r\f\v ]+", " ", raw).strip()
        if text:
            lines.append(text)
    return "\n".join(lines) + "\n"


def _polite_get(
    http: httpx.Client, urls: list[str], delay: float, retries: int = 4
) -> httpx.Response | None:
    """GET with a minimum spacing between requests and exponential backoff on 429/5xx.

    Only URLs taken from the manifest are requested. Be gentle: the archive and the original
    site are shared public resources (a burst of requests already got this project's IP blocked).
    """
    for url in urls:
        for attempt in range(retries):
            time.sleep(max(delay, 1.0))  # never faster than one request per second
            try:
                resp = http.get(url)
            except httpx.HTTPError:
                resp = None
            if resp is not None and resp.status_code == 200:
                return resp
            if resp is not None and resp.status_code not in (429, 500, 502, 503, 504):
                break  # permanent failure for this URL (403, 404, ...): try the next one
            time.sleep(min(60.0, 5.0 * 2**attempt))
    return None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m cti_guard.eval.fetch", description=__doc__)
    ap.add_argument(
        "--corpus-dir", type=Path, default=Path(__file__).resolve().parents[3] / "corpus"
    )
    ap.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    ap.add_argument("--delay", type=float, default=1.5, help="seconds between requests")
    args = ap.parse_args(argv)

    raw_dir = args.data_dir / "corpus" / "raw"
    text_dir = args.data_dir / "corpus" / "texts"
    raw_dir.mkdir(parents=True, exist_ok=True)
    text_dir.mkdir(parents=True, exist_ok=True)
    failures = 0
    with httpx.Client(
        follow_redirects=True,
        timeout=60,
        headers={"User-Agent": "cti-guard-eval/0.2 (research prototype)"},
    ) as http:
        for line in (args.corpus_dir / "manifest.jsonl").read_text().splitlines():
            if not line.strip():
                continue
            meta = json.loads(line)
            rid, raw_path = meta["id"], raw_dir / f"{meta['id']}.html"
            if not raw_path.exists():
                # The archived snapshot is immutable, so the sha256 stays valid; the live URL
                # (meta["url"]) is only a fallback and may have changed since.
                resp = _polite_get(
                    http, [u for u in (meta.get("archive_url"), meta["url"]) if u], args.delay
                )
                if resp is None:
                    failures += 1
                    print(f"DOWNLOAD FAILED {rid}", file=sys.stderr)
                    continue
                raw_path.write_bytes(resp.content)
            text = html_to_text(raw_path.read_text(encoding="utf-8", errors="replace"))
            (text_dir / f"{rid}.txt").write_text(text, encoding="utf-8")
            if sha256_text(text) != meta["text_sha256"]:
                failures += 1
                print(f"SHA MISMATCH {rid}: page changed or normaliser differs", file=sys.stderr)
    print(f"done, {failures} mismatches")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
