"""``python -m cti_guard.eval`` — one command, one metrics.json."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

from cti_guard.eval.adjudication import load_adjudication
from cti_guard.eval.attacks import DEFAULT_TEMPLATES, load_templates
from cti_guard.eval.corpus import DEFAULT_DATA_DIR, CorpusError, load_corpus
from cti_guard.eval.runner import run_all, write_metrics
from cti_guard.infrastructure.adapters.llm.clients import CachingClient, build_client

REPO_CORPUS = Path(__file__).resolve().parents[3] / "corpus"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m cti_guard.eval", description=__doc__)
    ap.add_argument(
        "--corpus-dir", type=Path, default=REPO_CORPUS, help="manifest.jsonl + gold.jsonl"
    )
    ap.add_argument(
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help="texts + LLM cache (outside the repo)",
    )
    ap.add_argument("--out", type=Path, default=Path("metrics.json"))
    ap.add_argument("--templates", type=Path, default=DEFAULT_TEMPLATES)
    ap.add_argument("--provider", default=os.getenv("LLM_PROVIDER", "ollama"))
    ap.add_argument("--model", default=os.getenv("LLM_MODEL", "gpt-oss:120b-cloud"))
    ap.add_argument("--no-llm", action="store_true", help="baselines only (no model calls)")
    ap.add_argument("--robust-reports", type=int, default=20)
    ap.add_argument(
        "--per-attack", type=int, default=2, help="templates sampled per report and attack"
    )
    ap.add_argument(
        "--reps",
        type=int,
        default=3,
        help="robustness repetitions (new template/fake sampling each)",
    )
    ap.add_argument("--timeout", type=float, default=300.0, help="per-call timeout (s)")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument(
        "--dump-outputs",
        type=Path,
        default=None,
        help="write per-report outputs (for adjudication)",
    )
    ap.add_argument("--limit", type=int, default=0, help="use only the first N reports (debug)")
    args = ap.parse_args(argv)

    try:
        reports = load_corpus(args.corpus_dir, args.data_dir)
    except CorpusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.limit:
        reports = reports[: args.limit]
    templates = load_templates(args.templates)

    client = None
    if not args.no_llm:
        raw = build_client(
            args.provider,
            args.model,
            ollama_host=os.getenv("OLLAMA_HOST", "http://localhost:11434"),
            ollama_api_key=os.getenv("OLLAMA_API_KEY", ""),
            base_url=os.getenv("LLM_BASE_URL", ""),
            api_key=os.getenv("LLM_API_KEY", ""),
            timeout=args.timeout,
            think="low" if "gpt-oss" in args.model else None,
        )
        slug = args.model.replace(":", "_").replace("/", "_")
        client = CachingClient(raw, args.data_dir / "cache" / slug)

    gold_sha = hashlib.sha256((args.corpus_dir / "gold.jsonl").read_bytes()).hexdigest()
    meta = {
        "reports": len(reports),
        "gold_iocs": sum(len(r.gold) for r in reports),
        "gold_sha256": gold_sha,
    }
    metrics = run_all(
        reports,
        templates,
        client,
        robust_n=args.robust_reports,
        per_attack=args.per_attack,
        workers=args.workers,
        seed=args.seed,
        corpus_meta=meta,
        reps=args.reps,
        adjudication=load_adjudication(args.corpus_dir / "adjudication.jsonl"),
        dump_outputs=args.dump_outputs,
        injection_samples=REPO_CORPUS.parent / "tests" / "fixtures" / "injection_samples.json",
    )
    write_metrics(metrics, args.out)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
