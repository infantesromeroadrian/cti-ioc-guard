"""Command line entry point: offline demo, API server and one-off extraction."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cti_guard.application.use_cases.scrape_and_extract import ScrapeAndExtractUseCase
from cti_guard.infrastructure.adapters.extractors import RegexIOCExtractor
from cti_guard.infrastructure.adapters.repositories import SQLiteCVERepository, SQLiteIOCRepository
from cti_guard.infrastructure.adapters.scrapers.fixture_scraper import FixtureCVEScraper
from cti_guard.infrastructure.config.settings import settings


def _build_extractor(kind: str):
    if kind == "regex":
        return RegexIOCExtractor()
    from cti_guard.infrastructure.adapters.llm.clients import build_client
    from cti_guard.infrastructure.adapters.llm.llm_extractor import LLMIOCExtractor

    client = build_client(
        settings.llm_provider,
        settings.llm_model,
        ollama_host=settings.ollama_host,
        ollama_api_key=settings.ollama_api_key.get_secret_value(),
        base_url=settings.llm_base_url,
        api_key=settings.llm_api_key.get_secret_value(),
        timeout=settings.llm_timeout_seconds,
        think="low" if "gpt-oss" in settings.llm_model else None,
    )
    return LLMIOCExtractor(client)


def run_demo(extractor: str = "regex", db_url: str | None = None) -> dict[str, object]:
    """Run scrape -> extract -> persist with recorded fixtures (no network, no keys)."""
    url = db_url or settings.database_url
    use_case = ScrapeAndExtractUseCase(
        cve_scraper=FixtureCVEScraper(),
        ioc_extractor=_build_extractor(extractor),
        cve_repository=SQLiteCVERepository(url),
        ioc_repository=SQLiteIOCRepository(url),
    )
    return use_case.execute(days=7)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cti-guard")
    sub = ap.add_subparsers(dest="cmd", required=True)

    demo = sub.add_parser("demo", help="offline pipeline over recorded fixtures")
    demo.add_argument("--extractor", choices=["regex", "llm"], default="regex")

    serve = sub.add_parser("serve", help="run the REST API")
    serve.add_argument("--demo", action="store_true", help="seed the database from fixtures first")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)

    ext = sub.add_parser("extract", help="extract IOCs from a text file (prints JSON)")
    ext.add_argument("file", type=Path)
    ext.add_argument("--extractor", choices=["regex", "llm"], default="regex")

    args = ap.parse_args(argv)
    if args.cmd == "demo":
        print(json.dumps(run_demo(args.extractor), indent=2, default=str))
    elif args.cmd == "serve":
        import uvicorn

        if args.demo:
            run_demo("regex")
        uvicorn.run("cti_guard.infrastructure.api.main:app", host=args.host, port=args.port)
    else:
        text = args.file.read_text(encoding="utf-8")
        iocs = _build_extractor(args.extractor).extract_from_text(text, args.file.name)
        print(json.dumps([i.to_dict() for i in iocs], indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
