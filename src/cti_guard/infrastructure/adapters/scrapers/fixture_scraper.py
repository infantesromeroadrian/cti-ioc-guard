"""Offline CVE scraper that replays a recorded NVD API v2.0 response (demo and tests)."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from cti_guard.domain.entities import CVE
from cti_guard.infrastructure.adapters.scrapers.nvd_scraper import NVDScraper

DEMO_NVD = Path(__file__).resolve().parents[3] / "demo_data" / "nvd_sample.json"


class FixtureCVEScraper(NVDScraper):
    """Same parsing as ``NVDScraper`` but reads a JSON file instead of calling the network."""

    def __init__(self, path: Path = DEMO_NVD) -> None:
        super().__init__()
        self.path = path

    def _load(self) -> list[CVE]:
        data = json.loads(self.path.read_text(encoding="utf-8"))
        cves = (self._parse_cve_from_nvd(item) for item in data.get("vulnerabilities", []))
        return [c for c in cves if c is not None]

    def scrape_recent(self, days: int = 7) -> list[CVE]:
        return self._load()

    def scrape_by_date_range(self, start_date: datetime, end_date: datetime) -> list[CVE]:
        return self._load()

    def get_source_name(self) -> str:
        return "NVD (fixture)"
