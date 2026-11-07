"""Scraper adapters for external data sources."""

from cti_guard.infrastructure.adapters.scrapers.nvd_scraper import NVDScraper
from cti_guard.infrastructure.adapters.scrapers.otx_scraper import OTXScraper

__all__ = [
    "NVDScraper",
    "OTXScraper",
]
