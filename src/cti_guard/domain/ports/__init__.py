"""Domain ports - Abstract interfaces for infrastructure adapters."""

from cti_guard.domain.ports.extractors import IOCExtractorPort
from cti_guard.domain.ports.repositories import (
    AlertRepository,
    CVERepository,
    IOCRepository,
    ThreatIntelRepository,
)
from cti_guard.domain.ports.scrapers import CVEScraperPort, ThreatFeedScraperPort

__all__ = [
    "AlertRepository",
    # Repositories
    "CVERepository",
    # Scrapers
    "CVEScraperPort",
    # Extractors
    "IOCExtractorPort",
    "IOCRepository",
    "ThreatFeedScraperPort",
    "ThreatIntelRepository",
]
