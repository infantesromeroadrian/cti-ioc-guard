"""API routes for all endpoints."""

from cti_guard.infrastructure.api.routes import alerts, cves, iocs, threats

__all__ = ["alerts", "cves", "iocs", "threats"]
