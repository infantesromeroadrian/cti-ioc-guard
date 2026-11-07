"""API models (DTOs) for request/response serialization."""

from cti_guard.infrastructure.api.models.alert import (
    AlertAcknowledgeRequest,
    AlertFalsePositiveRequest,
    AlertFilterParams,
    AlertResolveRequest,
    AlertResponse,
    AlertStatsResponse,
)
from cti_guard.infrastructure.api.models.common import (
    ErrorResponse,
    PaginatedResponse,
    PaginationParams,
    StatsResponse,
    SuccessResponse,
)
from cti_guard.infrastructure.api.models.cve import (
    CVECreateRequest,
    CVEFilterParams,
    CVEListResponse,
    CVEResponse,
    CVESummaryResponse,
    CVSSResponse,
)
from cti_guard.infrastructure.api.models.ioc import (
    IOCCreateRequest,
    IOCFilterParams,
    IOCResponse,
    IOCStatsResponse,
)
from cti_guard.infrastructure.api.models.threat_intel import (
    ThreatIntelFilterParams,
    ThreatIntelResponse,
    ThreatIntelStatsResponse,
)

__all__ = [
    "AlertAcknowledgeRequest",
    "AlertFalsePositiveRequest",
    "AlertFilterParams",
    "AlertResolveRequest",
    # Alert
    "AlertResponse",
    "AlertStatsResponse",
    "CVECreateRequest",
    "CVEFilterParams",
    "CVEListResponse",
    # CVE
    "CVEResponse",
    "CVESummaryResponse",
    "CVSSResponse",
    "ErrorResponse",
    "IOCCreateRequest",
    "IOCFilterParams",
    # IOC
    "IOCResponse",
    "IOCStatsResponse",
    "PaginatedResponse",
    # Common
    "PaginationParams",
    "StatsResponse",
    "SuccessResponse",
    "ThreatIntelFilterParams",
    # ThreatIntel
    "ThreatIntelResponse",
    "ThreatIntelStatsResponse",
]
