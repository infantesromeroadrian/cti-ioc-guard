"""Domain entities - Pure Python business objects."""

from cti_guard.domain.entities.alert import Alert, AlertSeverity, AlertStatus, AlertType
from cti_guard.domain.entities.cve import CVE, CVSS, CVESeverity
from cti_guard.domain.entities.ioc import IOC, IOCConfidence, IOCType
from cti_guard.domain.entities.threat_intel import ThreatIntel, ThreatSeverity, ThreatType

__all__ = [
    # CVE
    "CVE",
    "CVSS",
    # IOC
    "IOC",
    # Alert
    "Alert",
    "AlertSeverity",
    "AlertStatus",
    "AlertType",
    "CVESeverity",
    "IOCConfidence",
    "IOCType",
    # ThreatIntel
    "ThreatIntel",
    "ThreatSeverity",
    "ThreatType",
]
