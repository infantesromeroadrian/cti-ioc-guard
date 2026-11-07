"""Pydantic schemas for the structured LLM output (also sent as the JSON schema constraint)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from cti_guard.domain.entities import IOCType

WireType = Literal["ip", "domain", "url", "md5", "sha1", "sha256", "cve"]

WIRE_TO_IOC_TYPE: dict[str, IOCType] = {
    "ip": IOCType.IP_ADDRESS,
    "domain": IOCType.DOMAIN,
    "url": IOCType.URL,
    "md5": IOCType.FILE_HASH_MD5,
    "sha1": IOCType.FILE_HASH_SHA1,
    "sha256": IOCType.FILE_HASH_SHA256,
    "cve": IOCType.CVE_ID,
}
Severity = Literal["info", "low", "medium", "high", "critical"]


class ProposedIndicator(BaseModel):
    """One indicator proposed by the model (untrusted until verified)."""

    model_config = ConfigDict(extra="forbid")

    type: WireType
    value: str = Field(min_length=1, max_length=2048)


class ExtractionOutput(BaseModel):
    """Output of the extraction call for one chunk."""

    model_config = ConfigDict(extra="forbid")

    indicators: list[ProposedIndicator] = Field(default_factory=list, max_length=500)


class SeverityOutput(BaseModel):
    """Output of the severity call."""

    model_config = ConfigDict(extra="forbid")

    severity: Severity
    rationale: str = Field(default="", max_length=400)
