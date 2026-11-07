"""IOCExtractorPort adapter backed by the guarded LLM pipeline."""

from __future__ import annotations

from cti_guard.application.guarded_extraction import (
    DefenseConfig,
    ExtractionResult,
    GuardedExtractor,
)
from cti_guard.domain.entities import IOC, IOCType
from cti_guard.infrastructure.adapters.llm.clients import LLMClient
from cti_guard.infrastructure.adapters.llm.proposer import LLMProposer


class LLMIOCExtractor:
    """Extracts only verified IOCs; quarantined documents yield an empty list.

    The most recent ``ExtractionResult`` (quarantine flag, rejected proposals, severity) is kept
    in ``last_result`` so callers can log or surface it.
    """

    def __init__(self, client: LLMClient, defenses: DefenseConfig | None = None) -> None:
        self._guard = GuardedExtractor(LLMProposer(client, hardened=True), defenses)
        self.last_result: ExtractionResult | None = None

    def extract_from_text(self, text: str, source_document_id: str) -> list[IOC]:
        self.last_result = self._guard.run(text, with_severity=False)
        return self.last_result.to_iocs(source_document_id, self.get_extractor_name(), text)

    def _values(self, text: str, *types: IOCType) -> list[str]:
        return [i.value for i in self.extract_from_text(text, "adhoc") if i.ioc_type in types]

    def extract_ip_addresses(self, text: str) -> list[str]:
        return self._values(text, IOCType.IP_ADDRESS)

    def extract_domains(self, text: str) -> list[str]:
        return self._values(text, IOCType.DOMAIN)

    def extract_urls(self, text: str) -> list[str]:
        return self._values(text, IOCType.URL)

    def extract_file_hashes(self, text: str) -> dict[str, list[str]]:
        iocs = self.extract_from_text(text, "adhoc")
        return {
            "md5": [i.value for i in iocs if i.ioc_type is IOCType.FILE_HASH_MD5],
            "sha1": [i.value for i in iocs if i.ioc_type is IOCType.FILE_HASH_SHA1],
            "sha256": [i.value for i in iocs if i.ioc_type is IOCType.FILE_HASH_SHA256],
        }

    def extract_emails(self, text: str) -> list[str]:
        return []  # not in the LLM allow-list

    def extract_cve_ids(self, text: str) -> list[str]:
        return self._values(text, IOCType.CVE_ID)

    def get_extractor_name(self) -> str:
        return "llm+verifier"
