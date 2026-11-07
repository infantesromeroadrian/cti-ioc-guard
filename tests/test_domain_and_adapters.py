import json
from datetime import datetime

import pytest

from cti_guard.domain.entities import IOC, IOCConfidence, IOCType
from cti_guard.domain.services import AlertService, IOCExtractorService
from cti_guard.infrastructure.adapters.extractors import RegexIOCExtractor
from cti_guard.infrastructure.adapters.repositories import SQLiteIOCRepository
from cti_guard.infrastructure.adapters.scrapers import NVDScraper, OTXScraper
from cti_guard.infrastructure.adapters.scrapers.fixture_scraper import FixtureCVEScraper


def make_ioc(value="203.0.113.45", verified=True, conf=IOCConfidence.HIGH, kind=IOCType.IP_ADDRESS):
    return IOC(value, kind, conf, "doc", datetime(2099, 1, 1), verified=verified, start=0, end=5)


def test_regex_baseline_extracts_literal_matches_with_provenance(report_text):
    text = report_text("r2")
    iocs = RegexIOCExtractor().extract_from_text(text, "d")
    by_type = {i.ioc_type for i in iocs}
    assert {IOCType.IP_ADDRESS, IOCType.URL, IOCType.FILE_HASH_SHA1, IOCType.CVE_ID} <= by_type
    assert all(i.verified and text[i.start : i.end] == i.value for i in iocs)
    assert all(i.extractor == "regex" for i in iocs)


def test_regex_baseline_known_weaknesses_are_documented_by_tests(report_text):
    ex = RegexIOCExtractor()
    # defanged indicators are invisible to the plain regex baseline
    assert "203.0.113.45" in ex.extract_ip_addresses(report_text("r1"))
    assert not any("update-check" in d for d in ex.extract_domains(report_text("r1")))
    # file names are false-positive domains
    assert "payload.exe" in ex.extract_domains(report_text("r2"))
    assert ex.get_extractor_name() == "regex"


def test_regex_helpers():
    ex = RegexIOCExtractor()
    assert ex.extract_cve_ids("cve-2099-0001") == ["CVE-2099-0001"]
    assert ex.extract_emails("mail a.b@example.org now") == ["a.b@example.org"]
    assert ex.extract_urls("see http://a.example.net/x") == ["http://a.example.net/x"]
    assert ex.extract_ip_addresses("127.0.0.1 and 203.0.113.9") == ["203.0.113.9"]
    assert ex.extract_file_hashes("5d41402abc4b2a76b9719d911017c592")["md5"]


def test_alert_service_never_alerts_on_unverified_iocs():
    svc = AlertService()
    assert svc.should_alert_for_ioc(make_ioc(verified=True))
    assert not svc.should_alert_for_ioc(make_ioc(verified=False))
    assert not svc.should_alert_for_ioc(make_ioc(verified=True, conf=IOCConfidence.MEDIUM))


def test_ioc_service_dedup_and_stats():
    svc = IOCExtractorService()
    a, b = make_ioc(conf=IOCConfidence.MEDIUM), make_ioc(conf=IOCConfidence.HIGH)
    out = svc.deduplicate_iocs([a, b])
    assert len(out) == 1 and out[0].confidence is IOCConfidence.HIGH
    assert svc.calculate_ioc_statistics(out)["total"] == 1


def test_sqlite_repo_roundtrips_provenance(tmp_path):
    repo = SQLiteIOCRepository(f"sqlite:///{tmp_path}/t.db")
    repo.save(make_ioc())
    got = repo.find_all()[0] if hasattr(repo, "find_all") else repo.find_recent(10)[0]
    assert (got.verified, got.start, got.end) == (True, 0, 5)


def test_fixture_scraper_parses_recorded_nvd_response():
    cves = FixtureCVEScraper().scrape_recent()
    assert [c.cve_id for c in cves] == ["CVE-2099-0001", "CVE-2099-0002"]
    assert cves[0].is_high_or_critical


class _Resp:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self.payload


class _Session:
    def __init__(self, payload):
        self.payload, self.headers, self.urls = payload, {}, []

    def get(self, url, **kwargs):
        self.urls.append((url, kwargs.get("params")))
        return _Resp(self.payload)


def test_nvd_scraper_by_id_offline(fixtures_dir, monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_: None)
    payload = json.loads((fixtures_dir / "nvd_sample.json").read_text())
    scraper = NVDScraper()
    scraper.session = _Session(payload)
    cve = scraper.scrape_by_id("CVE-2099-0001")
    assert cve is not None and cve.cve_id == "CVE-2099-0001"
    assert scraper.session.urls[0][1] == {"cveId": "CVE-2099-0001"}
    scraper.session = _Session({"vulnerabilities": []})
    assert scraper.scrape_by_id("CVE-2099-9999") is None


def test_nvd_scraper_does_not_leak_key_when_unset():
    assert "apiKey" not in NVDScraper().session.headers


def test_otx_scraper_recent_offline(fixtures_dir, monkeypatch):
    monkeypatch.setattr("time.sleep", lambda *_: None)
    scraper = OTXScraper()
    scraper.session = _Session(json.loads((fixtures_dir / "otx_pulses.json").read_text()))
    threats = scraper.scrape_recent(hours=24)
    assert len(threats) == 1 and threats[0].document_id == "otx-pulse-0001"
    assert threats[0].related_cves == ["CVE-2099-0001"]


@pytest.mark.parametrize("bad", ["", None])
def test_ioc_requires_value(bad):
    with pytest.raises(ValueError):
        IOC(bad or "", IOCType.DOMAIN, IOCConfidence.LOW, "d", datetime.now())
