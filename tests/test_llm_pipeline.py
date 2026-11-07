import itertools
import json

import pytest

from cti_guard.application.guarded_extraction import DefenseConfig, GuardedExtractor
from cti_guard.domain.entities import IOCType
from cti_guard.infrastructure.adapters.llm.llm_extractor import LLMIOCExtractor
from cti_guard.infrastructure.adapters.llm.proposer import (
    LLMProposer,
    chunk_text,
    parse_json,
    seeded_nonce_fn,
)
from fakes import FakeLLM, broken, indicators, severity


def scripted(extract_out: str, sev: str = "high"):
    def handler(system, user, schema):
        return severity(sev) if "severity" in schema.get("properties", {}) else extract_out

    return FakeLLM(handler)


def test_chunk_text_covers_everything_and_respects_size():
    text = "\n".join(f"line {i:04d} " + "x" * 40 for i in range(300))
    chunks = chunk_text(text, size=1000, overlap=100)
    assert len(chunks) > 5
    assert all(len(c) <= 1000 for _o, c in chunks)
    assert chunks[0][0] == 0
    assert chunks[-1][0] + len(chunks[-1][1]) == len(text)
    for (o1, c1), (o2, _c2) in itertools.pairwise(chunks):
        assert o2 <= o1 + len(c1)  # overlap, never a gap


def test_chunk_text_short_input_is_single_chunk():
    assert chunk_text("short") == [(0, "short")]


def test_parse_json_tolerates_markdown_fence_only():
    assert parse_json('```json\n{"a": 1}\n```') == {"a": 1}
    with pytest.raises(json.JSONDecodeError):
        parse_json("not json")


def test_proposer_parses_schema_and_maps_types(report_text):
    client = scripted(indicators(("ip", "203.0.113.45"), ("cve", "CVE-2099-1111")))
    res = LLMProposer(client).propose(report_text("r1"))
    assert {(c.ioc_type, c.value) for c in res.candidates} == {
        (IOCType.IP_ADDRESS, "203.0.113.45"),
        (IOCType.CVE_ID, "CVE-2099-1111"),
    }
    assert res.llm_severity == "high"
    assert not res.errors


def test_proposer_fails_closed_on_schema_violation_and_llm_errors():
    bad = scripted(json.dumps({"iocs": [{"type": "ip", "value": "1.1.1.1"}]}))
    res = LLMProposer(bad).propose("text")
    assert res.candidates == []
    assert any(e.startswith("extract") for e in res.errors)

    res = LLMProposer(FakeLLM(broken)).propose("text")
    assert res.candidates == [] and res.llm_severity is None and len(res.errors) == 2


def test_proposer_rejects_unknown_type_and_extra_fields():
    res = LLMProposer(scripted(indicators(("email", "a@b.com")))).propose("text")
    assert res.candidates == [] and res.errors


def test_hardened_prompt_wraps_document_and_passes_token_limit(report_text):
    client = scripted(indicators())
    LLMProposer(client, hardened=True, max_output_tokens=777).propose(report_text("r1"))
    system, user, _schema, max_tokens = client.calls[0]
    assert max_tokens == 777
    assert "<untrusted_document_" in user and "ˆ" in user
    assert "{NONCE}" not in system and "untrusted_document_" in system


def test_naive_prompt_does_not_spotlight(report_text):
    client = scripted(indicators())
    LLMProposer(client, hardened=False).propose(report_text("r1"))
    assert "untrusted_document" not in client.calls[0][1]


def test_seeded_nonce_is_deterministic_but_secret_dependent():
    a, b = seeded_nonce_fn("k1"), seeded_nonce_fn("k2")
    assert a("x") == a("x") != b("x")


def test_guarded_extractor_drops_hallucinated_and_invalid_indicators(report_text, report_gold):
    text = report_text("r1")
    client = scripted(
        indicators(
            ("ip", "203.0.113.45"),  # real
            ("ip", "198.51.100.99"),  # hallucinated: not in the document
            ("domain", "update-check.example.net"),  # real, defanged in the source
            ("domain", "payload.exe"),  # invalid syntax
            ("sha256", "ab" * 32),  # valid but absent
        )
    )
    res = GuardedExtractor(LLMProposer(client)).run(text)
    got = {(a.ioc_type, a.value) for a in res.accepted}
    assert got == {
        (IOCType.IP_ADDRESS, "203.0.113.45"),
        (IOCType.DOMAIN, "update-check.example.net"),
    }
    assert {r.reason for r in res.rejected} == {"not_in_source", "invalid_syntax"}
    for a in res.accepted:  # provenance points at literal characters of the source
        assert text[a.start : a.end].replace("[.]", ".") == a.value


def test_severity_cannot_drop_below_evidence_floor(report_text):
    client = scripted(indicators(("ip", "203.0.113.45")), sev="info")
    res = GuardedExtractor(LLMProposer(client)).run(report_text("r1"))
    assert res.severity == "medium"
    raw = GuardedExtractor(LLMProposer(client), DefenseConfig.none()).run(report_text("r1"))
    assert raw.severity == "info"


def test_zero_width_content_quarantines_before_any_llm_call():
    client = scripted(indicators(("ip", "203.0.113.45")))
    res = GuardedExtractor(LLMProposer(client)).run("C2 203.0.113.45 ​​ hidden")
    assert res.quarantined and not res.accepted and client.calls == []
    assert "invisible_characters" in res.injection_rules


def test_span_veto_blocks_indicator_that_only_appears_inside_flagged_region():
    # A zero-width run flags a region; the attacker-chosen IP lives next to it.
    text = "Report body.\n" + "pad " * 80 + "\u200b\u200b 198.51.100.77 \u200b\n" + "pad " * 80
    client = scripted(indicators(("ip", "198.51.100.77")))
    cfg = DefenseConfig(verifier=True, span_veto=True, quarantine=False, severity_floor=True)
    res = GuardedExtractor(LLMProposer(client), cfg).run(text)
    assert not res.accepted
    assert res.rejected[0].reason == "only_in_injection_span"
    no_veto = DefenseConfig(verifier=True, span_veto=False, quarantine=False, severity_floor=True)
    assert GuardedExtractor(LLMProposer(client), no_veto).run(text).accepted


def test_port_adapter_returns_verified_iocs_with_provenance(report_text):
    client = scripted(
        indicators(("ip", "203.0.113.45"), ("md5", "5d41402abc4b2a76b9719d911017c592"))
    )
    ex = LLMIOCExtractor(client)
    iocs = ex.extract_from_text(report_text("r1"), "doc-1")
    assert all(i.verified and i.start is not None and i.extractor == "llm+verifier" for i in iocs)
    assert ex.extract_ip_addresses(report_text("r1")) == ["203.0.113.45"]
    assert ex.extract_file_hashes(report_text("r1"))["md5"] == ["5d41402abc4b2a76b9719d911017c592"]
    assert ex.extract_emails("x") == [] and ex.extract_domains("x") == []
    assert ex.extract_urls("x") == [] and ex.extract_cve_ids("x") == []
    assert ex.last_result is not None


def test_llm_ioc_absent_from_source_produces_no_alert(report_text):
    """End-to-end gate: a hallucinated IOC never reaches AlertService as alert-worthy."""
    from cti_guard.domain.services import AlertService

    client = scripted(indicators(("ip", "198.51.100.99"), ("ip", "203.0.113.45")))
    iocs = LLMIOCExtractor(client).extract_from_text(report_text("r1"), "doc-1")
    assert [i.value for i in iocs] == ["203.0.113.45"]  # hallucinated one was dropped
    svc = AlertService()
    for ioc in iocs:
        ioc.confidence = type(ioc.confidence).HIGH
    assert [svc.should_alert_for_ioc(i) for i in iocs] == [True]
    # Even if a caller forged an unverified entity for the hallucinated value, no alert.
    forged = iocs[0].__class__(
        "198.51.100.99", iocs[0].ioc_type, iocs[0].confidence, "doc-1", iocs[0].extracted_at
    )
    assert not forged.verified and not svc.should_alert_for_ioc(forged)
