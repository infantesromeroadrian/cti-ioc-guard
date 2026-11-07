import pytest

from cti_guard.domain.entities import IOCType
from cti_guard.security.verifier import Candidate, canonicalize, verify

SHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


@pytest.mark.parametrize(
    ("ioc_type", "value", "expected"),
    [
        (IOCType.IP_ADDRESS, "203.0.113.45", "203.0.113.45"),
        (IOCType.IP_ADDRESS, "203[.]0[.]113[.]45", "203.0.113.45"),
        (IOCType.IP_ADDRESS, "999.1.1.1", None),
        (IOCType.IP_ADDRESS, "2001:db8::1", "2001:db8::1"),
        (IOCType.DOMAIN, "Evil-Domain[.]Example.NET", "evil-domain.example.net"),
        (IOCType.DOMAIN, "payload.exe", None),
        (IOCType.DOMAIN, "localhost", None),
        (IOCType.DOMAIN, "-bad-.example.com", None),
        (IOCType.URL, "hxxps://a[.]example[.]net/x?y=1", "https://a.example.net/x?y=1"),
        (IOCType.URL, "javascript:alert(1)", None),
        (IOCType.URL, "http://exa mple.com", None),
        (IOCType.FILE_HASH_SHA256, SHA256.upper(), SHA256),
        (IOCType.FILE_HASH_SHA256, SHA256[:-1], None),
        (IOCType.FILE_HASH_MD5, "0" * 32, None),
        (IOCType.CVE_ID, "cve-2024-12345", "CVE-2024-12345"),
        (IOCType.CVE_ID, "CVE-24-1", None),
        (IOCType.EMAIL, "a@b.com", None),
    ],
)
def test_canonicalize(ioc_type, value, expected):
    assert canonicalize(ioc_type, value) == expected


def test_accepts_present_value_with_offsets_into_original_text():
    text = "beacon to 1[.]2[.]3[.]4 daily"
    acc, rej = verify([Candidate(IOCType.IP_ADDRESS, "1.2.3.4")], text)
    assert not rej
    assert text[acc[0].start : acc[0].end] == "1[.]2[.]3[.]4"


def test_rejects_value_not_literally_in_source():
    acc, rej = verify([Candidate(IOCType.IP_ADDRESS, "198.51.100.9")], "only 203.0.113.45 here")
    assert not acc
    assert rej[0].reason == "not_in_source"


def test_rejects_invalid_syntax_and_disallowed_type():
    acc, rej = verify(
        [Candidate(IOCType.IP_ADDRESS, "300.1.1.1"), Candidate(IOCType.EMAIL, "a@b.com")],
        "300.1.1.1 a@b.com",
    )
    assert not acc
    assert {r.reason for r in rej} == {"invalid_syntax", "type_not_allowed"}


def test_does_not_match_inside_longer_tokens():
    text = "see notevil.com and sub.evil.com and 11.2.3.45"
    acc, rej = verify(
        [
            Candidate(IOCType.DOMAIN, "evil.com"),
            Candidate(IOCType.IP_ADDRESS, "1.2.3.4"),
        ],
        text,
    )
    assert not acc
    assert all(r.reason == "not_in_source" for r in rej)


def test_hash_inside_longer_hex_string_is_not_a_match():
    acc, _ = verify([Candidate(IOCType.FILE_HASH_MD5, "a" * 31 + "b")], "x" + "a" * 31 + "bc y")
    assert not acc


def test_span_veto_rejects_values_only_inside_blocked_span():
    text = "benign intro. injected zone 198.51.100.7 end."
    start = text.index("198")
    acc, rej = verify(
        [Candidate(IOCType.IP_ADDRESS, "198.51.100.7")], text, [(start - 5, start + 20)]
    )
    assert not acc
    assert rej[0].reason == "only_in_injection_span"


def test_span_veto_keeps_value_that_also_appears_outside_span():
    text = "203.0.113.45 is C2. zone: 203.0.113.45"
    acc, _ = verify([Candidate(IOCType.IP_ADDRESS, "203.0.113.45")], text, [(20, len(text))])
    assert acc[0].start == 0


def test_deduplicates_candidates_after_canonicalisation():
    acc, _ = verify(
        [
            Candidate(IOCType.DOMAIN, "EVIL.example.net"),
            Candidate(IOCType.DOMAIN, "evil.example.net"),
        ],
        "evil.example.net",
    )
    assert len(acc) == 1


def test_hash_fragments_split_by_table_layout_are_rejected():
    h1, h2 = "b04b97e7431925097b3ca4841b894139", "7b0b88796da512986327ff66426544ca"
    text = f"SHA-256: | {h1} {h2} |"
    acc, rej = verify(
        [Candidate(IOCType.FILE_HASH_MD5, h1), Candidate(IOCType.FILE_HASH_MD5, h2)], text
    )
    assert not acc and {r.reason for r in rej} == {"not_in_source"}
    # the whole SHA-256 is not literally present either (it is split), so it is not accepted
    acc, _ = verify([Candidate(IOCType.FILE_HASH_SHA256, h1 + h2)], text)
    assert not acc


def test_md5_lists_one_per_line_are_not_fragments():
    a, b = "a" * 31 + "1", "b" * 31 + "2"
    acc, _ = verify(
        [Candidate(IOCType.FILE_HASH_MD5, a), Candidate(IOCType.FILE_HASH_MD5, b)],
        f"MD5\n{a}\n{b}\n",
    )
    assert len(acc) == 2
    # without newline-only separation but with a SHA-256 label the join is a fragment
    h = "c" * 32
    acc, _ = verify([Candidate(IOCType.FILE_HASH_MD5, h)], f"SHA-256 hash:\n{h}\n{h}")
    assert not acc


def test_malformed_defang_in_source_does_not_invent_an_ip():
    from cti_guard.security.refang import refang

    text = "hosts 194.33.40[.]103 and 194.33.40[.1]64 listed"
    assert refang(text).text == "hosts 194.33.40.103 and 194.33.40[.1]64 listed"
    acc, rej = verify(
        [
            Candidate(IOCType.IP_ADDRESS, "194.33.40.164"),
            Candidate(IOCType.IP_ADDRESS, "194.33.40.103"),
        ],
        text,
    )
    assert [a.value for a in acc] == ["194.33.40.103"]
    assert rej[0].reason == "not_in_source"
