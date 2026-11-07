from cti_guard.security.refang import refang, refang_value


def test_refang_common_defanging_patterns():
    rt = refang("hxxps://evil[.]example(.)com/a and 1[.]2[.]3[.]4 or user[at]host[.]org")
    assert rt.text == "https://evil.example.com/a and 1.2.3.4 or user@host.org"


def test_original_span_points_to_literal_defanged_chars():
    text = "C2 at 1[.]2[.]3[.]4 now"
    rt = refang(text)
    i = rt.text.index("1.2.3.4")
    start, end = rt.original_span(i, i + len("1.2.3.4"))
    assert text[start:end] == "1[.]2[.]3[.]4"


def test_plain_text_is_unchanged_and_offsets_identity():
    text = "nothing to refang here: example.net"
    rt = refang(text)
    assert rt.text == text
    assert rt.original_span(0, 7) == (0, 7)


def test_hxxp_only_rewritten_before_scheme_separator():
    assert refang_value("hxxp://a.b") == "http://a.b"
    assert refang_value("hxxpress is a word") == "hxxpress is a word"


def test_colon_and_scheme_separator_defanging_maps_to_original():
    text = "go to hxxps[:]//evil[.]example[.]net/p now; also hxxp[://]a[.]example[.]org"
    rt = refang(text)
    assert "https://evil.example.net/p" in rt.text and "http://a.example.org" in rt.text
    i = rt.text.index("https://evil.example.net/p")
    s, e = rt.original_span(i, i + len("https://evil.example.net/p"))
    assert text[s:e] == "hxxps[:]//evil[.]example[.]net/p"
