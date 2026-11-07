import json
import re

import pytest

from cti_guard.eval import stats
from cti_guard.eval.attacks import Template, build_variants, target_window
from cti_guard.eval.corpus import CorpusError, load_corpus, sha256_text
from cti_guard.eval.runner import quality_table, run_all, write_metrics
from cti_guard.eval.systems import Output
from fakes import FakeLLM, indicators, severity

FAKE_TEMPLATES = [
    Template(f"{a}-{i}", a, "direct", f"[[plumbing test payload {{FAKE_IP}} {a} {i}]]")
    for a in ("fake_ioc", "omit_iocs", "downgrade_severity")
    for i in range(3)
]
IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def regex_llm():
    """A 'model' that proposes every IPv4 it sees (good enough to exercise the harness)."""

    def handler(system, user, schema):
        if "severity" in schema.get("properties", {}):
            return severity("high")
        return indicators(*[("ip", m) for m in IP.findall(user)])

    return FakeLLM(handler)


def make_corpus(tmp_path, report_text, report_gold):
    repo, data = tmp_path / "corpus", tmp_path / "data"
    (data / "corpus" / "texts").mkdir(parents=True)
    repo.mkdir()
    manifest, gold = [], []
    for rid in ("r1", "r2"):
        text = report_text(rid)
        (data / "corpus" / "texts" / f"{rid}.txt").write_text(text, encoding="utf-8")
        manifest.append({"id": rid, "text_sha256": sha256_text(text)})
        gold.append({"id": rid, "iocs": report_gold[rid]})
    (repo / "manifest.jsonl").write_text("\n".join(json.dumps(m) for m in manifest))
    (repo / "gold.jsonl").write_text("\n".join(json.dumps(g) for g in gold))
    return repo, data


def test_wilson_interval_matches_known_values():
    lo, hi = stats.wilson(8, 10)
    assert (round(lo, 3), round(hi, 3)) == (0.49, 0.943)
    assert stats.wilson(0, 0) is None
    lo, hi = stats.wilson(0, 20)
    assert lo == 0.0 and 0.1 < hi < 0.2


def test_prf_and_bootstrap():
    assert stats.prf(8, 2, 8)["precision"] == 0.8
    assert stats.prf(0, 0, 0)["f1"] is None
    ci = stats.bootstrap_ci([1, 1, 0, 1, 0, 1, 1, 1], lambda s: sum(s) / len(s), iterations=200)
    assert ci is not None and 0 <= ci[0] <= ci[1] <= 1


def test_load_corpus_verifies_sha(tmp_path, report_text, report_gold):
    repo, data = make_corpus(tmp_path, report_text, report_gold)
    reports = load_corpus(repo, data)
    assert [r.report_id for r in reports] == ["r1", "r2"] and len(reports[0].gold) == 7
    (data / "corpus" / "texts" / "r1.txt").write_text("tampered")
    with pytest.raises(CorpusError, match="sha256"):
        load_corpus(repo, data)
    assert load_corpus(repo, data, strict_sha=False)


def test_build_variants_is_deterministic_and_inserts_payload(tmp_path, report_text, report_gold):
    repo, data = make_corpus(tmp_path, report_text, report_gold)
    reports = load_corpus(repo, data)
    a = build_variants(reports, FAKE_TEMPLATES, per_attack=2, seed=1)
    b = build_variants(reports, FAKE_TEMPLATES, per_attack=2, seed=1)
    assert [v.variant_id for v in a] == [v.variant_id for v in b]
    assert len(a) == 2 * 3 * 2
    for v in a:
        assert v.text[v.inserted[0] : v.inserted[1]].startswith("[[plumbing")
        assert "{FAKE_IP}" not in v.text
    fake = next(v for v in a if v.attack == "fake_ioc")
    assert fake.fakes["ip"] in fake.text
    assert target_window(reports[0], "downgrade_severity")[0] == 0


def test_quality_table_counts_per_type():
    gold = {("ip", "1.1.1.1"), ("ip", "2.2.2.2"), ("cve", "CVE-2099-1111")}
    out = Output({("ip", "1.1.1.1"), ("ip", "3.3.3.3")})
    table = quality_table({"r": (gold, out)})
    assert table["per_type"]["ip"]["tp"] == 1 and table["per_type"]["ip"]["fp"] == 1
    assert table["per_type"]["ip"]["fn"] == 1 and table["per_type"]["cve"]["fn"] == 1
    assert table["micro"]["precision"] == 0.5
    assert table["micro"]["precision_ci95"] is not None


def test_run_all_end_to_end_with_fake_model(tmp_path, report_text, report_gold):
    repo, data = make_corpus(tmp_path, report_text, report_gold)
    reports = load_corpus(repo, data)
    metrics = run_all(
        reports,
        FAKE_TEMPLATES,
        regex_llm(),
        robust_n=2,
        per_attack=1,
        workers=2,
        seed=0,
        corpus_meta={"reports": 2},
    )
    assert set(metrics["quality"]) >= {"regex", "regex_refang", "llm_d0_naive", "llm_d4_quarantine"}
    # refanging helps the regex baseline on defanged indicators
    assert (
        metrics["quality"]["regex_refang"]["micro"]["recall"]
        > metrics["quality"]["regex"]["micro"]["recall"]
    )
    rob = metrics["robustness"]
    assert rob["llm_d1_spotlight"]["fake_ioc"]["asr"]["n"] == 2
    assert "_quarantine" in rob and metrics["meta"]["model"]["name"] == "fake-1"
    out = tmp_path / "metrics.json"
    write_metrics(metrics, out)
    assert json.loads(out.read_text())["meta"]["variants"] == 6


def test_run_all_without_llm_only_reports_baselines(tmp_path, report_text, report_gold):
    repo, data = make_corpus(tmp_path, report_text, report_gold)
    metrics = run_all(
        load_corpus(repo, data),
        FAKE_TEMPLATES,
        None,
        robust_n=2,
        per_attack=1,
        workers=1,
        seed=0,
        corpus_meta={},
    )
    assert set(metrics["quality"]) == {"regex", "regex_refang"} and metrics["meta"]["model"] is None


def test_html_to_text_keeps_main_content_and_table_rows():
    from cti_guard.eval.fetch import html_to_text

    html = (
        "<html><body><nav>menu</nav><main><h1>Title</h1><p>Beacon  to 1.2.3.4</p>"
        "<table><tr><th>IP</th><td>5.6.7.8</td></tr></table><script>x()</script></main>"
        "<footer>f</footer></body></html>"
    )
    text = html_to_text(html)
    assert text == "Title\nBeacon to 1.2.3.4\nIP | 5.6.7.8\n"


def test_report_renders_and_injects_between_markers(tmp_path, report_text, report_gold):
    from cti_guard.eval import report

    repo, data = make_corpus(tmp_path, report_text, report_gold)
    metrics = run_all(
        load_corpus(repo, data),
        FAKE_TEMPLATES,
        regex_llm(),
        robust_n=2,
        per_attack=1,
        workers=1,
        seed=0,
        corpus_meta={"reports": 2, "gold_iocs": 13},
    )
    mp, rp = tmp_path / "m.json", tmp_path / "README.md"
    write_metrics(metrics, mp)
    rp.write_text(f"intro\n{report.START}\nold\n{report.END}\noutro\n")
    assert report.main(["--metrics", str(mp), "--readme", str(rp)]) == 0
    text = rp.read_text()
    assert "old" not in text and text.startswith("intro") and text.endswith("outro\n")
    assert "Regex (baseline original)" in text and "fake-1" in text


def test_stix_reference_extraction():
    from cti_guard.eval.stix import stix_iocs

    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "pattern": "[ipv4-addr:value = '203.0.113.45'] OR [domain-name:value = 'Evil.Example.NET']",
            },
            {
                "type": "indicator",
                "pattern": "[file:hashes.'SHA-256' = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08']",
            },
            {"type": "indicator", "pattern": "[url:value = 'http://a.example.net/x']"},
            {"type": "indicator", "pattern": "[email-addr:value = 'a@b.com']"},
            {"type": "vulnerability", "name": "cve-2099-1111"},
            {"type": "file", "hashes": {"MD5": "5d41402abc4b2a76b9719d911017c592"}},
        ],
    }
    assert stix_iocs(json.dumps(bundle)) == {
        ("ip", "203.0.113.45"),
        ("domain", "evil.example.net"),
        ("sha256", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
        ("url", "http://a.example.net/x"),
        ("cve", "CVE-2099-1111"),
        ("md5", "5d41402abc4b2a76b9719d911017c592"),
    }


def test_repetitions_pool_counts_and_keep_dispersion(tmp_path, report_text, report_gold):
    repo, data = make_corpus(tmp_path, report_text, report_gold)
    m = run_all(
        load_corpus(repo, data),
        FAKE_TEMPLATES,
        regex_llm(),
        robust_n=2,
        per_attack=1,
        workers=1,
        seed=0,
        corpus_meta={},
        reps=3,
    )
    asr = m["robustness"]["llm_d1_spotlight"]["fake_ioc"]["asr"]
    assert asr["n"] == 6 and len(asr["per_rep_rates"]) == 3
    assert m["meta"]["repetitions"] == 3


def test_stix1_xml_reference_extraction():
    from cti_guard.eval.stix import stix1_xml_iocs

    xml = """<stix:STIX_Package xmlns:stix="s" xmlns:cybox="c" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns:AddressObj="a" xmlns:DomainNameObj="d" xmlns:URIObj="u" xmlns:FileObj="f"><cybox:Object>
      <cybox:Properties xsi:type="AddressObj:AddressObjectType" category="ipv4-addr"><AddressObj:Address_Value>203.0.113.45</AddressObj:Address_Value></cybox:Properties>
      <cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType"><DomainNameObj:Value>evil.example.net</DomainNameObj:Value></cybox:Properties>
      <cybox:Properties xsi:type="URIObj:URIObjectType"><URIObj:Value>http://a.example.net/x</URIObj:Value></cybox:Properties>
      <cybox:Properties xsi:type="FileObj:FileObjectType"><FileObj:Hashes><cybox:Hash><cyboxCommon:Type xmlns:cyboxCommon="cc">MD5</cyboxCommon:Type><cyboxCommon:Simple_Hash_Value xmlns:cyboxCommon="cc">5d41402abc4b2a76b9719d911017c592</cyboxCommon:Simple_Hash_Value></cybox:Hash></FileObj:Hashes></cybox:Properties>
      <stixCommon:CVE_ID xmlns:stixCommon="sc">CVE-2099-1111</stixCommon:CVE_ID>
      </cybox:Object></stix:STIX_Package>"""
    assert stix1_xml_iocs(xml) == {
        ("ip", "203.0.113.45"),
        ("domain", "evil.example.net"),
        ("url", "http://a.example.net/x"),
        ("md5", "5d41402abc4b2a76b9719d911017c592"),
        ("cve", "CVE-2099-1111"),
    }


def test_polite_get_backs_off_and_falls_back(monkeypatch):
    import httpx

    from cti_guard.eval import fetch

    sleeps, seen = [], []
    monkeypatch.setattr(fetch.time, "sleep", sleeps.append)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        if "archive" in str(request.url):
            return httpx.Response(429) if seen.count(str(request.url)) < 3 else httpx.Response(404)
        return httpx.Response(200, text="ok")

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        resp = fetch._polite_get(http, ["http://archive/x", "http://live/x"], delay=1.5)
    assert resp is not None and resp.text == "ok"
    assert all(s >= 1.0 for s in sleeps) and max(sleeps) >= 10  # exponential backoff happened
