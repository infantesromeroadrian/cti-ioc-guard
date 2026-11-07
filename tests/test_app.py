from fastapi.testclient import TestClient

from cti_guard import cli
from cti_guard.application.guarded_extraction import GuardedExtractor
from cti_guard.infrastructure.adapters.llm.llm_extractor import LLMIOCExtractor
from cti_guard.infrastructure.api.main import app
from cti_guard.infrastructure.config.settings import Settings


def test_demo_pipeline_runs_offline_and_populates_database(tmp_path):
    url = f"sqlite:///{tmp_path}/demo.db"
    stats = cli.run_demo("regex", db_url=url)
    assert stats["cves_scraped"] == 2 and stats["iocs_unique"] >= 5


def test_api_health_and_ioc_listing_after_demo():
    cli.run_demo("regex")  # default DATABASE_URL set by conftest
    client = TestClient(app)
    assert client.get("/health").json()["status"] == "healthy"
    resp = client.get("/api/iocs")
    assert resp.status_code == 200
    body = resp.json()
    items = body.get("items") or body.get("data") or body
    assert items


def test_cli_extract_prints_json(tmp_path, capsys, fixtures_dir):
    path = fixtures_dir / "reports" / "r2.txt"
    assert cli.main(["extract", str(path)]) == 0
    out = capsys.readouterr().out
    assert "198.51.100.23" in out and '"verified": true' in out


def test_cli_demo_command(capsys):
    assert cli.main(["demo"]) == 0
    assert "cves_scraped" in capsys.readouterr().out


def test_build_llm_extractor_from_settings(monkeypatch):
    monkeypatch.setattr("ollama.Client", lambda **_: object())
    assert isinstance(cli._build_extractor("llm"), LLMIOCExtractor)
    assert GuardedExtractor  # imported to keep the public surface under test


def test_settings_secrets_are_not_leaked_in_repr(monkeypatch):
    monkeypatch.setenv("OLLAMA_API_KEY", "super-secret-value")
    s = Settings()
    assert "super-secret-value" not in repr(s) and "super-secret-value" not in str(s.model_dump())
    assert s.ollama_api_key.get_secret_value() == "super-secret-value"


def test_api_read_endpoints_respond_after_demo():
    cli.run_demo("regex")
    client = TestClient(app, follow_redirects=True)
    for path in (
        "/api/cves",
        "/api/cves/stats",
        "/api/cves/recent",
        "/api/cves/critical",
        "/api/iocs",
        "/api/iocs/stats",
        "/api/iocs/recent",
        "/api/iocs/active",
        "/api/threats",
        "/api/threats/stats",
        "/api/threats/recent",
        "/api/alerts",
        "/api/alerts/stats",
        "/api/alerts/active",
    ):
        assert client.get(path).status_code == 200, path
    detail = client.get("/api/cves/CVE-2099-0001")
    assert detail.status_code == 200 and detail.json()["cve_id"] == "CVE-2099-0001"
    assert client.get("/api/cves/CVE-0000-0000").status_code == 404
    iocs = client.get("/api/iocs").json()
    assert iocs["items"] and all(i["verified"] for i in iocs["items"])
