"""Shared fixtures. Tests never touch the network or need keys."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

# Must be set before cti_guard.infrastructure.config.settings is imported.
_TMP = tempfile.mkdtemp(prefix="cti-guard-tests-")
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP}/test.db"
os.environ["APP_ENV"] = "production"  # JSON logs, no colour noise
for _k in ("OLLAMA_API_KEY", "NVD_API_KEY", "OTX_API_KEY", "LLM_API_KEY"):
    os.environ.pop(_k, None)

import json  # noqa: E402

import pytest  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def fixtures_dir() -> Path:
    return FIXTURES


@pytest.fixture
def report_text(fixtures_dir: Path):
    def load(name: str) -> str:
        return (fixtures_dir / "reports" / f"{name}.txt").read_text(encoding="utf-8")

    return load


@pytest.fixture
def report_gold(fixtures_dir: Path) -> dict[str, list[dict]]:
    return json.loads((fixtures_dir / "reports" / "gold.json").read_text())
