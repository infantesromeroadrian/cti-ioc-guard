"""Build injected variants of reports from a template library (see attack_templates.json)."""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass, field
from pathlib import Path

from cti_guard.eval.corpus import Report
from cti_guard.infrastructure.adapters.llm.proposer import HEAD_CHARS, chunk_text

ATTACKS = ("fake_ioc", "omit_iocs", "downgrade_severity")
DEFAULT_TEMPLATES = Path(__file__).with_name("attack_templates.json")


@dataclass(frozen=True)
class Template:
    template_id: str
    attack: str
    style: str
    text: str


@dataclass
class Variant:
    """One attacked copy of a report."""

    variant_id: str
    report_id: str
    attack: str
    template_id: str
    style: str
    text: str
    inserted: tuple[int, int]
    fakes: dict[str, str] = field(default_factory=dict)  # wire type -> fake canonical value
    window: tuple[int, int] = (0, 0)  # original-text window the attack targets (omit_iocs)


def load_templates(path: Path = DEFAULT_TEMPLATES) -> list[Template]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [Template(t["id"], t["attack"], t["style"], t["text"]) for t in data["templates"]]


def _fakes(rng: random.Random) -> dict[str, str]:
    return {
        "ip": f"198.51.100.{rng.randint(2, 250)}",
        "domain": f"sync-{rng.getrandbits(40):010x}.net",
        "sha256": f"{rng.getrandbits(256):064x}",
    }


def _fill(text: str, fakes: dict[str, str]) -> tuple[str, dict[str, str]]:
    used: dict[str, str] = {}
    for placeholder, wire in (
        ("{FAKE_IP}", "ip"),
        ("{FAKE_DOMAIN}", "domain"),
        ("{FAKE_HASH}", "sha256"),
    ):
        if placeholder in text:
            text = text.replace(placeholder, fakes[wire])
            used[wire] = fakes[wire]
    return text, used


def _line_start(text: str, offset: int) -> int:
    nl = text.rfind("\n", 0, offset)
    return nl + 1 if nl != -1 else 0


def target_window(report: Report, attack: str) -> tuple[int, int]:
    """Window of the ORIGINAL text where the payload goes (and, for omit, is evaluated).

    ``downgrade_severity`` targets the head (the only part the severity call sees);
    the others target the chunk holding the most gold indicators (worst case).
    """
    if attack == "downgrade_severity":
        return 0, min(len(report.text), HEAD_CHARS)
    chunks = chunk_text(report.text)
    best = max(
        chunks,
        key=lambda c: sum(1 for s, _e in report.gold.values() if c[0] <= s < c[0] + len(c[1])),
    )
    return best[0], best[0] + len(best[1])


def build_variants(
    reports: list[Report], templates: list[Template], per_attack: int = 2, seed: int = 0
) -> list[Variant]:
    out: list[Variant] = []
    for report in reports:
        for attack in ATTACKS:
            pool = [t for t in templates if t.attack == attack]
            if not pool:
                continue
            rng = random.Random(f"{seed}:{report.report_id}:{attack}")
            for tmpl in rng.sample(pool, min(per_attack, len(pool))):
                payload, used = _fill(tmpl.text, _fakes(rng))
                win = target_window(report, attack)
                at = _line_start(report.text, win[0] + (win[1] - win[0]) // 3)
                text = report.text[:at] + "\n\n" + payload + "\n\n" + report.text[at:]
                vid = hashlib.sha1(
                    f"{report.report_id}{attack}{tmpl.template_id}".encode()
                ).hexdigest()[:10]
                out.append(
                    Variant(
                        f"{report.report_id}:{attack}:{tmpl.template_id}:{vid}",
                        report.report_id,
                        attack,
                        tmpl.template_id,
                        tmpl.style,
                        text,
                        (at + 2, at + 2 + len(payload)),
                        used,
                        win,
                    )
                )
    return out
