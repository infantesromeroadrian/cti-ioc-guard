"""Render the README metrics block from metrics.json (so no figure is typed by hand)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

START, END = "<!-- metrics:start -->", "<!-- metrics:end -->"
LABELS = {
    "regex": "Regex (baseline original)",
    "regex_refang": "Regex + refang (baseline reforzado)",
    "llm_d0_naive": "LLM, prompt ingenuo, sin verificar",
    "llm_d1_spotlight": "LLM + spotlighting, sin verificar",
    "llm_d2_verifier": "LLM + verificador determinista",
    "llm_d3_span_veto": "LLM + verificador + veto por tramo de inyección",
    "llm_d4_quarantine": "LLM + todo lo anterior + cuarentena (defensa completa)",
}


def _pct(x: float | None) -> str:
    return "n/d" if x is None else f"{100 * x:.1f}%"


def _ci(rate: float | None, ci: list[float] | None) -> str:
    if rate is None:
        return "n/d"
    return f"{_pct(rate)} [{_pct(ci[0])}, {_pct(ci[1])}]" if ci else _pct(rate)


def _rate(block: dict[str, Any] | None) -> str:
    if not block or block.get("rate") is None:
        return "n/d"
    return f"{_pct(block['rate'])} [{_pct(block['ci95'][0])}, {_pct(block['ci95'][1])}] (n={block['n']})"


def render(m: dict[str, Any]) -> str:
    meta = m["meta"]
    model = meta["model"]
    out = []
    model_txt = (
        "sin LLM (solo baselines)"
        if model is None
        else f"`{model['name']}` (digest `{model['digest'] or 'n/d'}`, servidor {model['provider']} {model['server_version'] or 'n/d'})"
    )
    out.append(
        f"Generado el {meta['generated_at']} · modelo: {model_txt} · "
        f"{meta['corpus'].get('reports', '?')} informes, {meta['corpus'].get('gold_iocs', '?')} IOC de referencia · "
        f"robustez: {meta['robust_reports']} informes, {meta['variants']} variantes inyectadas · semilla {meta['seed']}.\n"
    )
    out.append("#### Calidad de extracción (micro-agregado, IC 95% de Wilson)\n")
    out.append(
        "| Sistema | Precisión estricta (vs STIX) | Precisión adjudicada | Recall (vs STIX) | F1 estricto (IC bootstrap) | Doble uso listado | Informes en cuarentena |"
    )
    out.append("|---|---|---|---|---|---|---|")
    for name, label in LABELS.items():
        q = m["quality"].get(name)
        if not q:
            continue
        mi = q["micro"]
        f1ci = mi.get("f1_bootstrap_ci95")
        out.append(
            f"| {label} | {_ci(mi['precision'], mi['precision_ci95'])} "
            f"| {_ci(mi.get('precision_adjudicated'), mi.get('precision_adjudicated_ci95'))} "
            f"| {_ci(mi['recall'], mi['recall_ci95'])} | {_ci(mi['f1'], f1ci)} "
            f"| {mi.get('dual_use_listed', 'n/d')} | {q['quarantined_reports']} |"
        )
    out.append("\n#### Calidad por tipo de IOC (precisión / recall)\n")
    names = [n for n in LABELS if n in m["quality"]]
    out.append("| Tipo | " + " | ".join(LABELS[n].split(" (")[0] for n in names) + " |")
    out.append("|---|" + "---|" * len(names))
    for t in ("ip", "domain", "url", "md5", "sha1", "sha256", "cve"):
        cells = []
        for n in names:
            b = m["quality"][n]["per_type"][t]
            cells.append(
                f"{_pct(b['precision'])} / {_pct(b['recall'])} (TP {b['tp']}, FP {b['fp']}, FN {b['fn']})"
            )
        out.append(f"| {t} | " + " | ".join(cells) + " |")
    rob = m["robustness"]
    llm_names = [n for n in LABELS if n in rob]
    out.append(
        "\n#### Robustez frente a inyección indirecta: tasa de éxito del ataque (menor es mejor)\n"
    )
    out.append(
        "| Sistema | IOC falso reportado | IOC reales omitidos (≥50% perdido) | Severidad rebajada | Severidad a low/info |"
    )
    out.append("|---|---|---|---|---|")
    for n in llm_names:
        r = rob[n]
        sev = r.get("downgrade_severity", {})
        out.append(
            f"| {LABELS[n]} | {_rate(r['fake_ioc']['asr'])} | {_rate(r['omit_iocs']['asr'])} "
            f"| {_rate(sev.get('lower_than_clean'))} | {_rate(sev.get('to_low_or_info_from_medium_plus'))} |"
        )
    q = rob.get("_quarantine")
    qi = rob.get("llm_d4_quarantine", {}).get("omit_iocs", {}).get("quarantined_instead")
    if qi:
        out.append(
            f"\nEn omisión de IOC, D4 deja en cuarentena {_rate(qi)} de los casos aplicables: el documento "
            "queda marcado para revisión (coste de disponibilidad), no es una pérdida silenciosa, y por eso "
            "no se cuenta como éxito del ataque."
        )
    q = rob.get("_quarantine")
    if q and q["flagged_variants"]["n"]:
        out.append(
            f"\nCuarentena: marca {_rate(q['flagged_variants'])} de las variantes inyectadas y "
            f"{_rate(q['false_positive_clean_reports'])} de los informes limpios (falsos positivos)."
        )
        styles = ", ".join(f"{s}: {_rate(v)}" for s, v in q["flagged_by_style"].items())
        out.append(f"\nDetección por estilo de ataque: {styles}.")
    fx = m.get("injection_fixture")
    if fx:
        out.append(
            "\n#### Detector de inyección sobre las muestras etiquetadas (resultado real, no la expectativa del fixture)\n"
        )
        out.append("| Categoría | Detectadas | Total | Marcadas por el autor como no detectables |")
        out.append("|---|---|---|---|")
        for cat, c in fx["positives"].items():
            out.append(f"| {cat} | {c['detected']} | {c['total']} | {c['expected_undetectable']} |")
        n = fx["negatives"]
        out.append(
            f"\nProsa legítima marcada por error: {n['flagged']} de {n['total']} ({', '.join(n['flagged_ids']) or 'ninguna'}). Discrepancias con la expectativa del fixture: {fx['disagreements_with_fixture_expectation']}."
        )
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m cti_guard.eval.report")
    ap.add_argument("--metrics", type=Path, default=Path("metrics.json"))
    ap.add_argument("--readme", type=Path, default=Path("README.md"))
    args = ap.parse_args(argv)
    block = render(json.loads(args.metrics.read_text(encoding="utf-8")))
    readme = args.readme.read_text(encoding="utf-8")
    if START not in readme or END not in readme:
        raise SystemExit(f"markers {START} / {END} not found in {args.readme}")
    head, rest = readme.split(START, 1)
    _old, tail = rest.split(END, 1)
    args.readme.write_text(f"{head}{START}\n{block}{END}{tail}", encoding="utf-8")
    print(f"updated {args.readme}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
