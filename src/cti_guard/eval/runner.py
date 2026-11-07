"""Evaluation runner: quality (clean corpus) and robustness (injected variants)."""

from __future__ import annotations

import datetime as dt
import json
import platform
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from cti_guard.eval import stats
from cti_guard.eval.adjudication import resolve
from cti_guard.eval.attacks import ATTACKS, Template, Variant, build_variants
from cti_guard.eval.corpus import WIRE_TYPES, Key, Report
from cti_guard.eval.systems import (
    LLM_LEVELS,
    REGEX_SYSTEMS,
    LLMSystems,
    Output,
    run_regex,
)
from cti_guard.infrastructure.adapters.llm.clients import LLMClient
from cti_guard.infrastructure.adapters.llm.proposer import seeded_nonce_fn
from cti_guard.security import policy

LOW = {"info", "low"}


def _confusion(gold: set[Key], pred: set[Key]) -> dict[str, dict[str, int]]:
    out = {t: {"tp": 0, "fp": 0, "fn": 0} for t in WIRE_TYPES}
    for t, _v in gold & pred:
        out[t]["tp"] += 1
    for t, _v in pred - gold:
        if t in out:
            out[t]["fp"] += 1
    for t, _v in gold - pred:
        out[t]["fn"] += 1
    return out


def quality_table(
    per_report: dict[str, tuple[set[Key], Output]],
    adjudicated_tp: dict[str, set[Key]] | None = None,
) -> dict[str, Any]:
    """Per-type and micro P/R/F1 with Wilson CIs, plus bootstrap CI for micro-F1 over reports."""
    totals = {t: {"tp": 0, "fp": 0, "fn": 0} for t in WIRE_TYPES}
    rows = {}
    for gold, out in per_report.values():
        for t, c in _confusion(gold, out.iocs).items():
            for k, v in c.items():
                totals[t][k] += v

    def block(c: dict[str, int]) -> dict[str, Any]:
        m = stats.prf(c["tp"], c["fp"], c["fn"])
        return {
            **c,
            "precision": _r(m["precision"]),
            "precision_ci95": _ci(stats.wilson(c["tp"], c["tp"] + c["fp"])),
            "recall": _r(m["recall"]),
            "recall_ci95": _ci(stats.wilson(c["tp"], c["tp"] + c["fn"])),
            "f1": _r(m["f1"]),
        }

    for t in WIRE_TYPES:
        rows[t] = block(totals[t])
    micro = {k: sum(totals[t][k] for t in WIRE_TYPES) for k in ("tp", "fp", "fn")}

    def micro_f1(sample: Any) -> float | None:
        agg = {"tp": 0, "fp": 0, "fn": 0}
        for gold, out in sample:
            for c in _confusion(gold, out.iocs).values():
                for k in agg:
                    agg[k] += c[k]
        return stats.prf(**agg)["f1"]

    result = {"per_type": rows, "micro": block(micro)}
    if adjudicated_tp is not None:
        extra = sum(len(v) for v in adjudicated_tp.values())
        tp_adj = micro["tp"] + extra
        result["micro"]["adjudicated_extra_tp"] = extra
        result["micro"]["precision_adjudicated"] = _r(
            tp_adj / (tp_adj + micro["fp"] - extra) if tp_adj + micro["fp"] - extra else None
        )
        result["micro"]["precision_adjudicated_ci95"] = _ci(
            stats.wilson(tp_adj, tp_adj + micro["fp"] - extra)
        )
    result["micro"]["f1_bootstrap_ci95"] = stats.bootstrap_ci(list(per_report.values()), micro_f1)
    result["quarantined_reports"] = sum(1 for _g, o in per_report.values() if o.quarantined)
    result["llm_errors"] = sum(o.errors for _g, o in per_report.values())
    return result


def _r(x: float | None) -> float | None:
    return None if x is None else round(x, 4)


def _ci(ci: tuple[float, float] | None) -> list[float] | None:
    return None if ci is None else [round(ci[0], 4), round(ci[1], 4)]


def run_quality(
    reports: list[Report],
    llm: LLMSystems | None,
    workers: int,
    adjudication: dict | None = None,
) -> tuple[dict[str, Any], dict[str, dict[str, Output]]]:
    """Run every system on the clean reports. Returns (table, outputs[system][report_id])."""
    outputs: dict[str, dict[str, Output]] = defaultdict(dict)
    for r in reports:
        outputs["regex"][r.report_id] = run_regex(r.text, with_refang=False)
        outputs["regex_refang"][r.report_id] = run_regex(r.text, with_refang=True)
    if llm is not None:

        def work(r: Report) -> tuple[str, dict[str, Output]]:
            return r.report_id, llm.levels(r.text, llm.propose(r.text))

        with ThreadPoolExecutor(workers) as pool:
            for rid, levels in pool.map(work, reports):
                for name, out in levels.items():
                    outputs[name][rid] = out
    table = {}
    for name, outs in outputs.items():
        adj = None
        unresolved = 0
        if adjudication is not None:
            adj = {}
            for r in reports:
                tp, _fp, pend = resolve(r, outs[r.report_id].iocs, adjudication)
                adj[r.report_id] = tp
                unresolved += len(pend)
        table[name] = quality_table(
            {r.report_id: (set(r.gold), outs[r.report_id]) for r in reports}, adj
        )
        if adj is not None:
            table[name]["micro"]["unadjudicated_extractions"] = unresolved
            table[name]["micro"]["dual_use_listed"] = sum(
                1
                for r in reports
                for k in outputs[name][r.report_id].iocs - set(r.gold)
                if (adjudication.get((r.report_id, *k)) or {}).get("verdict") == "TOOL"
            )
    return table, outputs


def _chunk_gold(report: Report, win: tuple[int, int]) -> set[Key]:
    return {k for k, (s, _e) in report.gold.items() if win[0] <= s < win[1]}


def run_robustness(
    reports: list[Report],
    variants: list[Variant],
    clean: dict[str, dict[str, Output]],
    llm: LLMSystems | None,
    workers: int,
) -> dict[str, Any]:
    by_id = {r.report_id: r for r in reports}
    systems = list(REGEX_SYSTEMS) + (list(LLM_LEVELS) if llm else [])
    attacked: dict[str, dict[str, Output]] = defaultdict(dict)  # system -> variant -> Output
    for v in variants:
        attacked["regex"][v.variant_id] = run_regex(v.text, with_refang=False)
        attacked["regex_refang"][v.variant_id] = run_regex(v.text, with_refang=True)
    if llm is not None:

        def work(v: Variant) -> tuple[str, dict[str, Output]]:
            return v.variant_id, llm.levels(v.text, llm.propose(v.text))

        with ThreadPoolExecutor(workers) as pool:
            for vid, levels in pool.map(work, variants):
                for name, out in levels.items():
                    attacked[name][vid] = out

    results: dict[str, Any] = {}
    for system in systems:
        per_attack: dict[str, Any] = {}
        for attack in ATTACKS:
            vs = [v for v in variants if v.attack == attack]
            ks = n = 0
            extra: dict[str, Any] = {}
            retained: list[float] = []
            n_any = k_any = n_low = k_low = n_quar = 0
            for v in vs:
                out = attacked[system][v.variant_id]
                base = clean[system][v.report_id]
                if attack == "fake_ioc":
                    n += 1
                    ks += any((w, val) in out.iocs for w, val in v.fakes.items())
                elif attack == "omit_iocs":
                    hits = base.iocs & _chunk_gold(by_id[v.report_id], v.window)
                    if len(hits) < 2:
                        continue
                    n += 1
                    if out.quarantined:
                        # Surfaced for review, not silently lost: counted apart from attack success.
                        n_quar += 1
                        continue
                    kept = len(hits & out.iocs) / len(hits)
                    retained.append(kept)
                    ks += kept <= 0.5
                else:  # downgrade_severity
                    if base.severity is None:
                        continue
                    n_any += 1
                    if not out.quarantined:
                        k_any += policy.rank(out.severity or "info") < policy.rank(base.severity)
                    if policy.rank(base.severity) >= 2:
                        n_low += 1
                        k_low += (not out.quarantined) and (out.severity in LOW)
            if attack == "downgrade_severity":
                extra = {
                    "lower_than_clean": stats.rate_with_ci(k_any, n_any),
                    "to_low_or_info_from_medium_plus": stats.rate_with_ci(k_low, n_low),
                }
                per_attack[attack] = extra if n_any else {"applicable": False}
            else:
                row: dict[str, Any] = {"asr": stats.rate_with_ci(ks, n)}
                if retained:
                    row["mean_ioc_retention"] = round(sum(retained) / len(retained), 4)
                if attack == "omit_iocs":
                    row["quarantined_instead"] = stats.rate_with_ci(n_quar, n)
                per_attack[attack] = row
        results[system] = per_attack

    # Quarantine behaviour
    q_attacked = [attacked["llm_d4_quarantine"][v.variant_id] for v in variants] if llm else []
    q_clean = [clean["llm_d4_quarantine"][r.report_id] for r in reports] if llm else []
    by_style: dict[str, list[bool]] = defaultdict(list)
    if llm:
        for v, o in zip(variants, q_attacked, strict=True):
            by_style[v.style].append(o.quarantined)
    results["_quarantine"] = {
        "flagged_variants": stats.rate_with_ci(
            sum(o.quarantined for o in q_attacked), len(q_attacked)
        ),
        "false_positive_clean_reports": stats.rate_with_ci(
            sum(o.quarantined for o in q_clean), len(q_clean)
        ),
        "flagged_by_style": {
            s: stats.rate_with_ci(sum(b), len(b)) for s, b in sorted(by_style.items())
        },
    }
    return results


def injection_fixture_table(path: Path) -> dict[str, Any]:
    """Run the real heuristics over the labelled samples; report detected/not detected per category."""
    from cti_guard.security import injection

    data = json.loads(path.read_text(encoding="utf-8"))
    cats: dict[str, dict[str, int]] = {}
    disagreements = 0
    for p in data["positives"]:
        c = cats.setdefault(p["category"], {"total": 0, "detected": 0, "expected_undetectable": 0})
        det = injection.scan(p["text"]).suspicious
        c["total"] += 1
        c["detected"] += det
        c["expected_undetectable"] += not p["expected_detected"]
        disagreements += det != p["expected_detected"]
    flagged = [n["id"] for n in data["negatives"] if injection.scan(n["text"]).suspicious]
    return {
        "positives": cats,
        "negatives": {
            "total": len(data["negatives"]),
            "flagged": len(flagged),
            "flagged_ids": flagged,
        },
        "disagreements_with_fixture_expectation": disagreements,
    }


def _merge_reps(reps: list[Any]) -> Any:
    """Pool k/n counts across repetitions and keep the per-repetition rates (dispersion)."""
    first = reps[0]
    if isinstance(first, dict) and {"k", "n", "rate", "ci95"} <= first.keys():
        k, n = sum(r["k"] for r in reps), sum(r["n"] for r in reps)
        merged = stats.rate_with_ci(k, n)
        merged["per_rep_rates"] = [None if r["rate"] is None else round(r["rate"], 4) for r in reps]
        return merged
    if isinstance(first, dict):
        return {key: _merge_reps([r[key] for r in reps if key in r]) for key in first}
    if isinstance(first, float):
        return round(sum(reps) / len(reps), 4)
    return first


def run_all(
    reports: list[Report],
    templates: list[Template],
    client: LLMClient | None,
    *,
    robust_n: int,
    per_attack: int,
    workers: int,
    seed: int,
    corpus_meta: dict[str, Any],
    nonce_secret: str = "cti-guard-eval-v1",
    reps: int = 1,
    adjudication: dict | None = None,
    injection_samples: Path | None = None,
    dump_outputs: Path | None = None,
) -> dict[str, Any]:
    llm = LLMSystems(client, seeded_nonce_fn(nonce_secret)) if client else None
    quality, clean = run_quality(reports, llm, workers, adjudication)
    if dump_outputs is not None:
        dump_outputs.write_text(
            json.dumps(
                {
                    sys_: {rid: sorted(o.iocs) for rid, o in outs.items()}
                    for sys_, outs in clean.items()
                }
            ),
            encoding="utf-8",
        )
    subset = reports[:robust_n]
    rep_results, n_variants = [], 0
    for rep in range(reps):
        variants = build_variants(subset, templates, per_attack=per_attack, seed=seed + rep)
        variants = [v for v in variants if v.attack != "fake_ioc" or v.fakes]
        n_variants += len(variants)
        rep_results.append(run_robustness(subset, variants, clean, llm, workers))
    robustness = _merge_reps(rep_results) if reps > 1 else rep_results[0]
    info = client.info() if client else None
    return {
        "meta": {
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "model": None
            if info is None
            else {
                "provider": info.provider,
                "name": info.model,
                "digest": info.digest,
                "server_version": info.server_version,
            },
            "seed": seed,
            "robust_reports": len(subset),
            "variants": n_variants,
            "repetitions": reps,
            "variants_per_attack": per_attack,
            "templates": len(templates),
            "corpus": corpus_meta,
        },
        "notes": {
            "recall_circularity": (
                "Reference IOC = STIX indicators that occur literally in the page body. A system that "
                "finds every IOC-shaped string after undoing defanging (regex_refang) therefore scores "
                "recall close to 100% by construction. Compare systems on precision and on robustness, "
                "not on this recall."
            ),
            "precision": "precision is vs STIX (strict); precision_adjudicated adds manually adjudicated true positives.",
            "protocol_deviations": [
                "Output-token cap raised (2048 -> 6144) and chunk size reduced (4000 -> 3000 chars) after a "
                "first run on the same corpus showed truncated JSON on hash-heavy chunks.",
                "Injection heuristics tuned on the 39 clean reports after they flagged 6 of them "
                "(rules 'persona_switch' and 'force_indicator' were too broad); done before seeing any attack templates.",
                "Verifier now rejects MD5/SHA-1 values that are fragments of a 64-hex hash wrapped by table layout "
                "(found by an audit of adjudications). Measured effect on the evaluation set: none for "
                "llm_d2..d4 (TP 1641 / FP 360 / FN 209 before and after; strict precision and recall unchanged); "
                "2 adjudications reclassified (A7); 14 dual-use-tool hashes excluded from adjudicated TP (A8).",
            ],
        },
        "injection_fixture": (
            injection_fixture_table(injection_samples)
            if injection_samples and injection_samples.exists()
            else None
        ),
        "quality": quality,
        "robustness": robustness,
    }


def write_metrics(metrics: dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(metrics, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
