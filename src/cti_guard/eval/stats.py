"""Small statistics helpers (no numpy): Wilson interval, precision/recall/F1, bootstrap."""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Sequence

Z95 = 1.959963984540054


def wilson(successes: int, n: int, z: float = Z95) -> tuple[float, float] | None:
    """Wilson score interval for a binomial proportion; ``None`` when ``n == 0``."""
    if n <= 0:
        return None
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def prf(tp: int, fp: int, fn: int) -> dict[str, float | None]:
    """Precision, recall, F1 (``None`` if undefined)."""
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f1 = 2 * p * r / (p + r) if p is not None and r is not None and p + r else None
    return {"precision": p, "recall": r, "f1": f1}


def rate_with_ci(successes: int, n: int) -> dict[str, object]:
    """A proportion with its Wilson 95% interval, in a JSON-friendly shape."""
    ci = wilson(successes, n)
    return {
        "k": successes,
        "n": n,
        "rate": successes / n if n else None,
        "ci95": [round(ci[0], 4), round(ci[1], 4)] if ci else None,
    }


def bootstrap_ci(
    items: Sequence[object],
    statistic: Callable[[Sequence[object]], float | None],
    *,
    iterations: int = 1000,
    seed: int = 0,
) -> list[float] | None:
    """Percentile bootstrap 95% CI, resampling ``items`` (here: reports) with replacement."""
    if not items:
        return None
    rng = random.Random(seed)
    values: list[float] = []
    for _ in range(iterations):
        sample = [items[rng.randrange(len(items))] for _ in items]
        v = statistic(sample)
        if v is not None:
            values.append(v)
    if not values:
        return None
    values.sort()
    return [
        round(values[int(0.025 * len(values))], 4),
        round(values[int(0.975 * len(values)) - 1], 4),
    ]
