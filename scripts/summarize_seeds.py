#!/usr/bin/env python
"""Summarize multi-seed batch results with mean, std, and statistical tests.

Reads the ``sweep_summary.json`` produced by ``batch_runner.py``, extracts
per-run metrics (precision, recall, F1, block_rate, detection_latency_sec),
and prints a table of mean +/- std.  When a second results directory is
given (``--compare``), a Mann-Whitney U test is run between the two groups
for each metric.

Usage::

    python scripts/summarize_seeds.py batch_results/
    python scripts/summarize_seeds.py batch_results_e3/ --compare batch_results_e2/
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np

METRICS = [
    "precision",
    "recall",
    "f1_score",
    "block_rate",
    "detection_latency_sec",
    "total_blocked",
    "total_passed",
]


def load_metric_vectors(results_dir: Path) -> dict[str, list[float]]:
    summary_path = results_dir / "sweep_summary.json"
    if not summary_path.exists():
        print(f"Error: {summary_path} not found.", file=sys.stderr)
        sys.exit(1)

    with summary_path.open(encoding="utf-8") as f:
        data = json.load(f)

    vectors: dict[str, list[float]] = {m: [] for m in METRICS}
    for run in data.get("results", []):
        mets = run.get("metrics", {})
        for m in METRICS:
            val = mets.get(m)
            if val is not None:
                try:
                    vectors[m].append(float(val))
                except (ValueError, TypeError):
                    pass
    return vectors


def print_table(vectors: dict[str, list[float]], label: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {label}  ({len(next(iter(vectors.values()), []))} runs)")
    print(f"{'=' * 60}")
    print(f"  {'Metric':<25s} {'Mean':>10s} {'Std':>10s} {'Min':>10s} {'Max':>10s}")
    print(f"  {'-' * 55}")
    for m in METRICS:
        vals = vectors[m]
        if not vals:
            continue
        arr = np.array(vals)
        print(
            f"  {m:<25s} {arr.mean():10.4f} {arr.std():10.4f} "
            f"{arr.min():10.4f} {arr.max():10.4f}"
        )


def run_comparison(
    vecs_a: dict[str, list[float]],
    vecs_b: dict[str, list[float]],
    label_a: str,
    label_b: str,
) -> None:
    from scipy.stats import mannwhitneyu

    print(f"\n{'=' * 60}")
    print(f"  Mann-Whitney U test: {label_a} vs {label_b}")
    print(f"{'=' * 60}")
    print(f"  {'Metric':<25s} {'U':>10s} {'p-value':>10s} {'Sig?':>6s}")
    print(f"  {'-' * 51}")
    for m in METRICS:
        a, b = vecs_a[m], vecs_b[m]
        if len(a) < 2 or len(b) < 2:
            continue
        u_stat, p_val = mannwhitneyu(a, b, alternative="two-sided")
        sig = "yes" if p_val < 0.05 else "no"
        print(f"  {m:<25s} {u_stat:10.1f} {p_val:10.4f} {sig:>6s}")


def export_latex_table(vectors: dict[str, list[float]], out_path: Path) -> None:
    """Write a small LaTeX table fragment for copy-paste into experiments.tex."""
    lines = [
        r"\begin{tabular}{lcc}",
        r"\toprule",
        r"Metric & Mean & Std \\",
        r"\midrule",
    ]
    for m in METRICS:
        vals = vectors[m]
        if not vals:
            continue
        arr = np.array(vals)
        nice = m.replace("_", r"\_")
        lines.append(f"  {nice} & {arr.mean():.4f} & {arr.std():.4f} \\\\")
    lines.append(r"\bottomrule")
    lines.append(r"\end{tabular}")
    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nLaTeX table fragment written to {out_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize multi-seed batch results.")
    parser.add_argument("results_dir", help="Path to batch_results/ directory.")
    parser.add_argument(
        "--compare",
        default=None,
        help="Second results directory for statistical comparison.",
    )
    parser.add_argument(
        "--latex",
        default=None,
        help="Path to write a LaTeX table fragment.",
    )
    args = parser.parse_args()

    vecs = load_metric_vectors(Path(args.results_dir))
    print_table(vecs, args.results_dir)

    if args.latex:
        export_latex_table(vecs, Path(args.latex))

    if args.compare:
        vecs_b = load_metric_vectors(Path(args.compare))
        print_table(vecs_b, args.compare)
        run_comparison(vecs, vecs_b, args.results_dir, args.compare)


if __name__ == "__main__":
    main()
