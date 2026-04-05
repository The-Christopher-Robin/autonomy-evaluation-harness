#!/usr/bin/env python
"""Batch runner for multi-configuration evaluation sweeps.

Reads a YAML sweep configuration, generates all parameter combinations,
runs each configuration as a subprocess call to ``run_demo.py``, collects
per-run results, and produces comparison CSV / JSON reports.

Usage::

    python batch_runner.py --config configs/sweep.yaml --repeat 3
    python batch_runner.py --config configs/default.yaml --output-dir my_results
"""

from __future__ import annotations

import argparse
import csv
import itertools
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml


def load_sweep_config(config_path: str | Path) -> dict:
    with open(config_path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def generate_configurations(sweep_cfg: dict) -> list[dict]:
    """Generate all parameter combinations from a sweep config."""
    params = sweep_cfg.get("parameters", {})
    defaults = sweep_cfg.get("defaults", {})

    param_names = list(params.keys())
    param_values = [
        v if isinstance(v, list) else [v] for v in params.values()
    ]

    configs: list[dict] = []
    for combo in itertools.product(*param_values):
        cfg = dict(defaults)
        for name, val in zip(param_names, combo):
            cfg[name] = val
        configs.append(cfg)

    return configs


def run_single_config(
    config: dict,
    run_idx: int,
    output_dir: Path,
    project_root: Path,
) -> dict:
    """Run a single configuration and collect results."""
    run_dir = output_dir / f"run_{run_idx:04d}"
    run_dir.mkdir(parents=True, exist_ok=True)

    cmd = [sys.executable, str(project_root / "run_demo.py"), "--no-live-plot"]

    for key, val in config.items():
        flag = f"--{key.replace('_', '-')}"
        if isinstance(val, bool):
            if val:
                cmd.append(flag)
        else:
            cmd.extend([flag, str(val)])

    start_t = time.time()
    result = subprocess.run(
        cmd, cwd=project_root, capture_output=True, text=True,
    )
    elapsed = time.time() - start_t

    out = project_root / "out"
    run_metrics: dict = {}

    for name in ("metrics.json", "scenario_results.json"):
        src = out / name
        if src.exists():
            with src.open(encoding="utf-8") as f:
                run_metrics.update(json.load(f))

    for name in (
        "metrics.json", "scenario_results.json", "accuracy_plot.png",
        "detector_accuracy.csv", "defense_summary.json",
        "visual_analysis.json",
    ):
        src = out / name
        if src.exists():
            shutil.copy2(src, run_dir / name)

    run_result = {
        "run_idx": run_idx,
        "config": config,
        "metrics": run_metrics,
        "elapsed_seconds": round(elapsed, 2),
        "return_code": result.returncode,
    }

    with (run_dir / "run_result.json").open("w", encoding="utf-8") as f:
        json.dump(run_result, f, indent=2)

    return run_result


def build_comparison_csv(results: list[dict], output_path: Path) -> None:
    """Build a CSV comparing all configurations and their metrics."""
    if not results:
        return

    config_keys: set[str] = set()
    metric_keys: set[str] = set()
    for r in results:
        config_keys.update(r.get("config", {}).keys())
        metric_keys.update(r.get("metrics", {}).keys())

    config_keys_sorted = sorted(config_keys)

    scalar_metric_keys: list[str] = []
    for k in sorted(metric_keys):
        for r in results:
            val = r.get("metrics", {}).get(k)
            if val is not None and not isinstance(val, (dict, list)):
                scalar_metric_keys.append(k)
                break

    headers = (
        ["run_idx", "elapsed_seconds", "return_code"]
        + [f"config_{k}" for k in config_keys_sorted]
        + scalar_metric_keys
    )

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for r in results:
            row: list = [r["run_idx"], r["elapsed_seconds"], r["return_code"]]
            row.extend(r.get("config", {}).get(k, "") for k in config_keys_sorted)
            row.extend(r.get("metrics", {}).get(k, "") for k in scalar_metric_keys)
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(
        description="Batch runner for evaluation sweeps.",
    )
    parser.add_argument(
        "--config", required=True,
        help="Path to YAML sweep/config file.",
    )
    parser.add_argument(
        "--repeat", type=int, default=1,
        help="Repeat each configuration N times (default: 1).",
    )
    parser.add_argument(
        "--output-dir", default="batch_results",
        help="Directory for collected results (default: batch_results/).",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent
    sweep_cfg = load_sweep_config(args.config)
    configs = generate_configurations(sweep_cfg)

    output_dir = project_root / args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    total_runs = len(configs) * args.repeat
    print(
        f"Sweep: {len(configs)} configurations x {args.repeat} repeat(s) "
        f"= {total_runs} total runs"
    )

    all_results: list[dict] = []
    run_idx = 0

    for repeat_num in range(args.repeat):
        for config_idx, config in enumerate(configs):
            run_idx += 1
            print(
                f"\n[{run_idx}/{total_runs}] "
                f"Config {config_idx + 1}/{len(configs)}, "
                f"repeat {repeat_num + 1}/{args.repeat}"
            )
            print(f"  Parameters: {config}")

            result = run_single_config(config, run_idx, output_dir, project_root)
            all_results.append(result)

            p = result.get("metrics", {}).get("precision", "N/A")
            r = result.get("metrics", {}).get("recall", "N/A")
            f1 = result.get("metrics", {}).get("f1_score", "N/A")
            print(f"  Results: precision={p}, recall={r}, F1={f1}")

    summary_path = output_dir / "sweep_summary.json"
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(
            {
                "total_runs": run_idx,
                "configurations": len(configs),
                "repeats": args.repeat,
                "results": all_results,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
            f,
            indent=2,
        )

    csv_path = output_dir / "comparison.csv"
    build_comparison_csv(all_results, csv_path)

    print(f"\nSweep complete: {run_idx} runs")
    print(f"  Summary : {summary_path}")
    print(f"  CSV     : {csv_path}")


if __name__ == "__main__":
    main()
