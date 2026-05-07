#!/usr/bin/env python
"""Run E3 with multiple random seeds and collect per-run metrics.

Simpler alternative to batch_runner.py that avoids subprocess overhead.
Runs each seed in-process and writes results to a JSON file.

Usage::

    python scripts/run_multi_seed.py --seeds 20 --output batch_results_e3
    python scripts/run_multi_seed.py --seeds 20 --output batch_results_e2 --no-randomize
    python scripts/run_multi_seed.py --seeds 20 --output batch_results_rate --defense-mode rate
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from run_demo import build_parser, build_episode_schedule, main as _demo_main


def run_seed(
    seed: int,
    defense_mode: str,
    randomize: bool,
    output_dir: Path,
    project_root: Path,
) -> dict:
    """Run a single seed by invoking run_demo in-process via subprocess."""
    import subprocess

    run_dir = output_dir / f"seed_{seed:03d}"
    run_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable, str(project_root / "run_demo.py"),
        "--no-live-plot",
        "--baseline-seconds", "5",
        "--attack-seconds", "5",
        "--attack-rate", "200",
        "--sim-rate", "10",
        "--threshold", "0.9",
        "--window", "100",
        "--mode", "all",
        "--defense-mode", defense_mode,
        "--random-seed", str(seed),
    ]
    if defense_mode == "markov":
        cmd.extend(["--defense-threshold", "0.05"])
    elif defense_mode == "rate":
        cmd.extend(["--defense-threshold", "2.0"])
    elif defense_mode == "adaptive":
        cmd.extend(["--defense-threshold", "0.5"])

    if randomize:
        cmd.append("--randomize-attacks")

    start_t = time.time()
    result = subprocess.run(cmd, cwd=project_root, capture_output=True, text=True)
    elapsed = time.time() - start_t

    out = project_root / "out"
    run_metrics: dict = {}

    for name in ("metrics.json", "scenario_results.json"):
        src = out / name
        if src.exists():
            with src.open(encoding="utf-8") as f:
                run_metrics.update(json.load(f))

    for name in ("metrics.json", "scenario_results.json", "accuracy_plot.png",
                  "detector_accuracy.csv", "defense_summary.json"):
        src = out / name
        if src.exists():
            shutil.copy2(src, run_dir / name)

    return {
        "seed": seed,
        "defense_mode": defense_mode,
        "randomize": randomize,
        "metrics": run_metrics,
        "elapsed_seconds": round(elapsed, 2),
        "return_code": result.returncode,
    }


def main():
    parser = argparse.ArgumentParser(description="Multi-seed experiment runner.")
    parser.add_argument("--seeds", type=int, default=20, help="Number of seeds (1..N).")
    parser.add_argument("--output", required=True, help="Output directory.")
    parser.add_argument("--defense-mode", default="markov", choices=["none", "markov", "adaptive", "rate"])
    parser.add_argument("--no-randomize", action="store_true", help="Disable randomized attacks.")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent.parent
    output_dir = project_root / args.output
    output_dir.mkdir(parents=True, exist_ok=True)

    randomize = not args.no_randomize
    total = args.seeds
    results = []

    print(f"Running {total} seeds, defense={args.defense_mode}, randomize={randomize}")
    print(f"Output: {output_dir}")
    sys.stdout.flush()

    for i in range(1, total + 1):
        print(f"\n[{i}/{total}] seed={i}, defense={args.defense_mode}", flush=True)
        result = run_seed(i, args.defense_mode, randomize, output_dir, project_root)
        results.append(result)

        m = result.get("metrics", {})
        print(
            f"  block_rate={m.get('block_rate', 'N/A')}, "
            f"precision={m.get('precision', 'N/A')}, "
            f"recall={m.get('recall', 'N/A')}, "
            f"F1={m.get('f1_score', 'N/A')}",
            flush=True,
        )

    summary = {
        "total_runs": total,
        "defense_mode": args.defense_mode,
        "randomize": randomize,
        "results": results,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    summary_path = output_dir / "sweep_summary.json"
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\nAll {total} seeds complete. Summary: {summary_path}", flush=True)


if __name__ == "__main__":
    main()
