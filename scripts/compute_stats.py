"""Compute multi-seed statistics from sweep results."""
import json
import numpy as np
from pathlib import Path
import sys

results_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("batch_results_e3")
data = json.loads((results_dir / "sweep_summary.json").read_text())

metrics = ["precision", "recall", "f1_score", "block_rate", "detection_latency_sec"]
vecs = {m: [] for m in metrics}
for r in data["results"]:
    for m in metrics:
        v = r["metrics"].get(m)
        if v is not None:
            vecs[m].append(float(v))

print(f"\n{'='*60}")
print(f"  {results_dir}  ({len(data['results'])} runs)")
print(f"{'='*60}")
header = f"  {'Metric':<25s} {'Mean':>10s} {'Std':>10s} {'Min':>10s} {'Max':>10s}"
print(header)
print(f"  {'-'*55}")
for m in metrics:
    arr = np.array(vecs[m])
    line = f"  {m:<25s} {arr.mean():10.4f} {arr.std():10.4f} {arr.min():10.4f} {arr.max():10.4f}"
    print(line)
