import json
from pathlib import Path
import sys

base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("batch_results_e3")
for d in sorted(base.iterdir()):
    if d.is_dir():
        mf = d / "metrics.json"
        if mf.exists():
            m = json.loads(mf.read_text())
            br = m.get("block_rate", "?")
            p = m.get("precision", "?")
            r = m.get("recall", "?")
            f1 = m.get("f1_score", "?")
            print(f"{d.name}: block_rate={br} precision={p} recall={r} F1={f1}")
