"""Adaptive ML-based message defense.

Blocks messages whose Isolation Forest anomaly score falls below a
configurable threshold.  Every decision is logged to CSV for
post-analysis and presentation.
"""

import csv
import json
from collections import defaultdict
from pathlib import Path

from framework.base import BaseDefense


class AdaptiveDefense(BaseDefense):
    def __init__(self, score_threshold=0.3, out_dir="out"):
        self.threshold = score_threshold
        self._out = Path(out_dir)
        self._out.mkdir(exist_ok=True)
        self._log_path = self._out / "defense_adaptive.csv"

        self.blocked = 0
        self.passed = 0
        self._by_type: dict[int, int] = defaultdict(int)
        self._by_src: dict[int, int] = defaultdict(int)

        with self._log_path.open("w", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerow(
                ["timestamp", "msg_id", "src_system", "anomaly_score", "action", "reason"]
            )

    @property
    def name(self) -> str:
        return "adaptive_isolation_forest"

    def evaluate(self, timestamp, msg_id, src, anomaly_score):
        """Return *True* if the message should be **blocked**."""
        if anomaly_score < self.threshold:
            self.blocked += 1
            self._by_type[msg_id] += 1
            self._by_src[src] += 1
            self._log(timestamp, msg_id, src, anomaly_score,
                      "BLOCK", "anomaly_score_below_threshold")
            return True
        self.passed += 1
        return False

    def _log(self, ts, msg_id, src, score, action, reason):
        with self._log_path.open("a", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerow(
                [ts, msg_id, src, f"{score:.4f}", action, reason]
            )

    def summary(self):
        total = self.blocked + self.passed
        return {
            "defense_type": "adaptive_isolation_forest",
            "score_threshold": self.threshold,
            "total_blocked": self.blocked,
            "total_passed": self.passed,
            "block_rate": round(self.blocked / max(total, 1), 4),
            "blocked_by_msg_type": dict(self._by_type),
            "blocked_by_src_system": {str(k): v for k, v in self._by_src.items()},
        }

    def write_summary(self, path=None):
        p = Path(path) if path else self._out / "defense_summary.json"
        with p.open("w", encoding="utf-8") as fh:
            json.dump(self.summary(), fh, indent=2)
