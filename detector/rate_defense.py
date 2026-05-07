"""Rate-based message defense (baseline comparison).

Blocks messages when the current message rate (messages per second,
computed by the feature engine) exceeds a fixed multiple of the median
rate observed during the baseline phase.  This is the simplest possible
anomaly detector and serves as a lower-bound comparison for the Markov
and Isolation Forest defences.
"""

import csv
import json
from collections import defaultdict
from pathlib import Path

from framework.base import BaseDefense


class RateDefense(BaseDefense):
    def __init__(self, rate_multiplier=2.0, out_dir="out"):
        self.rate_multiplier = rate_multiplier
        self._baseline_rate: float | None = None
        self._threshold: float | None = None
        self._out = Path(out_dir)
        self._out.mkdir(exist_ok=True)
        self._log_path = self._out / "defense_rate.csv"

        self.blocked = 0
        self.passed = 0
        self._by_type: dict[int, int] = defaultdict(int)
        self._by_src: dict[int, int] = defaultdict(int)

        with self._log_path.open("w", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerow(
                ["timestamp", "msg_id", "src_system", "msg_rate", "action", "reason"]
            )

    @property
    def name(self) -> str:
        return "rate_threshold"

    def calibrate(self, baseline_rate: float) -> None:
        """Set the blocking threshold from the median baseline message rate."""
        self._baseline_rate = baseline_rate
        self._threshold = baseline_rate * self.rate_multiplier

    def evaluate(self, timestamp, msg_id, src, anomaly_score):
        """Return *True* if the message should be **blocked**.

        For RateDefense the ``anomaly_score`` parameter carries the
        current message rate (msgs/s) from the feature engine, keeping
        the call-site uniform across defence strategies.
        """
        current_rate = anomaly_score
        if self._threshold is not None and current_rate > self._threshold:
            self.blocked += 1
            self._by_type[msg_id] += 1
            self._by_src[src] += 1
            self._log(timestamp, msg_id, src, current_rate,
                      "BLOCK", "rate_above_threshold")
            return True
        self.passed += 1
        return False

    def _log(self, ts, msg_id, src, rate, action, reason):
        with self._log_path.open("a", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerow(
                [ts, msg_id, src, f"{rate:.4f}", action, reason]
            )

    def summary(self):
        total = self.blocked + self.passed
        return {
            "defense_type": "rate_threshold",
            "rate_multiplier": self.rate_multiplier,
            "baseline_rate": round(self._baseline_rate, 4) if self._baseline_rate else None,
            "threshold_rate": round(self._threshold, 4) if self._threshold else None,
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
