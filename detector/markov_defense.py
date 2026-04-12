"""Markov-only message defense.

Blocks messages whose Markov transition probability (from the previous
message type to the current one) falls below a configurable threshold.
This is a simpler, pattern-based defense that does not use ML feature
vectors or the Isolation Forest; it relies solely on learned message-
ordering statistics from the baseline phase.
"""

import csv
import json
from collections import defaultdict
from pathlib import Path


class MarkovDefense:
    def __init__(self, prob_threshold=0.05, out_dir="out"):
        self.threshold = prob_threshold
        self._out = Path(out_dir)
        self._out.mkdir(exist_ok=True)
        self._log_path = self._out / "defense_markov.csv"

        self.blocked = 0
        self.passed = 0
        self._by_type: dict[int, int] = defaultdict(int)
        self._by_src: dict[int, int] = defaultdict(int)

        with self._log_path.open("w", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerow(
                ["timestamp", "msg_id", "src_system", "transition_prob", "action", "reason"]
            )

    def evaluate(self, timestamp, msg_id, src_system, transition_prob):
        """Return *True* if the message should be **blocked**."""
        if transition_prob < self.threshold:
            self.blocked += 1
            self._by_type[msg_id] += 1
            self._by_src[src_system] += 1
            self._log(timestamp, msg_id, src_system, transition_prob,
                      "BLOCK", "transition_prob_below_threshold")
            return True
        self.passed += 1
        return False

    def _log(self, ts, msg_id, src, prob, action, reason):
        with self._log_path.open("a", newline="", encoding="utf-8") as fh:
            csv.writer(fh).writerow(
                [ts, msg_id, src, f"{prob:.4f}", action, reason]
            )

    def summary(self):
        total = self.blocked + self.passed
        return {
            "defense_type": "markov_transition",
            "prob_threshold": self.threshold,
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
