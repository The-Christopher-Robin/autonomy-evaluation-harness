"""Standardised security and mission-level metrics.

Every evaluation scenario produces a :class:`ScenarioResult` that can be
compared across different attack / defense / parameter combinations.
Metrics follow the taxonomy used in CPS intrusion-detection literature:

* **Detection rate** (true-positive rate)
* **False-positive rate**
* **Detection latency** (time-to-first-alert after attack onset)
* **Block rate** (fraction of attack traffic stopped by active defence)
* **Accuracy recovery** (post-defence accuracy minus attack-period minimum)
* **Mission impact** (fraction of time the system was in a degraded state)
* **Precision / Recall / F1** (classification metrics for anomaly detection)

Usage::

    result = ScenarioResult(...)
    result.add_attack_window(start=10.0, end=20.0)
    result.add_alert(timestamp=11.2)
    result.add_blocked_message(timestamp=11.3, msg_id=4)
    result.add_prediction(msg_id=5, predicted_anomaly=True, actual_anomaly=True)
    summary = result.compute()
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AttackWindow:
    name: str
    start: float
    end: float


@dataclass
class ScenarioResult:
    """Accumulates raw events and computes comparable metrics."""

    scenario_name: str = ""
    baseline_end: float = 0.0

    _alerts: list[float] = field(default_factory=list)
    _blocks: list[dict[str, Any]] = field(default_factory=list)
    _attack_windows: list[AttackWindow] = field(default_factory=list)
    _accuracy_series: list[tuple[float, float]] = field(default_factory=list)
    _predictions: list[dict[str, Any]] = field(default_factory=list)

    # -- event recording --------------------------------------------------

    def add_alert(self, timestamp: float) -> None:
        self._alerts.append(timestamp)

    def add_blocked_message(self, timestamp: float, msg_id: int, **extra: Any) -> None:
        self._blocks.append({"t": timestamp, "msg_id": msg_id, **extra})

    def add_attack_window(self, name: str, start: float, end: float) -> None:
        self._attack_windows.append(AttackWindow(name, start, end))

    def record_accuracy(self, timestamp: float, accuracy: float) -> None:
        self._accuracy_series.append((timestamp, accuracy))

    def add_prediction(
        self,
        message_id: int,
        predicted_anomaly: bool,
        actual_anomaly: bool,
    ) -> None:
        """Record a single classification prediction for precision/recall/F1."""
        self._predictions.append({
            "message_id": message_id,
            "predicted": predicted_anomaly,
            "actual": actual_anomaly,
        })

    # -- classification metrics -------------------------------------------

    def compute_classification_metrics(self) -> dict[str, Any]:
        """Compute precision, recall, and F1 from recorded predictions."""
        if not self._predictions:
            return {
                "true_positives": 0,
                "false_positives": 0,
                "false_negatives": 0,
                "true_negatives": 0,
                "precision": 0.0,
                "recall": 0.0,
                "f1_score": 0.0,
                "total_predictions": 0,
            }

        tp = sum(1 for p in self._predictions if p["predicted"] and p["actual"])
        fp = sum(1 for p in self._predictions if p["predicted"] and not p["actual"])
        fn = sum(1 for p in self._predictions if not p["predicted"] and p["actual"])
        tn = sum(1 for p in self._predictions if not p["predicted"] and not p["actual"])

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        return {
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "true_negatives": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "total_predictions": len(self._predictions),
        }

    # -- metric computation -----------------------------------------------

    def compute(self) -> dict[str, Any]:
        """Return a flat dictionary of all metrics."""
        m: dict[str, Any] = {"scenario": self.scenario_name}

        attack_alerts = [
            t for t in self._alerts
            if any(w.start <= t <= w.end for w in self._attack_windows)
        ]
        baseline_alerts = [
            t for t in self._alerts if t < self.baseline_end
        ]

        m["total_alerts"] = len(self._alerts)
        m["true_positive_alerts"] = len(attack_alerts)
        m["false_positive_alerts"] = len(baseline_alerts)
        m["false_positive_rate"] = (
            round(len(baseline_alerts) / max(len(self._alerts), 1), 4)
        )

        if self._attack_windows and attack_alerts:
            first_attack_start = min(w.start for w in self._attack_windows)
            m["detection_latency_sec"] = round(
                min(attack_alerts) - first_attack_start, 3
            )
        else:
            m["detection_latency_sec"] = None

        m["total_blocked"] = len(self._blocks)
        if self._attack_windows:
            total_attack_dur = sum(w.end - w.start for w in self._attack_windows)
            attack_blocks = [
                b for b in self._blocks
                if any(w.start <= b["t"] <= w.end for w in self._attack_windows)
            ]
            m["attack_period_blocks"] = len(attack_blocks)
        else:
            total_attack_dur = 0
            m["attack_period_blocks"] = 0

        if self._accuracy_series:
            attack_acc = [
                acc for t, acc in self._accuracy_series
                if any(w.start <= t <= w.end for w in self._attack_windows)
            ]
            post_attack_acc = [
                acc for t, acc in self._accuracy_series
                if self._attack_windows
                and t > max(w.end for w in self._attack_windows)
            ]
            if attack_acc:
                m["min_accuracy_during_attack"] = round(min(attack_acc), 4)
            if post_attack_acc:
                m["accuracy_recovery"] = round(
                    max(post_attack_acc) - min(attack_acc) if attack_acc else 0, 4
                )

        degraded = sum(
            1 for _, acc in self._accuracy_series if acc < 0.9
        )
        m["mission_impact_ratio"] = round(
            degraded / max(len(self._accuracy_series), 1), 4
        )

        m["attacks"] = [
            {"name": w.name, "start": w.start, "end": w.end}
            for w in self._attack_windows
        ]

        # Classification metrics (precision / recall / F1)
        m.update(self.compute_classification_metrics())

        return m

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as fh:
            json.dump(self.compute(), fh, indent=2)
