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

Usage::

    result = ScenarioResult(...)
    result.add_attack_window(start=10.0, end=20.0)
    result.add_alert(timestamp=11.2)
    result.add_blocked_message(timestamp=11.3, msg_id=4)
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

    # -- event recording --------------------------------------------------

    def add_alert(self, timestamp: float) -> None:
        self._alerts.append(timestamp)

    def add_blocked_message(self, timestamp: float, msg_id: int, **extra: Any) -> None:
        self._blocks.append({"t": timestamp, "msg_id": msg_id, **extra})

    def add_attack_window(self, name: str, start: float, end: float) -> None:
        self._attack_windows.append(AttackWindow(name, start, end))

    def record_accuracy(self, timestamp: float, accuracy: float) -> None:
        self._accuracy_series.append((timestamp, accuracy))

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

        return m

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as fh:
            json.dump(self.compute(), fh, indent=2)
