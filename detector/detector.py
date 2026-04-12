"""Anomaly detector: Isolation Forest + Markov model with adaptive defence.

Phase 1 (baseline):  collect messages, extract features, train both models.
Phase 2 (monitoring): score every message, optionally block anomalies,
                      track prediction accuracy, and stream live data for
                      the real-time dashboard.
"""

import csv
import json
import time
from collections import defaultdict, deque
from pathlib import Path

from pymavlink import mavutil
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from .feature_engine import FeatureEngine, FEATURE_NAMES
from .ml_model import AnomalyDetector
from .adaptive_defense import AdaptiveDefense
from .markov_defense import MarkovDefense


class MarkovModel:
    def __init__(self):
        self.counts = defaultdict(lambda: defaultdict(int))

    def update(self, prev_id, next_id):
        self.counts[prev_id][next_id] += 1

    def predict(self, prev_id):
        options = self.counts.get(prev_id)
        if not options:
            return None
        return max(options.items(), key=lambda kv: kv[1])[0]

    def transition_prob(self, prev_id, next_id):
        options = self.counts.get(prev_id)
        if not options:
            return 0.0
        total = sum(options.values())
        return options.get(next_id, 0) / total if total > 0 else 0.0


def _normalize_udp(udp):
    if udp.startswith("udpin:"):
        return udp
    return f"udpin:{udp}"


def run_detector(
    udp,
    train_seconds,
    total_seconds,
    window_size,
    threshold,
    out_dir,
    enable_defense=False,
    defense_threshold=0.3,
    defense_mode="none",
):
    out_dir = Path(out_dir)
    out_dir.mkdir(exist_ok=True)

    csv_path = out_dir / "detector_accuracy.csv"
    alerts_path = out_dir / "alerts.log"
    alerts_path.write_text("", encoding="utf-8")
    live_path = out_dir / "live_data.jsonl"
    live_path.write_text("", encoding="utf-8")

    feat_engine = FeatureEngine(window_seconds=2.0)
    markov = MarkovModel()
    anomaly = AnomalyDetector(contamination=0.01, n_estimators=150)

    if defense_mode == "adaptive" or (enable_defense and defense_mode == "none"):
        defense = AdaptiveDefense(score_threshold=defense_threshold, out_dir=out_dir)
        defense_mode = "adaptive"
    elif defense_mode == "markov":
        defense = MarkovDefense(prob_threshold=defense_threshold, out_dir=out_dir)
    else:
        defense = None

    conn = mavutil.mavlink_connection(_normalize_udp(udp))
    acc_window: deque = deque(maxlen=window_size)

    start = time.time()
    train_end = start + train_seconds
    prev_id = None
    rows: list = []
    alert_active = False
    first_alert_time = None
    alert_count = 0
    baseline_feats: list = []
    baseline_count = 0

    while time.time() - start < total_seconds:
        msg = conn.recv_match(blocking=True, timeout=1)
        if msg is None:
            continue

        msg_id = msg.get_msgId()
        now = time.time()
        src = msg.get_srcSystem() if hasattr(msg, "get_srcSystem") else -1
        elapsed = now - start
        is_training = now <= train_end

        m_prob = markov.transition_prob(prev_id, msg_id) if prev_id is not None else 1.0
        feat_vec = feat_engine.extract(now, msg_id, src, m_prob)

        if is_training:
            if prev_id is not None:
                markov.update(prev_id, msg_id)
            baseline_feats.append(feat_vec)

            _append_live(live_path, {
                "t": round(elapsed, 3),
                "phase": "training",
                "msg_id": msg_id,
                "src": src,
                "anomaly": 1.0,
                "accuracy": 1.0,
                "blocked": False,
                "blocked_total": 0,
            })
        else:
            if not anomaly.is_trained and baseline_feats:
                baseline_count = len(baseline_feats)
                anomaly.fit(baseline_feats)
                baseline_feats = []
                _append_live(live_path, {"event": "training_end", "t": round(elapsed, 3)})

            a_score = anomaly.score(feat_vec)

            blocked = False
            if defense is not None:
                if defense_mode == "markov":
                    blocked = defense.evaluate(now, msg_id, src, m_prob)
                else:
                    blocked = defense.evaluate(now, msg_id, src, a_score)

            accuracy = sum(acc_window) / len(acc_window) if acc_window else 1.0

            if not blocked and prev_id is not None:
                predicted = markov.predict(prev_id)
                correct = 1 if predicted == msg_id else 0
                acc_window.append(correct)
                accuracy = sum(acc_window) / len(acc_window)

                rows.append([
                    now, msg_id,
                    predicted if predicted is not None else -1,
                    correct, accuracy, a_score,
                ])

                if len(acc_window) == window_size:
                    if accuracy < threshold and not alert_active:
                        with alerts_path.open("a", encoding="utf-8") as fh:
                            fh.write(
                                f"{now},ALERT,accuracy_below_threshold,{accuracy:.3f}\n"
                            )
                        alert_active = True
                        alert_count += 1
                        if first_alert_time is None:
                            first_alert_time = now
                    elif accuracy >= threshold:
                        alert_active = False

            _append_live(live_path, {
                "t": round(elapsed, 3),
                "phase": "monitoring",
                "msg_id": msg_id,
                "src": src,
                "anomaly": round(a_score, 4),
                "accuracy": round(accuracy, 4),
                "blocked": blocked,
                "blocked_total": defense.blocked if defense else 0,
            })

        prev_id = msg_id

    # ---- post-run outputs ----
    _write_csv(csv_path, rows)
    _write_enhanced_plot(out_dir, rows, start, threshold, train_seconds, defense, defense_mode)

    if defense:
        defense.write_summary()

    detection_latency = (
        (first_alert_time - train_end)
        if first_alert_time and first_alert_time > train_end
        else 0.0
    )

    metrics: dict = {
        "detection_latency_sec": round(detection_latency, 3),
        "total_alerts": alert_count,
        "model_type": "isolation_forest",
        "defense_mode": defense_mode,
        "features_used": FEATURE_NAMES,
        "baseline_samples": baseline_count,
    }
    if defense:
        metrics.update(defense.summary())
    return metrics


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _append_live(path, obj):
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj) + "\n")


def _write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow([
            "timestamp", "msg_id", "predicted_id",
            "correct", "moving_avg", "anomaly_score",
        ])
        for r in rows:
            w.writerow(r)


def _write_enhanced_plot(out_dir, rows, start, threshold, train_seconds, defense, defense_mode="none"):
    """Three-panel PNG saved after the run completes."""
    if not rows:
        _write_empty_plot(out_dir, threshold, train_seconds)
        return

    times = [r[0] - start for r in rows]
    accuracy = [r[4] for r in rows]
    anom = [r[5] for r in rows]

    mode_labels = {"none": "No Defense", "markov": "Markov Defense", "adaptive": "Isolation Forest + Adaptive Defense"}
    title = f"Detection Report ({mode_labels.get(defense_mode, defense_mode)})"
    fig, axes = plt.subplots(3, 1, figsize=(12, 9), sharex=True)
    fig.suptitle(title, fontsize=14, fontweight="bold")

    # --- Panel 1: accuracy ---
    ax1 = axes[0]
    ax1.plot(times, accuracy, color="#2196F3", linewidth=1.2, label="Moving Avg Accuracy")
    ax1.axhline(threshold, color="red", linestyle="--", alpha=0.7,
                label=f"Threshold ({threshold})")
    ax1.axvline(train_seconds, color="gray", linestyle=":", alpha=0.5, label="Training end")
    ax1.set_ylabel("Accuracy")
    ax1.set_ylim(-0.05, 1.05)
    ax1.legend(loc="lower left", fontsize=8)
    ax1.set_title("Detection Health (Moving Average Accuracy)", fontsize=10)
    ax1.grid(True, alpha=0.3)

    # --- Panel 2: anomaly score ---
    ax2 = axes[1]
    ax2.plot(times, anom, color="#9C27B0", linewidth=0.8, alpha=0.7, label="Anomaly Score")
    ax2.axhline(0.3, color="orange", linestyle="--", alpha=0.7, label="Defense threshold (0.3)")
    ax2.axvline(train_seconds, color="gray", linestyle=":", alpha=0.5)
    ax2.set_ylabel("Score (1 = normal)")
    ax2.set_ylim(-0.05, 1.05)
    ax2.legend(loc="lower left", fontsize=8)
    ax2.set_title("Isolation Forest Anomaly Score", fontsize=10)
    ax2.grid(True, alpha=0.3)

    # --- Panel 3: defense timeline ---
    ax3 = axes[2]
    if defense and defense.blocked > 0:
        csv_name = "defense_markov.csv" if defense_mode == "markov" else "defense_adaptive.csv"
        log_path = out_dir / csv_name
        if log_path.exists():
            block_times, cumulative = [], []
            with log_path.open("r", encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    if row["action"] == "BLOCK":
                        block_times.append(float(row["timestamp"]) - start)
            if block_times:
                cumulative = list(range(1, len(block_times) + 1))
                ax3.plot(block_times, cumulative, color="#FF9800", linewidth=1.5,
                         label=f"Blocked ({defense.blocked} total)")
    ax3.axvline(train_seconds, color="gray", linestyle=":", alpha=0.5, label="Training end")
    ax3.set_ylabel("Cumulative Blocked")
    ax3.set_xlabel("Time (seconds)")
    ax3.legend(loc="upper left", fontsize=8)
    defense_title = {"none": "No Defense", "markov": "Markov Defense Actions", "adaptive": "Adaptive Defense Actions"}
    ax3.set_title(defense_title.get(defense_mode, "Defense Actions"), fontsize=10)
    ax3.grid(True, alpha=0.3)

    fig.tight_layout()
    fig.savefig(out_dir / "accuracy_plot.png", dpi=150)
    plt.close(fig)


def _write_empty_plot(out_dir, threshold, train_seconds):
    fig, axes = plt.subplots(3, 1, figsize=(12, 9), sharex=True)
    fig.suptitle("Detection Report (no data)", fontsize=14)
    for ax in axes:
        ax.text(0.5, 0.5, "No monitoring data collected", transform=ax.transAxes,
                ha="center", va="center", fontsize=12, color="gray")
        ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_dir / "accuracy_plot.png", dpi=150)
    plt.close(fig)
