"""Real-time detection dashboard.

Reads ``out/live_data.jsonl`` (appended by the detector in real time)
and refreshes a three-panel matplotlib window every 200 ms:

  Panel 1 -- Detection health  (moving-average accuracy)
  Panel 2 -- Isolation Forest anomaly score
  Panel 3 -- Cumulative blocked messages  (adaptive defence)

Launch:  python live_plotter.py [path/to/live_data.jsonl]
"""

import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.animation as animation


def main():
    data_path = (
        Path(sys.argv[1]) if len(sys.argv) > 1 else Path("out/live_data.jsonl")
    )

    plt.style.use("dark_background")
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(13, 8), sharex=True)
    fig.suptitle(
        "Live Detection Dashboard",
        fontsize=14, fontweight="bold", color="white",
    )
    fig.canvas.manager.set_window_title("Harness – Live Detection")

    state = {
        "idx": 0,
        "times": [], "acc": [], "anom": [], "blk": [],
        "events": [],
    }

    (line_acc,) = ax1.plot([], [], color="#00E5FF", linewidth=1.5, label="Accuracy")
    ax1.axhline(0.9, color="#FF1744", linestyle="--", alpha=0.7, label="Threshold (0.9)")
    ax1.set_ylabel("Accuracy", fontsize=9)
    ax1.set_ylim(-0.05, 1.05)
    ax1.set_title("Detection Health", fontsize=10)
    ax1.legend(loc="lower left", fontsize=8)
    ax1.grid(True, alpha=0.15)

    (line_anom,) = ax2.plot([], [], color="#AA00FF", linewidth=0.8, alpha=0.85,
                            label="Anomaly Score")
    ax2.axhline(0.3, color="#FF9100", linestyle="--", alpha=0.7,
                label="Defense Threshold")
    ax2.set_ylabel("Score (1 = normal)", fontsize=9)
    ax2.set_ylim(-0.05, 1.05)
    ax2.set_title("Isolation Forest Anomaly Score", fontsize=10)
    ax2.legend(loc="lower left", fontsize=8)
    ax2.grid(True, alpha=0.15)

    (line_blk,) = ax3.plot([], [], color="#FF9100", linewidth=1.5,
                           label="Cumulative Blocked")
    ax3.set_ylabel("Blocked Count", fontsize=9)
    ax3.set_xlabel("Time (seconds)", fontsize=9)
    ax3.set_title("Adaptive Defense Actions", fontsize=10)
    ax3.legend(loc="upper left", fontsize=8)
    ax3.grid(True, alpha=0.15)

    fig.tight_layout(rect=[0, 0, 1, 0.95])

    def _update(_frame):
        s = state
        if not data_path.exists():
            return (line_acc, line_anom, line_blk)

        with data_path.open("r", encoding="utf-8") as fh:
            lines = fh.readlines()

        for raw in lines[s["idx"]:]:
            raw = raw.strip()
            if not raw:
                continue
            try:
                pt = json.loads(raw)
            except json.JSONDecodeError:
                continue

            if "event" in pt:
                s["events"].append(pt)
                t = pt.get("t", 0)
                if pt["event"] == "training_end":
                    for ax in (ax1, ax2, ax3):
                        ax.axvline(t, color="gray", linestyle=":", alpha=0.5)
                elif pt["event"] == "attack_start":
                    for ax in (ax1, ax2, ax3):
                        ax.axvline(t, color="#FF1744", linestyle="--", alpha=0.35)
                    ax1.annotate(
                        pt.get("name", ""),
                        xy=(t, 1.02), fontsize=6, color="#FF1744",
                        alpha=0.8, rotation=90, va="top",
                    )
                elif pt["event"] == "attack_end":
                    for ax in (ax1, ax2, ax3):
                        ax.axvline(t, color="#00E676", linestyle="--", alpha=0.35)
                continue

            s["times"].append(pt.get("t", 0))
            s["acc"].append(pt.get("accuracy", 1.0))
            s["anom"].append(pt.get("anomaly", 1.0))
            s["blk"].append(pt.get("blocked_total", 0))

        s["idx"] = len(lines)

        if not s["times"]:
            return (line_acc, line_anom, line_blk)

        line_acc.set_data(s["times"], s["acc"])
        line_anom.set_data(s["times"], s["anom"])
        line_blk.set_data(s["times"], s["blk"])

        xmax = max(s["times"][-1], 1) * 1.02
        for ax in (ax1, ax2, ax3):
            ax.set_xlim(0, xmax)
        blk_max = max(s["blk"]) if s["blk"] else 1
        ax3.set_ylim(0, max(blk_max, 1) * 1.15)

        return (line_acc, line_anom, line_blk)

    _ani = animation.FuncAnimation(  # noqa: F841  prevent GC
        fig, _update, interval=200, blit=False, cache_frame_data=False,
    )
    plt.show()


if __name__ == "__main__":
    main()
