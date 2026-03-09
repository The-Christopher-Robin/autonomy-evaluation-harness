"""Scenario orchestrator for the evaluation harness.

Launches the platform simulator, the ML-backed detector (Isolation Forest +
Markov model), an optional live dashboard, and then runs each attack script
in sequence.  All results are written to ``out/``.
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
import threading

from detector.detector import run_detector


ATTACK_SCRIPTS = [
    ("Heartbeat flood",        "attacks/heartbeat_flood.py"),
    ("Ping flood",             "attacks/ping_flood.py"),
    ("Param request flood",    "attacks/param_request_flood.py"),
    ("MITM identity spoof",    "attacks/mitm_identity_spoof.py"),
    ("Replay pattern attack",  "attacks/replay_pattern_attack.py"),
    ("Command injection burst", "attacks/command_injection_burst.py"),
]


def build_parser():
    p = argparse.ArgumentParser(description="Run an evaluation scenario.")
    p.add_argument("--udp", default="127.0.0.1:14550",
                   help="Host:port for UDP.")
    p.add_argument("--sim-rate", type=float, default=10.0,
                   help="Simulator message rate (msgs/s).")
    p.add_argument("--baseline-seconds", type=float, default=10.0,
                   help="Training / baseline duration.")
    p.add_argument("--attack-seconds", type=float, default=10.0,
                   help="Duration of each attack.")
    p.add_argument("--attack-rate", type=float, default=200.0,
                   help="Attack message rate (msgs/s).")
    p.add_argument("--window", type=int, default=1000,
                   help="Moving-average window size.")
    p.add_argument("--threshold", type=float, default=0.9,
                   help="Accuracy alert threshold.")
    p.add_argument("--mode", choices=["all", "baseline", "attacks"],
                   default="all")

    p.add_argument("--defense", action="store_true",
                   help="Enable adaptive ML defence (Isolation Forest).")
    p.add_argument("--defense-threshold", type=float, default=0.3,
                   help="Anomaly score below which messages are blocked (0-1).")

    p.add_argument("--live-plot", action="store_true", default=True,
                   help="Open a live detection dashboard (default: on).")
    p.add_argument("--no-live-plot", action="store_false", dest="live_plot",
                   help="Disable the live dashboard window.")
    return p


def _parse_port(udp):
    if ":" not in udp:
        raise ValueError("UDP must be in host:port form")
    _, port = udp.rsplit(":", 1)
    return port


def _write_event(path, event):
    """Append a single JSON-line event to the live-data stream."""
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(event) + "\n")


def main():
    args = build_parser().parse_args()
    base = Path(__file__).parent
    out_dir = base / "out"
    out_dir.mkdir(exist_ok=True)
    log_path = out_dir / "run_demo.log"
    live_path = out_dir / "live_data.jsonl"

    def log(line):
        stamp = datetime.now(timezone.utc).isoformat()
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write(f"{stamp} {line}\n")
        print(line)

    detector_total = args.baseline_seconds
    if args.mode in ("all", "attacks"):
        detector_total += args.attack_seconds * len(ATTACK_SCRIPTS)
    detector_total += 5

    listen_udp = f"0.0.0.0:{_parse_port(args.udp)}"

    # ---- launch live plotter ----
    plotter_proc = None
    if args.live_plot:
        plotter_proc = subprocess.Popen(
            [sys.executable, str(base / "live_plotter.py"), str(live_path)],
            cwd=base,
        )

    # ---- detector thread ----
    metrics: dict = {}
    demo_start = time.time()

    detector_thread = threading.Thread(
        target=lambda: metrics.update(run_detector(
            udp=listen_udp,
            train_seconds=args.baseline_seconds,
            total_seconds=detector_total,
            window_size=args.window,
            threshold=args.threshold,
            out_dir=out_dir,
            enable_defense=args.defense,
            defense_threshold=args.defense_threshold,
        )),
        daemon=True,
    )

    # ---- simulator ----
    log("Starting simulator substitute.")
    sim_proc = subprocess.Popen(
        [sys.executable, "sitl_sim.py",
         "--udp", args.udp,
         "--rate", str(args.sim_rate)],
        cwd=base,
    )

    log("Starting detector (Isolation Forest + Markov model).")
    if args.defense:
        log(f"Adaptive ML defence enabled  (score threshold = {args.defense_threshold}).")
    detector_thread.start()
    time.sleep(args.baseline_seconds)

    # ---- attacks ----
    if args.mode in ("all", "attacks"):
        for name, script in ATTACK_SCRIPTS:
            log(f"Running attack: {name}")
            _write_event(live_path, {
                "event": "attack_start",
                "t": round(time.time() - demo_start, 3),
                "name": name,
            })
            cmd = [
                sys.executable, script,
                "--udp",      args.udp,
                "--rate",     str(args.attack_rate),
                "--duration", str(args.attack_seconds),
                "--out-dir",  str(out_dir),
            ]
            try:
                subprocess.run(cmd, cwd=base, check=True)
            except subprocess.CalledProcessError as exc:
                log(f"Attack failed: {name} ({exc})")

            _write_event(live_path, {
                "event": "attack_end",
                "t": round(time.time() - demo_start, 3),
                "name": name,
            })

    # ---- tear-down ----
    detector_thread.join(timeout=detector_total + 5)

    log("Stopping simulator substitute.")
    sim_proc.terminate()
    try:
        sim_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        sim_proc.kill()

    # ---- metrics ----
    metrics_path = out_dir / "metrics.json"
    with metrics_path.open("w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)
    log(f"Metrics written to {metrics_path}")

    if args.defense:
        log("=== Adaptive Defence Report ===")
        log(f"  Model             : Isolation Forest (unsupervised)")
        log(f"  Score threshold   : {args.defense_threshold}")
        log(f"  Total blocked     : {metrics.get('total_blocked', 0)}")
        log(f"  Total passed      : {metrics.get('total_passed', 0)}")
        br = metrics.get("block_rate", 0)
        log(f"  Block rate        : {br:.1%}")
        bt = metrics.get("blocked_by_msg_type", {})
        if bt:
            log(f"  Blocked by type   : {bt}")
        bs = metrics.get("blocked_by_src_system", {})
        if bs:
            log(f"  Blocked by source : {bs}")
        log("  Defence log       : out/defense_adaptive.csv")
        log("  Defence summary   : out/defense_summary.json")

    log("Demo complete.")

    if plotter_proc:
        log("Live dashboard still open — close the window to exit.")
        try:
            plotter_proc.wait(timeout=300)
        except subprocess.TimeoutExpired:
            plotter_proc.terminate()


if __name__ == "__main__":
    main()
