"""Scenario orchestrator for the evaluation harness.

Launches the platform simulator, the ML-backed detector (Isolation Forest +
Markov model), an optional live dashboard, and then runs each attack script
in sequence.  All results are written to ``out/``.
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import time
from dataclasses import dataclass
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

# Moving-average window cap during --randomize-attacks so accuracy/anomaly traces
# react on human time-scales instead of a 1000-msg smoother washing out bursts.
_RANDOMIZE_MA_CAP = 160


@dataclass
class AttackEpisode:
    """One catalogue attack, possibly split into several rate/duration segments."""

    name: str
    script: str
    segments: list[tuple[float, float]]  # (rate msgs/s, duration s)


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

    p.add_argument(
        "--randomize-attacks",
        action="store_true",
        help=(
            "Shuffle attack order; randomize per-episode timing; split each episode "
            "into several segments with varying rates and short pauses; add random "
            "gaps between episodes. Caps the accuracy moving-average window so plots "
            "show bursts and recovery instead of a flat line."
        ),
    )
    p.add_argument(
        "--random-seed",
        type=int,
        default=None,
        help="RNG seed for --randomize-attacks (omit for different schedule each run).",
    )
    p.add_argument("--attack-rate-min", type=float, default=None,
                   help="With --randomize-attacks: min msgs/s (default ~0.35× --attack-rate).")
    p.add_argument("--attack-rate-max", type=float, default=None,
                   help="With --randomize-attacks: max msgs/s (default ~1.65× --attack-rate).")
    p.add_argument("--attack-duration-min", type=float, default=None,
                   help="With --randomize-attacks: min seconds per episode (default ~0.4× --attack-seconds).")
    p.add_argument("--attack-duration-max", type=float, default=None,
                   help="With --randomize-attacks: max seconds per episode (default ~1.6× --attack-seconds).")
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


def _bounds(args):
    r = args.attack_rate
    s = args.attack_seconds
    r_lo = args.attack_rate_min if args.attack_rate_min is not None else max(1.0, r * 0.35)
    r_hi = args.attack_rate_max if args.attack_rate_max is not None else max(r_lo, r * 1.65)
    d_lo = args.attack_duration_min if args.attack_duration_min is not None else max(0.5, s * 0.4)
    d_hi = args.attack_duration_max if args.attack_duration_max is not None else max(d_lo, s * 1.6)
    if r_lo > r_hi:
        r_lo, r_hi = r_hi, r_lo
    if d_lo > d_hi:
        d_lo, d_hi = d_hi, d_lo
    return r_lo, r_hi, d_lo, d_hi


def _partition_duration(total: float, n: int, rng: random.Random) -> list[float]:
    if n <= 1:
        return [total]
    cuts = [0.0, total]
    for _ in range(n - 1):
        cuts.append(rng.uniform(0.04 * total, 0.96 * total))
    cuts.sort()
    parts = [cuts[i + 1] - cuts[i] for i in range(len(cuts) - 1)]
    parts = [max(p, 0.1) for p in parts]
    s = sum(parts)
    return [p / s * total for p in parts]


def _sample_segment_rate(r_lo: float, r_hi: float, rng: random.Random) -> float:
    base = rng.uniform(r_lo, r_hi)
    roll = rng.random()
    if roll < 0.38:
        base *= rng.uniform(0.06, 0.42)
    elif roll < 0.62:
        base *= rng.uniform(1.08, 1.45)
    return max(1.0, base)


def _make_rng(args) -> random.Random:
    if args.random_seed is not None:
        return random.Random(args.random_seed)
    return random.Random()


def build_episode_schedule(
    args,
) -> tuple[list[AttackEpisode], list[float], list[list[float]]]:
    """Episodes, inter-episode gaps, and precomputed intra-episode pauses (seconds)."""
    if args.mode not in ("all", "attacks"):
        return [], [], []

    if not args.randomize_attacks:
        eps = [
            AttackEpisode(n, s, [(args.attack_rate, args.attack_seconds)])
            for n, s in ATTACK_SCRIPTS
        ]
        return eps, [], [[] for _ in eps]

    rng = _make_rng(args)
    r_lo, r_hi, d_lo, d_hi = _bounds(args)
    rows = list(ATTACK_SCRIPTS)
    rng.shuffle(rows)
    episodes: list[AttackEpisode] = []
    micro_per: list[list[float]] = []
    for name, script in rows:
        episode_dur = rng.uniform(d_lo, d_hi)
        n_seg = rng.randint(5, 13)
        part_durs = _partition_duration(episode_dur, n_seg, rng)
        segs = [(_sample_segment_rate(r_lo, r_hi, rng), d) for d in part_durs]
        episodes.append(AttackEpisode(name, script, segs))
        micro_per.append(
            [rng.uniform(0.04, 0.75) for _ in range(len(segs) - 1)]
        )
    gaps = [rng.uniform(0.35, 5.5) for _ in range(len(episodes) - 1)]
    return episodes, gaps, micro_per


def _schedule_wall_time(
    episodes: list[AttackEpisode],
    inter_gaps: list[float],
    micro_per: list[list[float]],
) -> float:
    seg = sum(d for ep in episodes for _, d in ep.segments)
    gaps_sum = sum(inter_gaps)
    micro = sum(sum(m) for m in micro_per)
    return seg + gaps_sum + micro


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

    episodes, inter_gaps, micro_per = build_episode_schedule(args)

    det_window = args.window
    if args.randomize_attacks and episodes:
        if det_window > _RANDOMIZE_MA_CAP:
            log(
                f"Randomized run: moving-average window {det_window} -> {_RANDOMIZE_MA_CAP} "
                f"(faster plot response to traffic bursts)."
            )
        det_window = min(det_window, _RANDOMIZE_MA_CAP)

    if args.randomize_attacks and episodes:
        wall = _schedule_wall_time(episodes, inter_gaps, micro_per)
        detector_total = args.baseline_seconds + wall + 5
    elif episodes:
        detector_total = args.baseline_seconds + sum(
            d for ep in episodes for _, d in ep.segments
        ) + 5
    else:
        detector_total = args.baseline_seconds + 5

    if args.randomize_attacks and episodes:
        log(
            "Volatile schedule (stage 3): shuffled attacks, multi-segment load per episode, "
            "random inter-episode gaps, per-segment rate jitter."
        )
        if args.random_seed is not None:
            log(f"  random-seed = {args.random_seed} (reproducible)")
        else:
            log("  random-seed = (none); schedule differs each run")
        for ep in episodes:
            n = len(ep.segments)
            total_d = sum(d for _, d in ep.segments)
            rmin = min(r for r, _ in ep.segments)
            rmax = max(r for r, _ in ep.segments)
            log(f"  - {ep.name}: {n} segments, {total_d:.1f}s total, rate [{rmin:.0f},{rmax:.0f}] msg/s")

    listen_udp = f"0.0.0.0:{_parse_port(args.udp)}"

    plotter_proc = None
    if args.live_plot:
        plotter_proc = subprocess.Popen(
            [sys.executable, str(base / "live_plotter.py"), str(live_path)],
            cwd=base,
        )

    metrics: dict = {}
    demo_start = time.time()

    detector_thread = threading.Thread(
        target=lambda: metrics.update(run_detector(
            udp=listen_udp,
            train_seconds=args.baseline_seconds,
            total_seconds=detector_total,
            window_size=det_window,
            threshold=args.threshold,
            out_dir=out_dir,
            enable_defense=args.defense,
            defense_threshold=args.defense_threshold,
        )),
        daemon=True,
    )

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

    if episodes:
        for ei, ep in enumerate(episodes):
            if ei > 0 and args.randomize_attacks and inter_gaps:
                gap = inter_gaps[ei - 1]
                log(f"Inter-attack gap: {gap:.2f}s (benign traffic only)")
                time.sleep(gap)

            log(f"Attack episode: {ep.name} ({len(ep.segments)} segments)")
            _write_event(live_path, {
                "event": "attack_start",
                "t": round(time.time() - demo_start, 3),
                "name": ep.name,
                "segments": len(ep.segments),
                "randomized": args.randomize_attacks,
            })

            micro = micro_per[ei] if ei < len(micro_per) else []
            for si, (atk_rate, atk_duration) in enumerate(ep.segments):
                if si > 0:
                    time.sleep(micro[si - 1])
                log(f"  segment {si + 1}/{len(ep.segments)}: rate={atk_rate:.1f}/s, {atk_duration:.2f}s")
                _write_event(live_path, {
                    "event": "attack_segment",
                    "t": round(time.time() - demo_start, 3),
                    "name": ep.name,
                    "segment": si,
                    "rate": round(atk_rate, 3),
                    "duration": round(atk_duration, 3),
                })
                cmd = [
                    sys.executable, ep.script,
                    "--udp", args.udp,
                    "--rate", str(atk_rate),
                    "--duration", str(atk_duration),
                    "--out-dir", str(out_dir),
                ]
                try:
                    subprocess.run(cmd, cwd=base, check=True)
                except subprocess.CalledProcessError as exc:
                    log(f"Attack failed: {ep.name} seg {si} ({exc})")

            _write_event(live_path, {
                "event": "attack_end",
                "t": round(time.time() - demo_start, 3),
                "name": ep.name,
            })

    detector_thread.join(timeout=detector_total + 5)

    log("Stopping simulator substitute.")
    sim_proc.terminate()
    try:
        sim_proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        sim_proc.kill()

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
