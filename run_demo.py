"""Scenario orchestrator for the evaluation harness.

Launches the platform simulator, the ML-backed detector (Isolation Forest +
Markov model), an optional live dashboard, and then runs each attack script
in sequence.  All results are written to ``out/``.
"""

from __future__ import annotations

import argparse
import csv as csv_mod
import json
import random
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import threading

try:
    import yaml as _yaml
except ImportError:
    _yaml = None

from attacks import ATTACK_REGISTRY
from detector.detector import run_detector
from framework.metrics import ScenarioResult
from sitl_sim import SITLSimulator

try:
    from detector.visual_grounding import VisualGrounder
    _HAS_VISUAL = True
except ImportError:
    _HAS_VISUAL = False


ATTACK_CATALOGUE = [(cls().name, cls) for cls in ATTACK_REGISTRY]

# Moving-average window cap during --randomize-attacks so accuracy/anomaly traces
# react on human time-scales instead of a 1000-msg smoother washing out bursts.
_RANDOMIZE_MA_CAP = 160


@dataclass
class AttackEpisode:
    """One catalogue attack, possibly split into several rate/duration segments."""

    name: str
    attack_cls: type
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

    p.add_argument("--defense-mode", choices=["none", "markov", "adaptive", "rate"],
                   default="none",
                   help="Defense strategy: none, markov (transition-probability blocking), "
                        "adaptive (Isolation Forest anomaly-score blocking), "
                        "or rate (simple rate-threshold baseline).")
    p.add_argument("--defense-threshold", type=float, default=None,
                   help="Score/probability threshold below which messages are blocked. "
                        "Defaults: markov=0.05, adaptive=0.5, rate=2.0.")

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
                   help="With --randomize-attacks: min msgs/s (default ~0.35x --attack-rate).")
    p.add_argument("--attack-rate-max", type=float, default=None,
                   help="With --randomize-attacks: max msgs/s (default ~1.65x --attack-rate).")
    p.add_argument("--attack-duration-min", type=float, default=None,
                   help="With --randomize-attacks: min seconds per episode (default ~0.4x --attack-seconds).")
    p.add_argument("--attack-duration-max", type=float, default=None,
                   help="With --randomize-attacks: max seconds per episode (default ~1.6x --attack-seconds).")

    p.add_argument("--config", default=None,
                   help="Path to YAML configuration file (CLI args override YAML values).")
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
            AttackEpisode(n, cls, [(args.attack_rate, args.attack_seconds)])
            for n, cls in ATTACK_CATALOGUE
        ]
        return eps, [], [[] for _ in eps]

    rng = _make_rng(args)
    r_lo, r_hi, d_lo, d_hi = _bounds(args)
    rows = list(ATTACK_CATALOGUE)
    rng.shuffle(rows)
    episodes: list[AttackEpisode] = []
    micro_per: list[list[float]] = []
    for name, cls in rows:
        episode_dur = rng.uniform(d_lo, d_hi)
        n_seg = rng.randint(5, 13)
        part_durs = _partition_duration(episode_dur, n_seg, rng)
        segs = [(_sample_segment_rate(r_lo, r_hi, rng), d) for d in part_durs]
        episodes.append(AttackEpisode(name, cls, segs))
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
    parser = build_parser()

    # Two-pass config loading: YAML sets defaults, CLI args override.
    pre_args, _ = parser.parse_known_args()
    if pre_args.config:
        if _yaml is None:
            print("pyyaml is required for --config.  pip install pyyaml")
            sys.exit(1)
        with open(pre_args.config, encoding="utf-8") as _f:
            _cfg = _yaml.safe_load(_f) or {}
        _mapped = {}
        for _k, _v in _cfg.items():
            _key = _k.replace("-", "_")
            if not isinstance(_v, (dict, list)):
                _mapped[_key] = _v
        parser.set_defaults(**_mapped)

    args = parser.parse_args()

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

    effective_mode = args.defense_mode

    if args.defense_threshold is None:
        _defaults = {"markov": 0.05, "adaptive": 0.5, "rate": 2.0, "none": 0.3}
        args.defense_threshold = _defaults.get(effective_mode, 0.3)

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
    attack_window_times: list[tuple[str, float, float]] = []

    detector_thread = threading.Thread(
        target=lambda: metrics.update(run_detector(
            udp=listen_udp,
            train_seconds=args.baseline_seconds,
            total_seconds=detector_total,
            window_size=det_window,
            threshold=args.threshold,
            out_dir=out_dir,
            defense_mode=effective_mode,
            defense_threshold=args.defense_threshold,
        )),
        daemon=True,
    )

    log("Starting simulator substitute.")
    simulator = SITLSimulator()
    simulator.start(target=args.udp, rate=args.sim_rate)

    log("Starting detector (Isolation Forest + Markov model).")
    mode_desc = {
        "none": "No defense (detection only).",
        "markov": f"Markov defense enabled (transition-prob threshold = {args.defense_threshold}).",
        "adaptive": f"Adaptive ML defence enabled (anomaly-score threshold = {args.defense_threshold}).",
        "rate": f"Rate-based baseline defence enabled (multiplier = {args.defense_threshold}).",
    }
    log(mode_desc.get(effective_mode, f"Defense mode: {effective_mode}"))
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

            ep_wall_start = time.time() - demo_start

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
                try:
                    attack = ep.attack_cls()
                    attack.execute(
                        target=args.udp,
                        duration=atk_duration,
                        rate=atk_rate,
                        out_dir=str(out_dir),
                    )
                except Exception as exc:
                    log(f"Attack failed: {ep.name} seg {si} ({exc})")

            ep_wall_end = time.time() - demo_start
            attack_window_times.append((ep.name, ep_wall_start, ep_wall_end))

            _write_event(live_path, {
                "event": "attack_end",
                "t": round(time.time() - demo_start, 3),
                "name": ep.name,
            })

    detector_thread.join(timeout=detector_total + 5)

    log("Stopping simulator substitute.")
    simulator.stop()

    # ---- ScenarioResult: classification metrics ----
    scenario = ScenarioResult(
        scenario_name="demo_run",
        baseline_end=args.baseline_seconds,
    )
    for name, start_t, end_t in attack_window_times:
        scenario.add_attack_window(name=name, start=start_t, end=end_t)

    alerts_path = out_dir / "alerts.log"
    if alerts_path.exists():
        for line in alerts_path.read_text(encoding="utf-8").splitlines():
            parts = line.strip().split(",")
            if len(parts) >= 2 and parts[1] == "ALERT":
                try:
                    scenario.add_alert(float(parts[0]) - demo_start)
                except ValueError:
                    pass

    anomaly_threshold = 0.5
    csv_path = out_dir / "detector_accuracy.csv"
    if csv_path.exists():
        with csv_path.open(encoding="utf-8") as f:
            reader = csv_mod.DictReader(f)
            for row in reader:
                try:
                    ts = float(row["timestamp"]) - demo_start
                    score = float(row["anomaly_score"])
                    msg_id = int(row["msg_id"])
                    is_attack = any(
                        w.start <= ts <= w.end
                        for w in scenario._attack_windows
                    )
                    scenario.add_prediction(msg_id, score < anomaly_threshold, is_attack)
                    scenario.record_accuracy(ts, float(row["moving_avg"]))
                except (ValueError, KeyError):
                    pass

    _csv_map = {"markov": "defense_markov.csv", "adaptive": "defense_adaptive.csv", "rate": "defense_rate.csv"}
    defense_csv_name = _csv_map.get(effective_mode, "defense_adaptive.csv")
    defense_csv = out_dir / defense_csv_name
    if effective_mode != "none" and defense_csv.exists():
        with defense_csv.open(encoding="utf-8") as f:
            reader = csv_mod.DictReader(f)
            for row in reader:
                try:
                    if row.get("action") == "BLOCK":
                        ts = float(row["timestamp"]) - demo_start
                        msg_id = int(row["msg_id"])
                        is_attack = any(
                            w.start <= ts <= w.end
                            for w in scenario._attack_windows
                        )
                        scenario.add_prediction(msg_id, True, is_attack)
                except (ValueError, KeyError):
                    pass

    scenario_metrics = scenario.compute()
    scenario_path = out_dir / "scenario_results.json"
    scenario.save(scenario_path)
    log(f"Scenario results written to {scenario_path}")

    if scenario_metrics.get("total_predictions", 0) > 0:
        log("=== Classification Metrics ===")
        log(f"  Precision : {scenario_metrics.get('precision', 'N/A')}")
        log(f"  Recall    : {scenario_metrics.get('recall', 'N/A')}")
        log(f"  F1 Score  : {scenario_metrics.get('f1_score', 'N/A')}")
        log(f"  TP={scenario_metrics.get('true_positives', 0)}  "
            f"FP={scenario_metrics.get('false_positives', 0)}  "
            f"FN={scenario_metrics.get('false_negatives', 0)}  "
            f"TN={scenario_metrics.get('true_negatives', 0)}")

    # ---- detector metrics.json ----
    metrics.update({
        "precision": scenario_metrics.get("precision"),
        "recall": scenario_metrics.get("recall"),
        "f1_score": scenario_metrics.get("f1_score"),
    })

    metrics_path = out_dir / "metrics.json"
    with metrics_path.open("w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)
    log(f"Metrics written to {metrics_path}")

    # ---- Visual grounding analysis ----
    if _HAS_VISUAL:
        try:
            grounder = VisualGrounder()
            plot_path = out_dir / "accuracy_plot.png"
            if plot_path.exists():
                visual_analysis = grounder.analyze_dashboard_frame(plot_path)
                visual_report = grounder.generate_visual_report(out_dir)
                visual_path = out_dir / "visual_analysis.json"
                with visual_path.open("w", encoding="utf-8") as fh:
                    json.dump({
                        "dashboard_analysis": visual_analysis,
                        "visual_report": visual_report,
                    }, fh, indent=2, default=str)
                log(f"Visual analysis written to {visual_path}")
        except Exception as e:
            log(f"Visual grounding analysis skipped: {e}")

    if effective_mode != "none":
        _model_labels = {
            "markov": "Markov transition model",
            "adaptive": "Isolation Forest (unsupervised)",
            "rate": "Rate-threshold baseline",
        }
        model_label = _model_labels.get(effective_mode, effective_mode)
        log(f"=== Defence Report ({effective_mode}) ===")
        log(f"  Model             : {model_label}")
        log(f"  Threshold         : {args.defense_threshold}")
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
        _rpt_csv = {"markov": "defense_markov.csv", "adaptive": "defense_adaptive.csv", "rate": "defense_rate.csv"}
        log(f"  Defence log       : out/{_rpt_csv.get(effective_mode, 'defense_adaptive.csv')}")
        log("  Defence summary   : out/defense_summary.json")

    log("Demo complete.")

    if plotter_proc:
        log("Live dashboard still open -- close the window to exit.")
        try:
            plotter_proc.wait(timeout=300)
        except subprocess.TimeoutExpired:
            plotter_proc.terminate()


if __name__ == "__main__":
    main()
