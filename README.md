# Autonomy Security Evaluation Harness

A standardised **red-team vs blue-team evaluation framework** for
AI-controlled autonomous and cyber-physical systems.

Most CPS security papers test one attack or one defence in isolation, use
ad-hoc setups, and rarely share a reusable environment.  This project fills
that gap with an engineering-grade harness that launches missions, schedules
attacks, runs defences in parallel, logs synchronised events, and
automatically computes **comparable** metrics such as detection rate, false
positives, latency, block rate, precision, recall, F1, and mission impact.

The framework supports **automated multi-configuration sweeps** (18+
configurations, 50+ runs via repeat) for systematically comparing
detection approaches, and includes **OpenCV-based visual grounding** for
multimodal dashboard analysis.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                       Orchestrator (run_demo.py)                 │
│  launches sim · starts detector · schedules attacks · logs events│
├──────────┬──────────────┬────────────────┬───────────────────────┤
│ Platform │  Attacks     │  Detector +    │  Live Dashboard       │
│ Simulator│  (pluggable) │  Defence       │  (live_plotter.py)    │
│          │              │  (pluggable)   │                       │
│ sitl_sim │ heartbeat    │ Isolation      │ 3-panel real-time     │
│  .py     │ ping         │  Forest        │  matplotlib window    │
│          │ param_req    │ Markov model   │                       │
│  MAVLink │ mitm_spoof   │ Adaptive       │ accuracy · anomaly    │
│  UDP     │ replay       │  filter        │  score · blocked msgs │
│          │ cmd_inject   │                │                       │
└──────────┴──────────────┴────────────────┴───────────────────────┘
         ▼                       ▼                    ▼
    out/attack_*.csv     out/detector_accuracy.csv   out/live_data.jsonl
                         out/defense_adaptive.csv    out/scenario_results.json
                         out/metrics.json            out/visual_analysis.json
```

### Key design principles

| Principle | How it is realised |
|---|---|
| **ABC-based extensibility** | All components implement ABCs from `framework/base.py` (`BaseAttack`, `BaseDetector`, `BaseDefense`, `BasePlatform`). Swap implementations without touching the orchestrator. |
| **Attacks are first-class modules** | Each attack is a standalone script with a uniform CLI (`--udp`, `--rate`, `--duration`, `--out-dir`) **and** a class implementing `BaseAttack`. |
| **Defences are pluggable** | The detector and adaptive filter implement `BaseDetector` / `BaseDefense` ABCs. Swap the Isolation Forest for a neural network or rule engine without touching the orchestrator. |
| **Standardised metrics** | `framework/metrics.py` provides `ScenarioResult` — a single class that computes detection rate, false-positive rate, latency, block rate, **precision, recall, F1**, accuracy recovery, and mission impact. |
| **Multi-config sweeps** | `batch_runner.py` generates 18+ configurations from YAML sweep files and runs them with optional repeats (50+ automated runs). |
| **OpenCV visual grounding** | `detector/visual_grounding.py` provides multimodal dashboard analysis via contour detection, color thresholding, and frame comparison. |
| **Reproducible by default** | Fixed random seeds, deterministic baselines, YAML-based configuration, CSV/JSON reports. |

---

## Quick start

```bash
# clone and set up
git clone <repo-url> && cd autonomy-evaluation-harness
python -m venv .venv
# Linux / macOS
source .venv/bin/activate
# Windows PowerShell
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

### Run a single demo

```bash
python run_demo.py --mode all --defense
```

### Run with a YAML config file

```bash
python run_demo.py --config configs/default.yaml
```

### Batch sweep (18+ configurations)

```bash
python batch_runner.py --config configs/sweep.yaml --repeat 3 --output-dir batch_results
```

This generates 18 configurations (3 attack rates × 3 thresholds × 2 defence modes) and runs each 3 times = 54 total runs, producing a `comparison.csv` and `sweep_summary.json`.

### Customise a scenario

```bash
python run_demo.py \
    --mode all \
    --defense \
    --baseline-seconds 15 \
    --attack-seconds 12 \
    --attack-rate 250 \
    --threshold 0.85 \
    --defense-threshold 0.3
```

### Disable the live dashboard

```bash
python run_demo.py --mode all --defense --no-live-plot
```

### Randomized attack order and parameters

```bash
python run_demo.py --mode all --defense --randomize-attacks --random-seed 42
```

Randomized mode uses **multi-segment** attacks, **inter-episode gaps**, and a **capped**
moving-average window so live plots show volatile accuracy and anomaly traces. See [DEMO.md](DEMO.md).

### Run tests

```bash
python -m pytest tests/ -v
```

---

## Project layout

```
.
├── framework/                # Harness abstractions & utilities
│   ├── base.py               #   ABCs: BaseAttack, BaseDefense, BaseDetector, BasePlatform
│   └── metrics.py            #   ScenarioResult with precision/recall/F1
│
├── detector/                 # Reference defence implementation
│   ├── detector.py           #   Main detection loop (Isolation Forest + Markov)
│   ├── feature_engine.py     #   11-dim sliding-window feature extraction
│   ├── ml_model.py           #   IsolationForest anomaly scorer (→ BaseDetector)
│   ├── adaptive_defense.py   #   Score-threshold adaptive message filter (→ BaseDefense)
│   └── visual_grounding.py   #   OpenCV-based multimodal dashboard analysis
│
├── attacks/                  # Attack catalogue (one module per vector)
│   ├── heartbeat_flood.py    #   → BaseAttack
│   ├── ping_flood.py         #   → BaseAttack
│   ├── param_request_flood.py#   → BaseAttack
│   ├── mitm_identity_spoof.py#   → BaseAttack
│   ├── replay_pattern_attack.py# → BaseAttack
│   └── command_injection_burst.py# → BaseAttack
│
├── configs/                  # YAML configuration files
│   ├── default.yaml          #   Single baseline config
│   └── sweep.yaml            #   18-config parameter sweep
│
├── tests/                    # Unit tests
│   └── test_metrics.py       #   Precision/recall/F1, feature engine, ML model
│
├── run_demo.py               # Scenario orchestrator
├── batch_runner.py           # Automated multi-config sweep runner
├── sitl_sim.py               # Platform simulator (→ BasePlatform)
├── live_plotter.py           # Real-time 3-panel dashboard
├── requirements.txt
├── DEMO.md                   # Step-by-step demo walkthrough
└── LICENSE
```

---

## How it works

### 1. Baseline training

The detector listens to normal platform traffic and builds two models:

* **Markov model** — learns message-ID transition probabilities.
* **Isolation Forest** — trained on 11-dimensional feature vectors extracted
  per message (rate, entropy, source diversity, Markov probability,
  inter-arrival time, and per-type frequency ratios).

### 2. Attack phase

Six attack scripts run in sequence (or individually), each injecting
malicious traffic via UDP:

| Attack | Technique | Rate |
|--------|-----------|------|
| Heartbeat flood | High-rate HEARTBEAT from rogue source | 200 msg/s |
| Ping flood | High-rate PING from rogue source | 200 msg/s |
| Param-request flood | High-rate PARAM\_REQUEST\_LIST from rogue source | 200 msg/s |
| MITM identity spoof | Forged HEARTBEAT + STATUSTEXT with trusted src\_system | 80 msg/s |
| Replay pattern | Fixed stale sequence replayed repeatedly | 120 iter/s |
| Command injection | ARM / TAKEOFF / LAND command bursts | 25 burst/s |

### 3. Detection

Every incoming message is converted to a feature vector, scored by the
Isolation Forest (0 = anomalous, 1 = normal), and tracked through a
moving-average prediction accuracy metric.  An alert fires when accuracy
drops below the configured threshold (default 0.9).

### 4. Adaptive defence

When enabled (`--defense`), messages whose anomaly score falls below the
defence threshold (default 0.3) are **blocked** before they reach the
accuracy tracker.  This creates a closed-loop feedback effect: blocking
malicious traffic causes the remaining stream to look more normal, which
makes the accuracy metric **recover** — the "rising graph" that
demonstrates active mitigation.

### 5. Classification metrics

After each run, the orchestrator computes standardised classification
metrics by comparing predictions against ground truth (attack window
timing):

| Metric | Description |
|--------|-------------|
| **Precision** | TP / (TP + FP) — how many flagged messages were actually attacks |
| **Recall** | TP / (TP + FN) — how many actual attacks were flagged |
| **F1 Score** | Harmonic mean of precision and recall |

These metrics are written to `out/scenario_results.json` and included in
`out/metrics.json`.

### 6. Visual grounding (OpenCV)

The `VisualGrounder` module provides multimodal analysis of dashboard
visualisations:

* **Dashboard frame analysis** — colour thresholding to detect red alert
  regions, purple anomaly regions, and orange defence markers
* **Anomaly spike detection** — contour analysis to count anomaly spikes
  in plot images
* **Frame comparison** — diff-based change detection between dashboard
  snapshots
* **Visual reports** — aggregated analysis of all dashboard frames

### 7. Batch sweeps

The batch runner (`batch_runner.py`) enables systematic evaluation across
multiple configurations:

* Define parameter sweeps in YAML (e.g., `configs/sweep.yaml`)
* Automatically generate all combinations (e.g., 6 attacks × 3 thresholds = 18)
* Run each configuration with optional repeats (`--repeat 3` → 54 runs)
* Produce a `comparison.csv` and `sweep_summary.json` for cross-config analysis

### 8. Live dashboard

A real-time matplotlib popup window with three panels:

* **Detection health** — moving-average accuracy with threshold line
* **Anomaly score** — per-message Isolation Forest score
* **Defence actions** — cumulative blocked message count

Attack start / end markers are drawn as vertical lines in real time.

---

## Feature vector (11 dimensions)

| # | Feature | Captures |
|---|---------|----------|
| 1 | `msg_rate` | Messages per second in a 2 s sliding window |
| 2 | `type_entropy` | Shannon entropy of the message-type distribution |
| 3 | `src_system_count` | Number of unique source systems in the window |
| 4 | `src_msg_rate` | Messages per second from the current source |
| 5 | `markov_prob` | Transition probability from the learned Markov model |
| 6 | `inter_arrival_delta` | Time elapsed since the previous message |
| 7–11 | `ratio_*` | Normalised frequency of HEARTBEAT, PING, PARAM\_REQUEST, COMMAND\_LONG, STATUSTEXT |

---

## Output artefacts

| File | Description |
|------|-------------|
| `out/metrics.json` | Detection latency, alert count, precision/recall/F1, defence stats |
| `out/scenario_results.json` | Full `ScenarioResult` metrics including classification metrics |
| `out/visual_analysis.json` | OpenCV-based visual grounding analysis of dashboard plots |
| `out/accuracy_plot.png` | 3-panel detection report (accuracy, anomaly score, defence) |
| `out/detector_accuracy.csv` | Per-message predictions with anomaly scores |
| `out/defense_adaptive.csv` | Per-message defence decisions |
| `out/live_data.jsonl` | Streaming data for the live dashboard |
| `batch_results/comparison.csv` | Cross-configuration comparison table |
| `batch_results/sweep_summary.json` | Complete batch run results |

---

## Extending the framework

### Add a new attack

1. Create `attacks/my_new_attack.py` with the standard CLI flags
   (`--udp`, `--rate`, `--duration`, `--out-dir`).
2. Add a class inheriting from `framework.BaseAttack` with `execute()` and `stop()`.
3. Register it in the `ATTACK_SCRIPTS` list in `run_demo.py`.

### Add a new defence / detector

1. Implement `framework.BaseDetector` or `framework.BaseDefense`.
2. Wire it into `detector/detector.py` alongside or in place of the
   Isolation Forest.

### Add a new platform

1. Implement `framework.BasePlatform`.
2. Create a new simulator script and point the orchestrator at it.

### Configure a batch sweep

1. Create a YAML file in `configs/` defining parameters and defaults.
2. Run `python batch_runner.py --config configs/my_sweep.yaml --repeat 3`.
3. Results appear in `batch_results/comparison.csv`.

---

## Roadmap

- [ ] Containerised execution (Docker Compose for sim + attacks + detector)
- [ ] Additional detector back-ends (autoencoder, LSTM, rule engine)
- [ ] Multi-platform support (ROS 2, CAN bus, ADS-B)
- [ ] Publication-quality LaTeX table / figure export
- [ ] CI pipeline with automated regression scenarios

---

## License

[MIT](LICENSE)
