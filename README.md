# Autonomy Security Evaluation Harness

A standardised **red-team vs blue-team evaluation framework** for
AI-controlled autonomous and cyber-physical systems.

Most CPS security papers test one attack or one defence in isolation, use
ad-hoc setups, and rarely share a reusable environment.  This project fills
that gap with an engineering-grade harness that launches missions, schedules
attacks, runs defences in parallel, logs synchronised events, and
automatically computes **comparable** metrics such as detection rate, false
positives, latency, block rate, and mission impact.

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
                         out/defense_adaptive.csv
                         out/metrics.json
```

### Key design principles

| Principle | How it is realised |
|---|---|
| **Attacks are first-class modules** | Each attack is a standalone script with a uniform CLI (`--udp`, `--rate`, `--duration`, `--out-dir`). New attacks only need to implement `BaseAttack`. |
| **Defences are pluggable** | The detector and adaptive filter each implement `BaseDetector` / `BaseDefense` ABCs. Swap the Isolation Forest for a neural network or rule engine without touching the orchestrator. |
| **Synchronised logging** | The orchestrator, detector, and attacks all append to a shared `live_data.jsonl` stream with millisecond-resolution timestamps and event markers. |
| **Comparable metrics** | `framework/metrics.py` provides `ScenarioResult` — a single class that computes detection rate, false-positive rate, latency, block rate, accuracy recovery, and mission impact from raw event logs. |
| **Reproducible by default** | Fixed random seeds, deterministic baselines, configurable durations and rates. |

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

### Run with detection only

```bash
python run_demo.py --mode all
```

### Run with detection + adaptive ML defence

```bash
python run_demo.py --mode all --defense
```

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

---

## Project layout

```
.
├── framework/              # Harness abstractions & utilities
│   ├── base.py             #   ABCs: BaseAttack, BaseDefense, BaseDetector, BasePlatform
│   └── metrics.py          #   Standardised ScenarioResult metric computation
│
├── detector/               # Reference defence implementation
│   ├── detector.py         #   Main detection loop (Isolation Forest + Markov)
│   ├── feature_engine.py   #   11-dim sliding-window feature extraction
│   ├── ml_model.py         #   Isolation Forest anomaly scorer
│   └── adaptive_defense.py #   Score-threshold adaptive message filter
│
├── attacks/                # Attack catalogue (one script per vector)
│   ├── heartbeat_flood.py
│   ├── ping_flood.py
│   ├── param_request_flood.py
│   ├── mitm_identity_spoof.py
│   ├── replay_pattern_attack.py
│   └── command_injection_burst.py
│
├── run_demo.py             # Scenario orchestrator
├── sitl_sim.py             # Platform simulator (MAVLink SITL substitute)
├── live_plotter.py         # Real-time 3-panel dashboard
├── requirements.txt
├── DEMO.md                 # Step-by-step demo walkthrough
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

### 5. Live dashboard

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

## Output metrics

`out/metrics.json` contains, at minimum:

```json
{
  "detection_latency_sec": 1.23,
  "total_alerts": 3,
  "model_type": "isolation_forest",
  "total_blocked": 1890,
  "block_rate": 0.597,
  "blocked_by_msg_type": {"0": 109, "4": 1049, "21": 723},
  "blocked_by_src_system": {"250": 13, "251": 1029, "252": 709}
}
```

For cross-scenario comparison, use `framework.metrics.ScenarioResult` to
compute detection rate, false-positive rate, latency, accuracy recovery,
and mission impact from raw event logs.

---

## Extending the framework

### Add a new attack

1. Create `attacks/my_new_attack.py` with the standard CLI flags
   (`--udp`, `--rate`, `--duration`, `--out-dir`).
2. Register it in the `ATTACK_SCRIPTS` list in `run_demo.py`.
3. (Optional) Subclass `framework.BaseAttack` for IDE auto-completion
   and validation.

### Add a new defence / detector

1. Implement `framework.BaseDetector` or `framework.BaseDefense`.
2. Wire it into `detector/detector.py` alongside or in place of the
   Isolation Forest.

### Add a new platform

1. Implement `framework.BasePlatform`.
2. Create a new simulator script and point the orchestrator at it.

---

## Roadmap

- [ ] Containerised execution (Docker Compose for sim + attacks + detector)
- [ ] Scenario configuration files (YAML/TOML)
- [ ] Additional detector back-ends (autoencoder, LSTM, rule engine)
- [ ] Multi-platform support (ROS 2, CAN bus, ADS-B)
- [ ] Publication-quality LaTeX table / figure export
- [ ] CI pipeline with automated regression scenarios

---

## License

[MIT](LICENSE)
