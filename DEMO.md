# Quick-Start Demo Guide

Reference scenario walkthrough using the MAVLink platform module with the
Isolation Forest detector, adaptive defence, and real-time dashboard.

## Overview

| Component | Description |
|-----------|-------------|
| **Simulator** (`sitl_sim.py`) | Generates normal MAVLink traffic (HEARTBEAT, PING, PARAM\_REQUEST, STATUSTEXT) |
| **Six attacks** (`attacks/`) | Heartbeat flood, Ping flood, Param-request flood, MITM identity spoof, Replay-pattern injection, Command-injection burst |
| **ML Detector** (`detector/`) | Isolation Forest trained on 11-dimensional feature vectors + Markov transition model |
| **Adaptive Defence** | Blocks messages whose anomaly score falls below a threshold -- works against *any* attack that deviates from normal, including unseen ones |
| **Live Dashboard** (`live_plotter.py`) | Three-panel real-time matplotlib window (accuracy, anomaly score, defence actions) |
| **Orchestrator** (`run_demo.py`) | Launches everything, runs attacks in sequence, writes metrics |

## Prerequisites

- Python 3.10+
- Virtual environment with dependencies installed

## One-Time Setup

```powershell
cd autonomy-evaluation-harness
python -m venv .venv
. .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Demo Commands

### Detection Only (no defence)
```powershell
python run_demo.py --mode all
```

### Detection + Adaptive ML Defence (recommended)
```powershell
python run_demo.py --mode all --defense
```

### Baseline Only (no attacks)
```powershell
python run_demo.py --mode baseline --baseline-seconds 20
```

### Custom Parameters
```powershell
python run_demo.py --mode all --defense --baseline-seconds 15 --attack-seconds 12 --attack-rate 250 --threshold 0.85 --defense-threshold 0.3
```

### Disable Live Dashboard
```powershell
python run_demo.py --mode all --defense --no-live-plot
```

### Randomized attacks (stage 3 — volatile traffic / “messy” plot)

With `--randomize-attacks` the orchestrator does **not** run one constant-rate burst per
catalogue attack. It **shuffles** attack order, draws a random **episode length** per
attack, splits each episode into **several subprocess segments** with **independent
random rates** (including deliberate slow “lulls” and short high-rate bursts), inserts
**random idle gaps** between episodes (benign traffic only), and **short pauses** between
segments. The detector’s moving-average accuracy window is **capped at 160 messages** for
these runs so the dashboard reacts visibly to load changes instead of smoothing them away.

```powershell
python run_demo.py --mode all --defense --randomize-attacks
```

Same schedule every time (for screenshots / comparison):

```powershell
python run_demo.py --mode all --defense --randomize-attacks --random-seed 42
```

Optional explicit ranges (msgs/s and seconds):

```powershell
python run_demo.py --mode all --defense --randomize-attacks --random-seed 1 --attack-rate 200 --attack-rate-min 80 --attack-rate-max 320 --attack-seconds 10 --attack-duration-min 4 --attack-duration-max 14
```

## Expected Outputs

After running, check `out/`:

| File | Description |
|------|-------------|
| `accuracy_plot.png` | 3-panel report: accuracy, anomaly score, defence timeline |
| `live_data.jsonl` | Streaming data consumed by the live dashboard |
| `detector_accuracy.csv` | Per-message prediction results with moving average + anomaly score |
| `alerts.log` | Timestamped alerts when accuracy drops below threshold |
| `metrics.json` | Detection latency, alert count, defence stats, feature list |
| `defense_adaptive.csv` | Per-message defence log (when `--defense` enabled) |
| `defense_summary.json` | Defence summary with block rates by type and source |
| `attack_*.csv` | Per-attack injection logs |
| `run_demo.log` | Timeline of demo execution |

## What to Show Professor

### Terminal Output
```
Starting simulator substitute.
Starting detector (Isolation Forest + Markov model).
Adaptive ML defence enabled  (score threshold = 0.3).
Running attack: Heartbeat flood
Running attack: Ping flood
Running attack: Param request flood
Running attack: MITM identity spoof
Running attack: Replay pattern attack
Running attack: Command injection burst
Stopping simulator substitute.
=== Adaptive Defence Report ===
  Model             : Isolation Forest (unsupervised)
  Total blocked     : 1890
  Block rate        : 59.7%
Demo complete.
```

### Key Artifacts
1. **Live dashboard window** -- real-time 3-panel plot updating during the demo
2. **accuracy_plot.png** -- saved 3-panel report showing accuracy drops + recovery
3. **metrics.json** -- detection latency, blocked counts, feature list
4. **defense_adaptive.csv** -- every blocked message with anomaly score

## Attack Details

### Heartbeat Flood
Floods MAVLink stream with HEARTBEAT messages (msg\_id=0) from src\_system=250 at 200 msg/s.

### Ping Flood
Floods with PING messages (msg\_id=4) from src\_system=251 at 200 msg/s.

### Param Request Flood
Floods with PARAM\_REQUEST\_LIST messages (msg\_id=21) from src\_system=252 at 200 msg/s.

### MITM Identity Spoof
Impersonates trusted vehicle identity (src\_system=1) and injects forged HEARTBEAT + STATUSTEXT at 80 msg/s.

### Replay Pattern Attack
Replays a fixed stale sequence (PING + PARAM\_REQUEST + STATUSTEXT) from src\_system=240 at 120 iter/s.

### Command Injection Burst
Injects ARM/DISARM, TAKEOFF, LAND commands via COMMAND\_LONG from src\_system=241 at 25 bursts/s.

## How It Works

### 1. Baseline Training
- Detector listens to normal MAVLink traffic for N seconds (default 10)
- Builds a **Markov model** of message-ID transitions
- Extracts **11-dimensional feature vectors** per message (rate, entropy, source diversity, timing, per-type ratios, Markov probability)
- Trains an **Isolation Forest** on the baseline feature vectors

### 2. Attack Period
- Attack scripts inject high-rate / malicious messages into the UDP stream
- Normal message patterns, rates, and source distributions are disrupted

### 3. ML Detection
- Each incoming message is converted to a feature vector
- The Isolation Forest scores it: **1.0 = normal, 0.0 = anomalous**
- The Markov model predicts the next message; moving-average accuracy is tracked
- Alert triggers when accuracy drops below threshold (default 0.9)

### 4. Adaptive Defence (when `--defense` is enabled)
- Messages with anomaly score **below the defence threshold** (default 0.3) are **blocked**
- Blocked messages never reach the accuracy tracker
- This causes the accuracy metric to **recover** (the "rising graph" effect)
- Works against **all attack types** including ones the system has never seen

### 5. Feature Vector (11 dimensions)

| # | Feature | What it captures |
|---|---------|-----------------|
| 1 | msg\_rate | Messages/sec in 2-second window |
| 2 | type\_entropy | Shannon entropy of message type distribution |
| 3 | src\_system\_count | Unique source systems in window |
| 4 | src\_msg\_rate | Messages/sec from this specific source |
| 5 | markov\_prob | Transition probability from Markov model |
| 6 | inter\_arrival\_delta | Time since previous message |
| 7-11 | type ratios | Normalised frequency of HEARTBEAT, PING, PARAM\_REQUEST, COMMAND\_LONG, STATUSTEXT |

## Novel Contributions

1. **Feature-engineered anomaly detection** -- goes beyond simple sequence accuracy with rate, entropy, source, and timing features
2. **Unsupervised adaptive defence** -- learns "normal" during baseline, blocks deviations without attack signatures
3. **Closed-loop feedback** -- defence blocking causes measurable accuracy recovery (the "rising graph")
4. **Generalises to unseen attacks** -- Isolation Forest is trained only on normal traffic; any deviation triggers defence

## Troubleshooting

**No plot generated**: Check `out/accuracy_plot.png` after run completes.

**Live dashboard doesn't open**: Ensure matplotlib has a GUI backend (TkAgg). Try `pip install tk`.

**No alerts in alerts.log**: Attack rate may be too low; try `--attack-rate 300`.

**Import errors**: Activate venv first: `. .venv\Scripts\Activate.ps1` then `pip install -r requirements.txt`.
