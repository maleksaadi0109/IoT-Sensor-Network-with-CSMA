# IoT Sensor Network — CSMA Star Topology
### NS-3 Network Simulation & Sybil Attack Research

A simulation of an IoT sensor network where multiple sensor nodes share a single CSMA bus to send data to a central gateway. Includes a **Sybil attack simulation** with a built-in **Intrusion Detection System (IDS)** for security research.

> **Note:** This repository contains simulation source files only. To run them, you need ns-3 **3.48** installed on your own machine.

---

## Repository Files

| File | Description |
|------|-------------|
| `iot-csma-star.cc` | **Baseline** — clean star topology, no attack |
| `iot-sybil-attack.cc` | **Sybil attack** — adds attacker nodes + IDS |
| `run-sybil-experiments.sh` | Batch runner for all experiment sweeps |
| `plot-results.py` | Publication-quality figure generator |

---

## What This Simulates

### Baseline (iot-csma-star.cc)

```
  Sensor 0 ──┐
  Sensor 1 ──┤
  Sensor 2 ──┼──[ CSMA Shared Bus ]──── Gateway (sink)
  Sensor 3 ──┤
  Sensor 4 ──┘
```

### Sybil Attack (iot-sybil-attack.cc)

```
  Sensor 0 ──┐                              ┌─ Sybil ID 0
  Sensor 1 ──┤                              ├─ Sybil ID 1
  Sensor 2 ──┼──[ CSMA Shared Bus ]──┬── Gateway (sink + IDS)
  Sensor 3 ──┤                       │      ├─ Sybil ID 2
  Sensor 4 ──┘                       │      └─ Sybil ID K
                                     │
                         One physical attacker forging K identities
```

A single malicious device creates **K fake identities** (each with a unique IP/MAC), flooding the shared channel. The gateway runs a **threshold-based IDS** that monitors per-source packet rates and flags suspicious nodes.

---

## What You Need Before Running

- A Linux machine (Ubuntu 20.04+ recommended)
- **ns-3 version 3.48**
- Python 3.8+ with `matplotlib`, `pandas`, `numpy`, `seaborn` (for plotting)
- NetAnim — optional, for visual animation
- Wireshark — optional, for packet inspection

### Install ns-3

```bash
git clone https://gitlab.com/nsnam/ns-3-dev.git ~/ns-3
cd ~/ns-3
git checkout ns-3.48
./ns3 configure --enable-examples --enable-tests
./ns3 build
```

---

## Quick Start — Baseline

```bash
cp iot-csma-star.cc ~/ns-3/scratch/
cd ~/ns-3 && ./ns3 build
./ns3 run "scratch/iot-csma-star"
```

---

## Quick Start — Sybil Attack

```bash
# 1. Copy to ns-3 scratch
cp iot-sybil-attack.cc ~/ns-3/scratch/

# 2. Build
cd ~/ns-3 && ./ns3 build

# 3. Run with default settings (5 sensors, 5 Sybil IDs, IDS enabled)
./ns3 run "scratch/iot-sybil-attack"

# 4. Customize
./ns3 run "scratch/iot-sybil-attack --numSensors=10 --numSybilIds=15 --sybilRateMulti=3.0"
```

---

## Sybil Attack Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--numSensors` | `5` | Number of legitimate IoT sensors |
| `--numSybilIds` | `5` | Number of Sybil (fake) identities |
| `--sybilRateMulti` | `2.0` | Sybil send-rate multiplier (1.0 = stealth) |
| `--attackStartTime` | `5.0` | When the attack begins (seconds) |
| `--simTime` | `60.0` | Simulation duration (seconds) |
| `--dataRate` | `100Mbps` | CSMA channel data rate |
| `--channelDelay` | `1ms` | Propagation delay |
| `--packetSize` | `64` | UDP payload size (bytes) |
| `--sendInterval` | `0.5` | Interval between sensor packets |
| `--enableIDS` | `true` | Enable intrusion detection |
| `--idsThreshold` | `3.0` | IDS alert threshold (packets/sec) |
| `--idsWindow` | `2.0` | IDS detection window (seconds) |
| `--enableNetAnim` | `true` | Generate NetAnim XML |
| `--csvFile` | `sybil-results.csv` | Output CSV filename |
| `--runNumber` | `1` | RNG run number (for reproducibility) |

---

## Example Scenarios

```bash
# Baseline: no attack (K=0) — should match iot-csma-star results
./ns3 run "scratch/iot-sybil-attack --numSybilIds=0 --simTime=20"

# Stealth attack: Sybil nodes send at normal rate
./ns3 run "scratch/iot-sybil-attack --numSybilIds=10 --sybilRateMulti=1.0"

# Aggressive attack: 5× normal rate
./ns3 run "scratch/iot-sybil-attack --numSybilIds=10 --sybilRateMulti=5.0"

# Massive attack: 20 Sybil identities
./ns3 run "scratch/iot-sybil-attack --numSybilIds=20 --sybilRateMulti=2.0"

# Tune IDS: lower threshold for higher recall
./ns3 run "scratch/iot-sybil-attack --idsThreshold=1.5 --numSybilIds=10"
```

---

## Running All Experiments

```bash
# Copy script and simulation to your ns-3 machine
cp iot-sybil-attack.cc ~/ns-3/scratch/
cp run-sybil-experiments.sh ~/ns-3/

# Build and run all experiments
cd ~/ns-3 && ./ns3 build
chmod +x run-sybil-experiments.sh
./run-sybil-experiments.sh
```

This runs **5 experiment sets** covering:
1. Sybil count sweep (K = 0, 2, 5, 10, 15, 20)
2. Rate multiplier sweep (α = 0.5, 1, 2, 5, 10)
3. IDS threshold sweep (θ = 1.0 to 10.0)
4. Network scale sweep (N = 5, 10, 15, 20, 30)
5. Full grid with multiple runs for statistical confidence

---

## Generating Figures

```bash
pip install matplotlib pandas numpy seaborn
python3 plot-results.py sybil-results.csv
```

Produces 7 publication-quality figures:

| Figure | Description |
|--------|-------------|
| `fig1_pdr_vs_sybil_count.png` | PDR degradation as K increases |
| `fig2_throughput_delay.png` | Throughput and delay impact |
| `fig3_ids_roc_curve.png` | IDS ROC curve across thresholds |
| `fig4_detection_latency.png` | Time to first IDS alert |
| `fig5_confusion_matrix.png` | TP/FP/TN/FN heatmap |
| `fig6_pdr_heatmap.png` | PDR across K × α grid |
| `fig7_f1_vs_rate.png` | IDS F1 score vs aggressiveness |

---

## Output Files

| File | Contents |
|------|----------|
| `sybil-results.csv` | All metrics per scenario (CSV) |
| `iot-sybil-attack.xml` | NetAnim animation |
| `iot-sybil-attack.tr` | ASCII trace log |
| `iot-sybil-gateway-0-0.pcap` | Wireshark capture at gateway |

---

## Metrics Measured

### Network Performance
- **PDR** — Packet Delivery Ratio (global, legitimate, Sybil)
- **Throughput** — Aggregate bandwidth (kbps)
- **Mean Delay** — End-to-end latency (ms)

### IDS Performance
- **TP / FP / TN / FN** — Confusion matrix
- **Precision** — TP / (TP + FP)
- **Recall** — TP / (TP + FN)
- **F1 Score** — Harmonic mean of precision and recall
- **Detection Latency** — Time from attack start to first alert

---

## Reading the Output

Live stats + IDS alerts during simulation:

```
[t=6.00s] Tx=48  Rx=45  Lost=3  LossRate=6.25%
[IDS t=7.00s]  ALERT — 192.168.1.7 flagged (4.5 pkt/s > 3.0 threshold)
[IDS t=7.00s]  ALERT — 192.168.1.8 flagged (4.5 pkt/s > 3.0 threshold)
```

Final IDS report:

```
========================================
  IDS DETECTION REPORT
========================================
  True Positives  (TP): 5
  False Positives (FP): 0
  True Negatives  (TN): 5
  False Negatives (FN): 0
  ────────────────────────────────────
  Precision : 1.0000
  Recall    : 1.0000
  F1 Score  : 1.0000
  Detection latency: 2.00 s
========================================
```

---

## License

Free to use and modify for academic and research purposes.
