# IoT Sensor Network — CSMA Star Topology
### NS-3 Network Simulation

A simulation of an IoT sensor network where multiple sensor nodes share a single CSMA bus to send data to a central gateway. Packet loss increases as more sensors compete for the same channel.

> **Note:** This repository contains only the simulation source file `iot-csma-star.cc`. To run it, you need to have ns-3 installed on your own machine.

---

## What This Simulates

```
  Sensor 0 ──┐
  Sensor 1 ──┤
  Sensor 2 ──┼──[ CSMA Shared Bus ]──── Gateway (sink)
  Sensor 3 ──┤
  Sensor 4 ──┘
```

Every sensor wakes up periodically, sends a UDP packet to the gateway, then sleeps. Since they all share one channel, collisions happen — and you can measure exactly how bad it gets.

---

## What You Need Before Running

This file does not include ns-3. You need to install it yourself first.

- A Linux machine (Ubuntu 20.04+ recommended)
- ns-3 version 3.35 or newer
- NetAnim — optional, for visual animation
- Wireshark — optional, for packet inspection

### Install ns-3

```bash
git clone https://gitlab.com/nsnam/ns-3-dev.git ~/ns-3
cd ~/ns-3
./ns3 configure --enable-examples --enable-tests
./ns3 build
```

---

## How to Use the File

Once ns-3 is installed:

```bash
# 1. Copy the file into ns-3's scratch folder
cp iot-csma-star.cc ~/ns-3/scratch/

# 2. Build
cd ~/ns-3
./ns3 build

# 3. Run
./ns3 run "scratch/iot-csma-star"
```

---

## Run Options

```bash
# Change number of sensors
./ns3 run "scratch/iot-csma-star --numSensors=10"

# Run longer
./ns3 run "scratch/iot-csma-star --simTime=60"

# Slow channel to force more collisions
./ns3 run "scratch/iot-csma-star --dataRate=1Mbps --numSensors=15"

# Stress test
./ns3 run "scratch/iot-csma-star --numSensors=30 --simTime=30"
```

---

## Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--numSensors` | `5` | Number of IoT sensor nodes |
| `--simTime` | `20.0` | Simulation duration in seconds |
| `--dataRate` | `100Mbps` | CSMA channel speed |
| `--channelDelay` | `1ms` | Propagation delay on the bus |
| `--packetSize` | `64` | UDP payload size in bytes |
| `--sendInterval` | `0.5` | Seconds between each sensor's transmissions |
| `--enableNetAnim` | `true` | Generate XML file for NetAnim |

---

## Output Files Generated After Running

| File | What it contains |
|------|-----------------|
| `iot-csma-star.xml` | NetAnim animation |
| `iot-csma-star.tr` | ASCII trace log |
| `iot-gateway-0-0.pcap` | Wireshark packet capture |

---

## Reading the Output

Live stats print every 2 seconds while running:

```
[t=2.00s] Tx=18  Rx=18  Lost=0   LossRate=0.00%
[t=4.00s] Tx=38  Rx=36  Lost=2   LossRate=5.26%
```

Final summary at the end:

```
========================================
  SUMMARY
========================================
  Total Tx (all sensors) : 190 pkts
  Total Rx (gateway)     : 178 pkts
  Total Lost             :  12 pkts
  Global Packet Loss     : 6.31%
  Aggregate Throughput   : 0.237 kbps
========================================
```

---

## License

Free to use and modify for academic and research purposes.
