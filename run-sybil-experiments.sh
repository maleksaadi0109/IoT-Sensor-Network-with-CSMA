#!/bin/bash
# ================================================================
#  run-sybil-experiments.sh
#  -------------------------
#  Batch runner for Sybil attack experiments.
#  Runs the iot-sybil-attack simulation across a sweep of:
#    K  = number of Sybil identities
#    N  = number of legitimate sensors
#    α  = Sybil send-rate multiplier
#    θ  = IDS threshold (pkt/s)
#
#  Usage:
#    chmod +x run-sybil-experiments.sh
#    ./run-sybil-experiments.sh
#
#  Prerequisite:
#    Copy iot-sybil-attack.cc to ~/ns-3/scratch/ and build first.
# ================================================================

set -e

NS3_DIR="${NS3_DIR:-$HOME/ns-3}"
SCRATCH_NAME="iot-sybil-attack"
CSV_FILE="sybil-results.csv"
SIM_TIME=60
IDS_WINDOW=2.0

# Remove old results file so header is written fresh
rm -f "${NS3_DIR}/${CSV_FILE}"

echo "============================================"
echo "  Sybil Attack — Batch Experiment Runner"
echo "============================================"
echo "NS-3 directory : ${NS3_DIR}"
echo "Output CSV     : ${CSV_FILE}"
echo ""

# ---------------------------------------------------------------
#  Experiment 1 — Impact of Sybil count  (K sweep)
#  Fixed: N=5, α=2.0, θ=3.0
# ---------------------------------------------------------------
echo ">>> Experiment 1: Sybil count sweep (K)"
for K in 0 2 5 10 15 20; do
    echo "  Running K=${K} ..."
    cd "${NS3_DIR}" && ./ns3 run "${SCRATCH_NAME} \
        --numSensors=5 \
        --numSybilIds=${K} \
        --sybilRateMulti=2.0 \
        --simTime=${SIM_TIME} \
        --enableIDS=true \
        --idsThreshold=3.0 \
        --idsWindow=${IDS_WINDOW} \
        --enableNetAnim=false \
        --csvFile=${CSV_FILE}" 2>/dev/null
done
echo "  Experiment 1 complete."
echo ""

# ---------------------------------------------------------------
#  Experiment 2 — Impact of attack aggressiveness  (α sweep)
#  Fixed: N=5, K=10, θ=3.0
# ---------------------------------------------------------------
echo ">>> Experiment 2: Rate multiplier sweep (α)"
for RATE in 0.5 1.0 2.0 5.0 10.0; do
    echo "  Running α=${RATE} ..."
    cd "${NS3_DIR}" && ./ns3 run "${SCRATCH_NAME} \
        --numSensors=5 \
        --numSybilIds=10 \
        --sybilRateMulti=${RATE} \
        --simTime=${SIM_TIME} \
        --enableIDS=true \
        --idsThreshold=3.0 \
        --idsWindow=${IDS_WINDOW} \
        --enableNetAnim=false \
        --csvFile=${CSV_FILE}" 2>/dev/null
done
echo "  Experiment 2 complete."
echo ""

# ---------------------------------------------------------------
#  Experiment 3 — IDS threshold tuning  (θ sweep)
#  Fixed: N=5, K=10, α=2.0
# ---------------------------------------------------------------
echo ">>> Experiment 3: IDS threshold sweep (θ)"
for THRESH in 1.0 1.5 2.0 3.0 4.0 5.0 8.0 10.0; do
    echo "  Running θ=${THRESH} ..."
    cd "${NS3_DIR}" && ./ns3 run "${SCRATCH_NAME} \
        --numSensors=5 \
        --numSybilIds=10 \
        --sybilRateMulti=2.0 \
        --simTime=${SIM_TIME} \
        --enableIDS=true \
        --idsThreshold=${THRESH} \
        --idsWindow=${IDS_WINDOW} \
        --enableNetAnim=false \
        --csvFile=${CSV_FILE}" 2>/dev/null
done
echo "  Experiment 3 complete."
echo ""

# ---------------------------------------------------------------
#  Experiment 4 — Network scale  (N sweep)
#  Fixed: K=10, α=2.0, θ=3.0
# ---------------------------------------------------------------
echo ">>> Experiment 4: Network scale sweep (N)"
for N in 5 10 15 20 30; do
    echo "  Running N=${N} ..."
    cd "${NS3_DIR}" && ./ns3 run "${SCRATCH_NAME} \
        --numSensors=${N} \
        --numSybilIds=10 \
        --sybilRateMulti=2.0 \
        --simTime=${SIM_TIME} \
        --enableIDS=true \
        --idsThreshold=3.0 \
        --idsWindow=${IDS_WINDOW} \
        --enableNetAnim=false \
        --csvFile=${CSV_FILE}" 2>/dev/null
done
echo "  Experiment 4 complete."
echo ""

# ---------------------------------------------------------------
#  Experiment 5 — Full grid:  K × N × α  (for heatmaps)
#  With multiple runs for statistical confidence
# ---------------------------------------------------------------
echo ">>> Experiment 5: Full parameter grid"
for K in 0 5 10 15; do
    for N in 5 10 15; do
        for RATE in 1.0 2.0 5.0; do
            for RUN in 1 2 3; do
                echo "  K=${K} N=${N} α=${RATE} run=${RUN} ..."
                cd "${NS3_DIR}" && ./ns3 run "${SCRATCH_NAME} \
                    --numSensors=${N} \
                    --numSybilIds=${K} \
                    --sybilRateMulti=${RATE} \
                    --simTime=${SIM_TIME} \
                    --enableIDS=true \
                    --idsThreshold=3.0 \
                    --idsWindow=${IDS_WINDOW} \
                    --enableNetAnim=false \
                    --csvFile=${CSV_FILE} \
                    --runNumber=${RUN}" 2>/dev/null
            done
        done
    done
done
echo "  Experiment 5 complete."
echo ""

# ---------------------------------------------------------------
#  Summary
# ---------------------------------------------------------------
TOTAL_ROWS=$(wc -l < "${NS3_DIR}/${CSV_FILE}")
echo "============================================"
echo "  ALL EXPERIMENTS COMPLETE"
echo "  Total result rows: ${TOTAL_ROWS}"
echo "  Output file      : ${NS3_DIR}/${CSV_FILE}"
echo ""
echo "  Next step: python3 plot-results.py ${NS3_DIR}/${CSV_FILE}"
echo "============================================"
