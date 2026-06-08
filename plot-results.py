#!/usr/bin/env python3
"""
plot-results.py
---------------
Generate publication-quality figures from Sybil attack simulation results.

Usage:
    python3 plot-results.py                          # reads sybil-results.csv
    python3 plot-results.py  path/to/sybil-results.csv

Output:
    fig1_pdr_vs_sybil_count.png
    fig2_throughput_delay.png
    fig3_ids_roc_curve.png
    fig4_detection_latency.png
    fig5_confusion_matrix.png
    fig6_pdr_heatmap.png

Dependencies:
    pip install matplotlib pandas numpy seaborn
"""

import sys
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import seaborn as sns

# ── style ─────────────────────────────────────────────────────────
plt.rcParams.update({
    "figure.dpi":       150,
    "savefig.dpi":      300,
    "font.family":      "serif",
    "font.size":        11,
    "axes.titlesize":   13,
    "axes.labelsize":   12,
    "legend.fontsize":  10,
    "figure.figsize":   (7, 5),
    "axes.grid":        True,
    "grid.alpha":       0.3,
})

COLORS = {
    "legit":    "#2196F3",
    "sybil":    "#FF9800",
    "global":   "#4CAF50",
    "ids":      "#E91E63",
    "accent":   "#9C27B0",
}


def load_data(csv_path: str) -> pd.DataFrame:
    """Load and validate the CSV results."""
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} rows from {csv_path}")
    print(f"Columns: {list(df.columns)}")
    return df


# ═══════════════════════════════════════════════════════════════════
#  Figure 1 — PDR vs Number of Sybil Identities
# ═══════════════════════════════════════════════════════════════════
def fig1_pdr_vs_sybil_count(df: pd.DataFrame, outdir: str):
    """Line plot: PDR (global, legit, sybil) as K increases."""
    sub = df[(df["sybilRateMulti"] == 2.0) & (df["numSensors"] == 5)].copy()
    sub = sub.sort_values("numSybilIds")

    if sub.empty:
        print("  [SKIP] fig1: no matching data for α=2.0, N=5")
        return

    fig, ax = plt.subplots()
    ax.plot(sub["numSybilIds"], sub["globalPDR"],
            "o-", color=COLORS["global"], label="Global PDR", linewidth=2)
    ax.plot(sub["numSybilIds"], sub["legitPDR"],
            "s--", color=COLORS["legit"], label="Legitimate PDR", linewidth=2)
    ax.plot(sub["numSybilIds"], sub["sybilPDR"],
            "^:", color=COLORS["sybil"], label="Sybil PDR", linewidth=2)

    ax.set_xlabel("Number of Sybil Identities (K)")
    ax.set_ylabel("Packet Delivery Ratio (%)")
    ax.set_title("Impact of Sybil Attack on PDR\n(N=5 sensors, α=2.0×)")
    ax.legend()
    ax.set_ylim(0, 105)

    path = os.path.join(outdir, "fig1_pdr_vs_sybil_count.png")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    print(f"  Saved {path}")


# ═══════════════════════════════════════════════════════════════════
#  Figure 2 — Throughput and Delay vs Sybil Count
# ═══════════════════════════════════════════════════════════════════
def fig2_throughput_delay(df: pd.DataFrame, outdir: str):
    """Dual-axis: throughput (bars) + delay (line) vs K."""
    sub = df[(df["sybilRateMulti"] == 2.0) & (df["numSensors"] == 5)].copy()
    sub = sub.sort_values("numSybilIds")

    if sub.empty:
        print("  [SKIP] fig2: no matching data")
        return

    fig, ax1 = plt.subplots()

    x = sub["numSybilIds"].values
    width = 0.8

    bars = ax1.bar(x, sub["avgThroughputKbps"], width,
                   color=COLORS["legit"], alpha=0.7, label="Throughput")
    ax1.set_xlabel("Number of Sybil Identities (K)")
    ax1.set_ylabel("Aggregate Throughput (kbps)", color=COLORS["legit"])
    ax1.tick_params(axis="y", labelcolor=COLORS["legit"])

    ax2 = ax1.twinx()
    ax2.plot(x, sub["avgDelayMs"], "D-", color=COLORS["ids"],
             linewidth=2, markersize=6, label="Mean Delay")
    ax2.set_ylabel("Mean Delay (ms)", color=COLORS["ids"])
    ax2.tick_params(axis="y", labelcolor=COLORS["ids"])

    ax1.set_title("Throughput & Delay vs Sybil Count\n(N=5 sensors, α=2.0×)")

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper left")

    path = os.path.join(outdir, "fig2_throughput_delay.png")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    print(f"  Saved {path}")


# ═══════════════════════════════════════════════════════════════════
#  Figure 3 — IDS ROC Curve (varying threshold)
# ═══════════════════════════════════════════════════════════════════
def fig3_ids_roc_curve(df: pd.DataFrame, outdir: str):
    """ROC: TPR vs FPR across IDS threshold values."""
    sub = df[
        (df["numSybilIds"] == 10) &
        (df["numSensors"] == 5) &
        (df["sybilRateMulti"] == 2.0)
    ].copy()
    sub = sub.sort_values("idsThreshold")

    if sub.empty or len(sub) < 2:
        print("  [SKIP] fig3: not enough threshold sweep data")
        return

    fig, ax = plt.subplots()

    # Plot ROC curve
    ax.plot(sub["idsFPR"], sub["idsRecall"],
            "o-", color=COLORS["ids"], linewidth=2, markersize=8)

    # Annotate each point with its threshold
    for _, row in sub.iterrows():
        ax.annotate(f'θ={row["idsThreshold"]:.1f}',
                    (row["idsFPR"], row["idsRecall"]),
                    textcoords="offset points", xytext=(8, -5),
                    fontsize=8, color="gray")

    # Random baseline
    ax.plot([0, 1], [0, 1], "k--", alpha=0.3, label="Random (baseline)")

    ax.set_xlabel("False Positive Rate (FPR)")
    ax.set_ylabel("True Positive Rate (Recall)")
    ax.set_title("IDS ROC Curve — Threshold Sweep\n(N=5, K=10, α=2.0×)")
    ax.set_xlim(-0.05, 1.05)
    ax.set_ylim(-0.05, 1.05)
    ax.legend(loc="lower right")
    ax.set_aspect("equal")

    path = os.path.join(outdir, "fig3_ids_roc_curve.png")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    print(f"  Saved {path}")


# ═══════════════════════════════════════════════════════════════════
#  Figure 4 — Detection Latency vs Sybil Count
# ═══════════════════════════════════════════════════════════════════
def fig4_detection_latency(df: pd.DataFrame, outdir: str):
    """Bar chart: time from attack start to first IDS alert."""
    sub = df[
        (df["sybilRateMulti"] == 2.0) &
        (df["numSensors"] == 5) &
        (df["numSybilIds"] > 0) &
        (df["idsDetectionLatency"] >= 0)
    ].copy()
    sub = sub.sort_values("numSybilIds")

    if sub.empty:
        print("  [SKIP] fig4: no detection latency data")
        return

    fig, ax = plt.subplots()
    bars = ax.bar(sub["numSybilIds"].astype(str),
                  sub["idsDetectionLatency"],
                  color=COLORS["accent"], alpha=0.8, edgecolor="white")

    # Value labels on bars
    for bar_item in bars:
        h = bar_item.get_height()
        if h > 0:
            ax.text(bar_item.get_x() + bar_item.get_width() / 2, h + 0.1,
                    f"{h:.1f}s", ha="center", va="bottom", fontsize=9)

    ax.set_xlabel("Number of Sybil Identities (K)")
    ax.set_ylabel("Detection Latency (seconds)")
    ax.set_title("IDS Detection Latency vs Sybil Count\n(N=5 sensors, α=2.0×)")

    path = os.path.join(outdir, "fig4_detection_latency.png")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    print(f"  Saved {path}")


# ═══════════════════════════════════════════════════════════════════
#  Figure 5 — Confusion Matrix (single scenario)
# ═══════════════════════════════════════════════════════════════════
def fig5_confusion_matrix(df: pd.DataFrame, outdir: str):
    """Heatmap confusion matrix for the default scenario."""
    sub = df[
        (df["numSybilIds"] == 10) &
        (df["numSensors"] == 5) &
        (df["sybilRateMulti"] == 2.0) &
        (df["idsThreshold"] == 3.0)
    ]

    if sub.empty:
        print("  [SKIP] fig5: no matching scenario for confusion matrix")
        return

    row = sub.iloc[0]
    cm = np.array([
        [int(row["idsTP"]), int(row["idsFN"])],
        [int(row["idsFP"]), int(row["idsTN"])]
    ])

    fig, ax = plt.subplots(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt="d", cmap="YlOrRd",
                xticklabels=["Predicted Sybil", "Predicted Legit"],
                yticklabels=["Actual Sybil", "Actual Legit"],
                ax=ax, cbar=True, linewidths=2, linecolor="white",
                annot_kws={"size": 16, "weight": "bold"})

    ax.set_title(f"IDS Confusion Matrix\n(N=5, K=10, α=2.0×, θ=3.0)")

    path = os.path.join(outdir, "fig5_confusion_matrix.png")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    print(f"  Saved {path}")


# ═══════════════════════════════════════════════════════════════════
#  Figure 6 — PDR Heatmap (K × α grid)
# ═══════════════════════════════════════════════════════════════════
def fig6_pdr_heatmap(df: pd.DataFrame, outdir: str):
    """Heatmap showing Global PDR across K and α combinations."""
    sub = df[df["numSensors"] == 5].copy()

    if sub.empty:
        print("  [SKIP] fig6: no matching data for N=5")
        return

    # Average over multiple runs if present
    pivot = sub.groupby(["numSybilIds", "sybilRateMulti"])["globalPDR"].mean()
    pivot = pivot.unstack(level="sybilRateMulti")

    if pivot.empty or pivot.shape[0] < 2 or pivot.shape[1] < 2:
        print("  [SKIP] fig6: not enough grid data for heatmap")
        return

    fig, ax = plt.subplots(figsize=(7, 5))
    sns.heatmap(pivot, annot=True, fmt=".1f", cmap="RdYlGn",
                ax=ax, cbar_kws={"label": "PDR (%)"},
                linewidths=1, linecolor="white",
                annot_kws={"size": 11})

    ax.set_xlabel("Sybil Rate Multiplier (α)")
    ax.set_ylabel("Number of Sybil Identities (K)")
    ax.set_title("Global PDR Heatmap (N=5 sensors)")

    path = os.path.join(outdir, "fig6_pdr_heatmap.png")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    print(f"  Saved {path}")


# ═══════════════════════════════════════════════════════════════════
#  Figure 7 — IDS F1 Score vs Rate Multiplier (α)
# ═══════════════════════════════════════════════════════════════════
def fig7_f1_vs_rate(df: pd.DataFrame, outdir: str):
    """Shows how IDS F1 score changes with attacker aggressiveness."""
    sub = df[
        (df["numSybilIds"] == 10) &
        (df["numSensors"] == 5) &
        (df["idsThreshold"] == 3.0)
    ].copy()
    sub = sub.sort_values("sybilRateMulti")

    if sub.empty or len(sub) < 2:
        print("  [SKIP] fig7: not enough rate sweep data")
        return

    fig, ax = plt.subplots()
    ax.plot(sub["sybilRateMulti"], sub["idsF1"],
            "o-", color=COLORS["ids"], linewidth=2, markersize=8,
            label="F1 Score")
    ax.plot(sub["sybilRateMulti"], sub["idsPrecision"],
            "s--", color=COLORS["legit"], linewidth=1.5,
            label="Precision")
    ax.plot(sub["sybilRateMulti"], sub["idsRecall"],
            "^:", color=COLORS["sybil"], linewidth=1.5,
            label="Recall")

    ax.axvline(x=1.0, color="gray", linestyle=":", alpha=0.5,
               label="Stealth (α=1)")

    ax.set_xlabel("Sybil Rate Multiplier (α)")
    ax.set_ylabel("Score")
    ax.set_title("IDS Performance vs Attack Aggressiveness\n(N=5, K=10, θ=3.0)")
    ax.legend()
    ax.set_ylim(-0.05, 1.1)

    path = os.path.join(outdir, "fig7_f1_vs_rate.png")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    print(f"  Saved {path}")


# ═══════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════
def main():
    csv_path = sys.argv[1] if len(sys.argv) > 1 else "sybil-results.csv"
    outdir   = os.path.dirname(csv_path) or "."

    if not os.path.isfile(csv_path):
        print(f"ERROR: '{csv_path}' not found.")
        print("Run the simulation experiments first, then re-run this script.")
        sys.exit(1)

    df = load_data(csv_path)

    print("\nGenerating figures...")
    fig1_pdr_vs_sybil_count(df, outdir)
    fig2_throughput_delay(df, outdir)
    fig3_ids_roc_curve(df, outdir)
    fig4_detection_latency(df, outdir)
    fig5_confusion_matrix(df, outdir)
    fig6_pdr_heatmap(df, outdir)
    fig7_f1_vs_rate(df, outdir)

    print("\nAll figures generated successfully!")
    print(f"Output directory: {outdir}")


if __name__ == "__main__":
    main()
