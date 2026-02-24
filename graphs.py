"""
graphs.py
---------
4 mandatory matplotlib graphs for the RSA Common Modulus Attack project.
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import time
from rsa_common_modulus import (
    generate_shared_modulus_keypairs,
    generate_rsa_keypair,
    common_modulus_attack,
)


# ─────────────────────────────────────────────────────
# Colour palette (consistent across all 4 graphs)
# ─────────────────────────────────────────────────────
RED_VULN   = "#E53935"
GREEN_SEC  = "#43A047"
BLUE_INFO  = "#1E88E5"
ORANGE_OVH = "#FB8C00"
BG_DARK    = "#1a1a2e"
BG_AX      = "#16213e"
TEXT_COLOR = "#e0e0e0"
GRID_COLOR = "#2a2a4a"


def _style_axes(ax, title: str, xlabel: str, ylabel: str):
    """Apply consistent dark-theme styling to an axes object."""
    ax.set_facecolor(BG_AX)
    ax.set_title(title, color=TEXT_COLOR, fontsize=13, fontweight="bold", pad=12)
    ax.set_xlabel(xlabel, color=TEXT_COLOR, fontsize=11)
    ax.set_ylabel(ylabel, color=TEXT_COLOR, fontsize=11)
    ax.tick_params(colors=TEXT_COLOR)
    ax.spines["bottom"].set_color(GRID_COLOR)
    ax.spines["left"].set_color(GRID_COLOR)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.grid(True, color=GRID_COLOR, linestyle="--", linewidth=0.6, alpha=0.7)


# ─────────────────────────────────────────────────────
# Graph 1 — Before / After Attack Success Rate
# ─────────────────────────────────────────────────────

def graph_before_after_success(before_rate: float, after_rate: float, fig=None):
    """
    Bar chart comparing attack success % before and after applying prevention.
    """
    if fig is None:
        fig, ax = plt.subplots(figsize=(6, 5))
    else:
        ax = fig.add_subplot(111)

    fig.patch.set_facecolor(BG_DARK)

    labels = ["Before Fix\n(Shared n)", "After Fix\n(Unique n)"]
    values = [before_rate, after_rate]
    colors = [RED_VULN, GREEN_SEC]

    bars = ax.bar(labels, values, color=colors, width=0.4, edgecolor="#ffffff22",
                  linewidth=0.8)

    for bar, val in zip(bars, values):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 1.5,
            f"{val:.1f}%",
            ha="center", va="bottom",
            color=TEXT_COLOR, fontsize=12, fontweight="bold"
        )

    ax.set_ylim(0, 115)
    _style_axes(ax, "Attack Success Rate: Before vs After Fix",
                "Condition", "Attack Success Rate (%)")

    # Reference lines
    ax.axhline(90, color=RED_VULN, linestyle="--", linewidth=1, alpha=0.5,
               label="90% threshold (vulnerable)")
    ax.axhline(2, color=GREEN_SEC, linestyle="--", linewidth=1, alpha=0.5,
               label="2% threshold (secure)")
    ax.legend(facecolor=BG_AX, edgecolor=GRID_COLOR, labelcolor=TEXT_COLOR,
              fontsize=8)

    fig.tight_layout()
    return fig


# ─────────────────────────────────────────────────────
# Graph 2 — Time vs Key Size (attack execution time)
# ─────────────────────────────────────────────────────

def _measure_attack_time(bits: int, samples: int = 3) -> float:
    """Average time (s) for generating shared-modulus keys + running the attack."""
    times = []
    for _ in range(samples):
        t0 = time.perf_counter()
        kp1, kp2 = generate_shared_modulus_keypairs(bits)
        common_modulus_attack(kp1["n"], kp2["n"])
        times.append(time.perf_counter() - t0)
    return sum(times) / len(times)


def graph_time_vs_keysize(fig=None, status_callback=None):
    """
    Line chart: average attack execution time across key sizes.
    Key sizes tested: 256, 512, 768, 1024 bits.
    """
    key_sizes = [256, 512, 768, 1024]
    times_sec = []

    for bits in key_sizes:
        if status_callback:
            status_callback(f"Measuring {bits}-bit keys…")
        avg_t = _measure_attack_time(bits, samples=3)
        times_sec.append(avg_t)

    if fig is None:
        fig, ax = plt.subplots(figsize=(6, 5))
    else:
        ax = fig.add_subplot(111)

    fig.patch.set_facecolor(BG_DARK)

    ax.plot(key_sizes, times_sec, marker="o", color=BLUE_INFO,
            linewidth=2.5, markersize=8, markerfacecolor=ORANGE_OVH,
            markeredgewidth=1.5, markeredgecolor=TEXT_COLOR)

    for x, y in zip(key_sizes, times_sec):
        ax.annotate(f"{y:.3f}s", (x, y), textcoords="offset points",
                    xytext=(6, 6), color=TEXT_COLOR, fontsize=9)

    _style_axes(ax, "Attack Execution Time vs Key Size",
                "Key Size (bits)", "Time (seconds)")

    ax.fill_between(key_sizes, times_sec, alpha=0.15, color=BLUE_INFO)
    fig.tight_layout()
    return fig, key_sizes, times_sec


# ─────────────────────────────────────────────────────
# Graph 3 — Confidentiality Rate
# ─────────────────────────────────────────────────────

def graph_confidentiality_rate(before_rate: float, after_rate: float, fig=None):
    """
    Horizontal bar chart: confidentiality = 100% - attack_success_rate.
    """
    conf_before = 100 - before_rate
    conf_after  = 100 - after_rate

    if fig is None:
        fig, ax = plt.subplots(figsize=(6, 5))
    else:
        ax = fig.add_subplot(111)

    fig.patch.set_facecolor(BG_DARK)

    labels = ["After Fix\n(Unique n)", "Before Fix\n(Shared n)"]
    values = [conf_after, conf_before]
    colors = [GREEN_SEC, RED_VULN]

    bars = ax.barh(labels, values, color=colors, height=0.35,
                   edgecolor="#ffffff22", linewidth=0.8)

    for bar, val in zip(bars, values):
        ax.text(
            min(val + 1, 102),
            bar.get_y() + bar.get_height() / 2,
            f"{val:.1f}%",
            va="center", color=TEXT_COLOR, fontsize=12, fontweight="bold"
        )

    ax.set_xlim(0, 115)
    _style_axes(ax, "Confidentiality Rate (100% − Attack Success)",
                "Confidentiality (%)", "Condition")
    ax.axvline(100, color=GREEN_SEC, linestyle="--", linewidth=1, alpha=0.5)

    fig.tight_layout()
    return fig


# ─────────────────────────────────────────────────────
# Graph 4 — Latency Overhead (key generation time)
# ─────────────────────────────────────────────────────

def _measure_keygen_time(bits: int, use_prevention: bool, samples: int = 5) -> float:
    """Average key-generation time in ms."""
    from rsa_common_modulus import generate_secure_keypair, reset_registry
    times = []
    for _ in range(samples):
        if use_prevention:
            reset_registry()
        t0 = time.perf_counter()
        if use_prevention:
            generate_secure_keypair(bits)
            generate_secure_keypair(bits)
        else:
            generate_shared_modulus_keypairs(bits)
        times.append((time.perf_counter() - t0) * 1000)   # → ms
    return sum(times) / len(times)


def graph_latency_overhead(bits: int = 512, fig=None, status_callback=None):
    """
    Grouped bar chart: key-generation latency (ms) for vulnerable vs secure setup.
    Measured at one key size; repeated 5 times for variation.
    """
    if status_callback:
        status_callback("Measuring latency overhead…")

    # 5 independent measurements for each scenario
    from rsa_common_modulus import reset_registry
    vuln_times = []
    sec_times  = []
    trials = 5

    for _ in range(trials):
        t0 = time.perf_counter()
        generate_shared_modulus_keypairs(bits)
        vuln_times.append((time.perf_counter() - t0) * 1000)

        reset_registry()
        from rsa_common_modulus import generate_secure_keypair
        t0 = time.perf_counter()
        generate_secure_keypair(bits)
        generate_secure_keypair(bits)
        sec_times.append((time.perf_counter() - t0) * 1000)
        reset_registry()

    x = np.arange(trials)
    width = 0.35

    if fig is None:
        fig, ax = plt.subplots(figsize=(6, 5))
    else:
        ax = fig.add_subplot(111)

    fig.patch.set_facecolor(BG_DARK)

    bars1 = ax.bar(x - width / 2, vuln_times, width, label="Vulnerable (shared n)",
                   color=RED_VULN, edgecolor="#ffffff22")
    bars2 = ax.bar(x + width / 2, sec_times,  width, label="Secure (unique n)",
                   color=GREEN_SEC, edgecolor="#ffffff22")

    ax.set_xticks(x)
    ax.set_xticklabels([f"Trial {i+1}" for i in range(trials)], color=TEXT_COLOR)
    _style_axes(ax, f"Key Generation Latency Overhead ({bits}-bit)",
                "Trial", "Time (ms)")

    ax.legend(facecolor=BG_AX, edgecolor=GRID_COLOR, labelcolor=TEXT_COLOR)

    # Annotate average lines
    avg_v = sum(vuln_times) / trials
    avg_s = sum(sec_times) / trials
    ax.axhline(avg_v, color=RED_VULN, linestyle="--", linewidth=1.2, alpha=0.6)
    ax.axhline(avg_s, color=GREEN_SEC, linestyle="--", linewidth=1.2, alpha=0.6)
    ax.text(trials - 0.6, avg_v + 1, f"avg {avg_v:.1f}ms",
            color=RED_VULN, fontsize=8)
    ax.text(trials - 0.6, avg_s + 1, f"avg {avg_s:.1f}ms",
            color=GREEN_SEC, fontsize=8)

    fig.tight_layout()
    return fig


# ─────────────────────────────────────────────────────
# Composite: open all 4 graphs in one window
# ─────────────────────────────────────────────────────

def show_all_graphs(before_rate: float, after_rate: float,
                    status_callback=None):
    """
    Render all 4 graphs in a 2×2 subplot figure.
    before_rate / after_rate should be percentages (0–100).
    """
    fig = plt.figure(figsize=(14, 10))
    fig.patch.set_facecolor(BG_DARK)
    fig.suptitle("RSA Common Modulus Attack — Analysis Dashboard",
                 color=TEXT_COLOR, fontsize=15, fontweight="bold", y=0.98)

    # ── Graph 1 ──
    ax1 = fig.add_subplot(2, 2, 1)
    ax1.set_facecolor(BG_AX)
    labels = ["Before Fix\n(Shared n)", "After Fix\n(Unique n)"]
    values = [before_rate, 100 - after_rate if after_rate > 0 else after_rate]
    # Slight correction: after_rate is already attack success rate (low)
    values = [before_rate, after_rate]
    colors = [RED_VULN, GREEN_SEC]
    bars = ax1.bar(labels, values, color=colors, width=0.4, edgecolor="#ffffff22")
    for bar, val in zip(bars, values):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1.5,
                 f"{val:.1f}%", ha="center", va="bottom",
                 color=TEXT_COLOR, fontsize=11, fontweight="bold")
    ax1.set_ylim(0, 115)
    ax1.axhline(90, color=RED_VULN, linestyle="--", linewidth=1, alpha=0.5)
    ax1.axhline(2, color=GREEN_SEC, linestyle="--", linewidth=1, alpha=0.5)
    _style_axes(ax1, "1. Before/After Attack Success Rate",
                "Condition", "Success Rate (%)")

    # ── Graph 2 ──
    ax2 = fig.add_subplot(2, 2, 2)
    ax2.set_facecolor(BG_AX)
    key_sizes = [256, 512, 768, 1024]
    times_sec = []
    for bits in key_sizes:
        if status_callback:
            status_callback(f"Timing {bits}-bit keys for graph 2…")
        times_sec.append(_measure_attack_time(bits, samples=2))

    ax2.plot(key_sizes, times_sec, marker="o", color=BLUE_INFO,
             linewidth=2.5, markersize=8, markerfacecolor=ORANGE_OVH,
             markeredgewidth=1.5, markeredgecolor=TEXT_COLOR)
    for x, y in zip(key_sizes, times_sec):
        ax2.annotate(f"{y:.3f}s", (x, y), textcoords="offset points",
                     xytext=(6, 6), color=TEXT_COLOR, fontsize=8)
    ax2.fill_between(key_sizes, times_sec, alpha=0.15, color=BLUE_INFO)
    _style_axes(ax2, "2. Attack Time vs Key Size",
                "Key Size (bits)", "Time (seconds)")

    # ── Graph 3 ──
    ax3 = fig.add_subplot(2, 2, 3)
    ax3.set_facecolor(BG_AX)
    conf_before = 100 - before_rate
    conf_after  = 100 - after_rate
    conf_labels = ["After Fix\n(Unique n)", "Before Fix\n(Shared n)"]
    conf_values = [conf_after, conf_before]
    conf_colors = [GREEN_SEC, RED_VULN]
    h_bars = ax3.barh(conf_labels, conf_values, color=conf_colors, height=0.35,
                      edgecolor="#ffffff22")
    for bar, val in zip(h_bars, conf_values):
        ax3.text(min(val + 1, 102), bar.get_y() + bar.get_height() / 2,
                 f"{val:.1f}%", va="center",
                 color=TEXT_COLOR, fontsize=11, fontweight="bold")
    ax3.set_xlim(0, 115)
    ax3.axvline(100, color=GREEN_SEC, linestyle="--", linewidth=1, alpha=0.5)
    _style_axes(ax3, "3. Confidentiality Rate",
                "Confidentiality (%)", "Condition")

    # ── Graph 4 ──
    ax4 = fig.add_subplot(2, 2, 4)
    ax4.set_facecolor(BG_AX)
    if status_callback:
        status_callback("Measuring latency for graph 4…")

    from rsa_common_modulus import reset_registry, generate_secure_keypair
    bits = 512
    trials = 5
    vuln_times, sec_times = [], []
    for _ in range(trials):
        t0 = time.perf_counter()
        generate_shared_modulus_keypairs(bits)
        vuln_times.append((time.perf_counter() - t0) * 1000)

        reset_registry()
        t0 = time.perf_counter()
        generate_secure_keypair(bits)
        generate_secure_keypair(bits)
        sec_times.append((time.perf_counter() - t0) * 1000)
        reset_registry()

    x = np.arange(trials)
    w = 0.35
    ax4.bar(x - w/2, vuln_times, w, label="Vulnerable", color=RED_VULN,  edgecolor="#ffffff22")
    ax4.bar(x + w/2, sec_times,  w, label="Secure",     color=GREEN_SEC, edgecolor="#ffffff22")
    ax4.set_xticks(x)
    ax4.set_xticklabels([f"T{i+1}" for i in range(trials)], color=TEXT_COLOR)
    avg_v = sum(vuln_times) / trials
    avg_s = sum(sec_times) / trials
    ax4.axhline(avg_v, color=RED_VULN, linestyle="--", linewidth=1.2, alpha=0.6)
    ax4.axhline(avg_s, color=GREEN_SEC, linestyle="--", linewidth=1.2, alpha=0.6)
    ax4.legend(facecolor=BG_AX, edgecolor=GRID_COLOR, labelcolor=TEXT_COLOR, fontsize=8)
    _style_axes(ax4, "4. Key Generation Latency Overhead (512-bit)",
                "Trial", "Time (ms)")

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plt.show()
