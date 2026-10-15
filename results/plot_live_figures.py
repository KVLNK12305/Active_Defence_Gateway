#!/usr/bin/env python3
"""
plot_live_figures.py -- regenerate the thesis figures from recorded evidence only.

  Images/adg_architecture.png      schematic of the implemented components (no data)
  Images/live_frag_drop.png        fragmentation attack -> DROP, live acceptance run (pcap + flow samples)
  Images/live_telemetry_hold.png   heartbeat age, DROP-rule presence and controller events across a
                                   graceful restart and a SIGKILL outage (timeline.csv + controller log)
  Images/dedup_cpu_comparison.png  controller CPU with/without PacketIn dedup (cpu_benchmark_raw.csv)

Run from the repository root:  python3 results/plot_live_figures.py
Inputs are read, never modified. Needs matplotlib and tcpdump (read-only pcap parsing).
"""
import csv
import json
import re
import statistics as st
import subprocess
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

RES = Path(__file__).resolve().parent
OUT = RES / "Images"
LIVE = RES / "live_acceptance"
RESTART = LIVE / "restart_drop_20261015T012928"
SIGKILL = LIVE / "sigkill_outage_20261015T014347"
H1, H2 = "10.0.0.1", "10.0.0.2"


def pcap_times(pcap, bpf):
    out = subprocess.run(["tcpdump", "-r", str(pcap), "-nn", "-tt", bpf],
                         capture_output=True, text=True, check=True).stdout
    return [float(ln.split()[0]) for ln in out.splitlines() if ln[:1].isdigit()]


def timeline(run):
    rows = []
    with open(run / "timeline.csv") as f:
        for r in csv.DictReader(f):
            rows.append(dict(t=float(r["t"]), prio200=r["prio200"] == "True", prio120=r["prio120"] == "True",
                             state=r["hb_state"], wall_ms=int(r["hb_wall_ms"] or 0)))
    return rows


def ctrl_event(run, pattern):
    with open(run / "controller_stamped.log") as f:
        for ln in f:
            if re.search(pattern, ln):
                return float(ln.split()[0])
    return None


def hist(times, t0, t1, width):
    n = int((t1 - t0) / width) + 1
    counts = [0] * n
    for t in times:
        if t0 <= t <= t1:
            counts[int((t - t0) / width)] += 1
    return [t0 + i * width - t0 for i in range(n)], counts


def fig_frag_drop():
    ev = json.loads((RESTART / "events.json").read_text())
    t0, t1 = ev["p1_start"] - 2.0, ev["daemon1_stop"] + 2.0
    pcap = RESTART / "s1-eth1.pcap"
    frags = pcap_times(pcap, "src %s and (ip[6:2] & 0x3fff != 0)" % H1)
    reqs = pcap_times(pcap, "src %s and dst %s and icmp and icmp[0] == 8" % (H1, H2))
    reps = pcap_times(pcap, "src %s and dst %s and icmp and icmp[0] == 0" % (H2, H1))
    w = 0.5
    x, fc = hist(frags, t0, t1, w)
    _, qc = hist(reqs, t0, t1, w)
    _, pc = hist(reps, t0, t1, w)
    rows = [r for r in timeline(RESTART) if t0 <= r["t"] <= t1]

    fig, ax = plt.subplots(figsize=(7, 3.6))
    for r in rows:
        if r["prio200"]:
            ax.axvspan(r["t"] - t0 - 0.125, r["t"] - t0 + 0.125, color="#d62728", alpha=0.15, lw=0)
    ax.step(x, fc, where="post", color="#7f7f7f", label="IPv4 fragments from h1")
    ax.step(x, qc, where="post", color="#1f77b4", label="echo requests h1→h2")
    ax.step(x, pc, where="post", color="#2ca02c", lw=2, label="echo replies h2→h1")
    for key, lab in (("p1_start", "attack start"), ("drop_installed", "DROP rule observed"),
                     ("daemon1_stop", "daemon #1 stopped")):
        ax.axvline(ev[key] - t0, color="k", ls="--", lw=0.8)
        ax.text(ev[key] - t0 + 0.1, ax.get_ylim()[1] * 0.92, lab, fontsize=7, rotation=90, va="top")
    ax.set_xlabel("time [s] (0.5 s bins)")
    ax.set_ylabel("packets per bin on s1-eth1")
    ax.set_title("Live run restart_drop_20261015T012928: fragmented ICMP (ping -s 3000) -> trust 15 -> DROP\n"
                 "red shading: priority-200 nw_src=10.0.0.1 drop rule present in OVS sample", fontsize=8)
    ax.legend(fontsize=7, loc="upper center", bbox_to_anchor=(0.5, -0.2), ncol=3)
    fig.tight_layout()
    fig.savefig(OUT / "live_frag_drop.png", dpi=200)
    plt.close(fig)


def fig_telemetry_hold():
    runs = ((RESTART, "daemon1_stop", "daemon #1 stopped (SIGINT)",
             "Graceful restart: telemetry stays fresh; hold triggered by the missing host entry"),
            (SIGKILL, "daemon1_sigkill_time", "daemon #1 SIGKILL",
             "SIGKILL outage: heartbeat goes stale; daemon restarted after ~45 s"))
    events = ((r"trust HELD", "trust HELD (last valid value 15)", "#ff7f0e", "-."),
              (r"Host=10\.0\.0\.1 trust unavailable", "hold expired -> degraded DROP", "#d62728", "-"),
              (r"trust recovered", "fresh value -> ALLOW", "#2ca02c", "-"))
    fig, axes = plt.subplots(2, 1, figsize=(7, 5.6))
    for ax, (run, stop_key, stop_label, title) in zip(axes, runs):
        ev = json.loads((run / "events.json").read_text())
        tref = ev[stop_key]
        rows = [r for r in timeline(run) if r["t"] >= ev["drop_installed"] - 3]
        xs = [r["t"] - tref for r in rows]
        age = [(r["t"] - r["wall_ms"] / 1000.0) if r["wall_ms"] else float("nan") for r in rows]
        for r, xv in zip(rows, xs):
            if r["prio200"]:
                ax.axvspan(xv - 0.125, xv + 0.125, color="#d62728", alpha=0.12, lw=0)
        ax.plot(xs, age, color="#1f77b4", lw=1.2, label="heartbeat age (sample time - last heartbeat)")
        ax.axhline(5, color="#1f77b4", ls=":", lw=0.8, label="5 s freshness limit")
        ax.axvline(0, color="k", ls="--", lw=0.8, label=stop_label)
        ax.axvline(ev["daemon2_ready"] - tref, color="#9467bd", ls="--", lw=0.8, label="daemon #2 ready (new maps)")
        ax.axvline(ev["p3_start"] - tref, color="#8c564b", ls=":", lw=1.0, label="benign traffic from h1")
        for pat, lab, col, ls in events:
            t = ctrl_event(run, pat)
            if t:
                ax.axvline(t - tref, color=col, ls=ls, lw=1.1, label="controller: " + lab)
        top = max(6.0, max(a for a in age if a == a) * 1.1)
        ax.set_ylim(0, top)
        ax.set_title("%s\n(%s; red shading: DROP rule present)" % (title, run.name), fontsize=7.5)
        ax.set_ylabel("heartbeat age [s]", fontsize=8)
        ax.set_xlabel("time relative to daemon #1 stop [s]", fontsize=8)
        ax.tick_params(labelsize=7)
        ax.legend(fontsize=5.8, loc="upper right", ncol=2)
    fig.tight_layout()
    fig.savefig(OUT / "live_telemetry_hold.png", dpi=200)
    plt.close(fig)


def fig_dedup_cpu():
    rows = [r for r in csv.DictReader(open(RES / "cpu_benchmark_raw.csv")) if r["trial"] != "0"]  # trial 0 = validation
    stats = {}
    for cfg in ("DEDUP_DISABLED", "DEDUP_ENABLED"):
        rs = [r for r in rows if r["config"] == cfg]
        cpu = [float(r["per_ctl_mean_cpu"]) for r in rs]
        rate = [float(r["rate_pkt_s"]) for r in rs]
        stats[cfg] = (st.mean(cpu), st.stdev(cpu), st.mean(rate), st.stdev(rate), len(rs))
    labels = ["dedup disabled", "dedup enabled (1.0 s)"]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(7, 3))
    for ax, idx, ylab in ((a1, 0, "mean CPU per controller [%]"), (a2, 2, "logged PacketIns per second")):
        vals = [stats[c][idx] for c in stats]
        errs = [stats[c][idx + 1] for c in stats]
        bars = ax.bar(labels, vals, yerr=errs, capsize=4, color=["#d62728", "#2ca02c"])
        for b, v, e in zip(bars, vals, errs):
            ax.text(b.get_x() + b.get_width() / 2, v + e, "%.2f" % v if idx == 0 else "%.0f" % v,
                    ha="center", va="bottom", fontsize=7)
        ax.set_ylabel(ylab, fontsize=8)
        ax.tick_params(labelsize=7)
    a1.set_ylim(0, 110)
    a2.set_ylim(0, max(stats[c][2] + stats[c][3] for c in stats) * 1.12)
    n = stats["DEDUP_DISABLED"][4]
    fig.suptitle("3 EQUAL controllers, 8 OVS switches, 16 hosts; 1,000 pkt/s offered; 30 s windows; n=%d per arm\n"
                 "(mean ± s.d.; no-dedup arm saturates one core per controller)" % n, fontsize=7.5)
    fig.tight_layout()
    fig.savefig(OUT / "dedup_cpu_comparison.png", dpi=200)
    plt.close(fig)


def fig_architecture():
    """Schematic of components that exist in the code (no measured data)."""
    fig, ax = plt.subplots(figsize=(7.2, 4.1))
    ax.set_xlim(0, 100); ax.set_ylim(0, 60); ax.axis("off")

    def box(x, y, w, h, text, fc="white", ec="#222", fs=7, weight="normal", lw=1.0):
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.25,rounding_size=0.8",
                                    fc=fc, ec=ec, lw=lw))
        ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs,
                fontweight=weight, linespacing=1.3)

    def arrow(x1, y1, x2, y2, text="", tx=None, ty=None, dashed=False, rad=0.0, ha="center"):
        ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                    arrowprops=dict(arrowstyle="-|>", lw=1.0, color="#222", mutation_scale=9,
                                    linestyle=(0, (3, 2)) if dashed else "-",
                                    connectionstyle="arc3,rad=%s" % rad))
        if text:
            ax.text(tx if tx is not None else (x1 + x2) / 2, ty if ty is not None else (y1 + y2) / 2,
                    text, ha=ha, va="center", fontsize=6.4, linespacing=1.25)

    # ---- control plane ----
    ax.add_patch(FancyBboxPatch((17, 33.5), 82, 25, boxstyle="round,pad=0.3,rounding_size=1",
                                fc="#ececec", ec="#222", lw=1.2))
    ax.text(58, 55.6, "Control Plane", ha="center", va="center", fontsize=12, fontweight="bold")
    box(20, 36.5, 23, 14.5, "Rust / Aya daemon\nprofiling, trust,\nnetwork risk\n(every 2 s)", fc="#fff2cc", fs=8.4)
    box(50.5, 37.5, 17, 12.5, "Pinned eBPF maps\nHOST_TRUST\nHOST_RISK\nheartbeat file", fs=8.4)
    box(75, 36.5, 22, 14.5, "OS-Ken controller\nfreshness check\n30 s hold\npolicy reconciler", fc="#e2f0d9", fs=8.4)
    arrow(43.4, 43.7, 50.1, 43.7, "write", ty=46.2, dashed=True)
    arrow(67.9, 43.7, 74.6, 43.7, "bpf()\nread", tx=71.2, ty=47.3, dashed=True)

    # ---- data plane ----
    box(0.5, 20, 10.5, 6, "benign host", fc="#dbe9f7", fs=8)
    box(0.5, 6, 10.5, 6, "attacker", fc="#f6d5d5", fs=8)
    box(18, 11, 16, 11, "XDP hook\n(s1-eth1)\nobserve only:\nXDP_PASS", fc="#fff2cc", fs=8.4)
    box(41, 6, 19, 21, "Open vSwitch s1\n\napplies the\ncontroller's rule\nper source host", fs=8.6)
    arrow(11.2, 23, 18, 19, rad=-0.2)
    arrow(11.2, 9, 18, 13.5, rad=0.2)
    arrow(34.3, 16.5, 40.7, 16.5, "pass", tx=37.5, ty=14.4)
    arrow(26, 22.4, 26, 36.1, "HOST_STATS\nFLOW_EVENTS", tx=27.3, ty=29, dashed=True, ha="left")
    arrow(86, 36.1, 54, 27.4, "FlowMod", tx=70.5, ty=30.0, dashed=True, rad=0.1)

    # ---- outcomes: OpenFlow actions applied inside OVS ----
    ax.add_patch(FancyBboxPatch((68.5, 0.8), 30.8, 27.6, boxstyle="round,pad=0.2,rounding_size=0.8",
                                fc="none", ec="#555", lw=0.9, ls=(0, (3, 2))))
    ax.text(84, 30.0, "OVS action per host", ha="center", va="center", fontsize=8, style="italic")
    box(70, 20.5, 28, 6.5, "ALLOW\ntrust \u2265 70 and risk < 80", fc="#d9ead3", fs=8)
    box(70, 11, 28, 7, "MIRROR (prio 120)\ntrust 40\u201369, or \u2265 70 with risk \u2265 80", fc="#fde9c8", fs=7.6)
    box(70, 2, 28, 6.5, "DROP (prio 200)\ntrust < 40 or unavailable", fc="#f6d5d5", fs=8)
    arrow(60.3, 22, 69.6, 23.8, rad=-0.1)
    arrow(60.3, 16.5, 69.6, 14.5)
    arrow(60.3, 11, 69.6, 5.3, rad=0.1)
    ax.text(36, 1.8, "Data Plane", ha="center", va="center", fontsize=12, fontweight="bold")
    fig.tight_layout(pad=0.2)
    fig.savefig(OUT / "adg_architecture.png", dpi=300)
    plt.close(fig)


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    fig_architecture()
    fig_frag_drop()
    fig_telemetry_hold()
    fig_dedup_cpu()
    print("written:", sorted(p.name for p in OUT.glob("*.png")))
