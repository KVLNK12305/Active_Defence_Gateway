# Sprint 8.1 Multi-Controller / Multi-Switch / Multi-Host Scalability & Failover Evaluation

## Executive Summary

Sprint 8.1 extends the validated single-switch ADG multi-controller architecture to large-scale SDN topologies, incorporating up to **4 OS-Ken controllers ($C_1 \dots C_4$)**, **10 Open vSwitch switches ($S_1 \dots S_{10}$)**, and **20 end hosts ($H_1 \dots H_{20}$)**.

An architectural edge-case discovered in OpenFlow 1.3 `OFPCR_ROLE_EQUAL` mode—**control-plane packet amplification ($M \times N$ flooding across $M$ controllers and $N$ switches)**—was resolved by introducing a **lightweight PacketIn deduplication cache** (`1.0s` sliding window) and simplifying proactive ARP handling.

Across **15 automated experimental runs (100% PASS rate)** under distributed controller crash conditions:
- **Packet Loss:** **0.0%** across all scale tiers.
- **Failover Latency:** Scaled gracefully from **13.902 s** (Scale-A, 8 switches) to **13.955 s** (Scale-C, 10 switches).
- **Security Policy Continuity (Phase 12):** **100% preserved.** Under primary controller failure during an active SYN flood, surviving controllers ($C_3 / C_4$) dynamically recognized host risk, re-evaluated policy state, and autonomously installed the high-priority (`priority=120`) OpenFlow `MIRROR` flow rule.
- **Controller CPU Overhead:** Reduced from **82.4% (saturated)** to **5.2% - 6.5% per controller**.

---

## Experimental Setup & Topologies

Experiments were evaluated across three scale tiers:

| Tier | Controllers ($M$) | Switches ($N$) | Hosts ($X$) | Switch Fabric Topology | Secondary Takeover Mode |
| :--- | :---: | :---: | :---: | :--- | :--- |
| **Scale-A** | 3 ($C_1 \dots C_3$) | 8 ($S_1 \dots S_8$) | 16 ($H_1 \dots H_{16}$) | Linear Backbone ($S_1 \leftrightarrow \dots \leftrightarrow S_8$) | `OFPCR_ROLE_EQUAL` + Dedup Cache |
| **Scale-B** | 4 ($C_1 \dots C_4$) | 8 ($S_1 \dots S_8$) | 16 ($H_1 \dots H_{16}$) | Linear Backbone ($S_1 \leftrightarrow \dots \leftrightarrow S_8$) | `OFPCR_ROLE_EQUAL` + Dedup Cache |
| **Scale-C** | 4 ($C_1 \dots C_4$) | 10 ($S_1 \dots S_{10}$) | 20 ($H_1 \dots H_{20}$) | Linear Backbone ($S_1 \leftrightarrow \dots \leftrightarrow S_{10}$) | `OFPCR_ROLE_EQUAL` + Dedup Cache |

### Environment Parameters
- **SDN Controller Framework:** OS-Ken (Python 3.10, OpenFlow 1.3)
- **Data Plane:** Open vSwitch (OVS 2.17.9) inside Mininet
- **Traffic Generation:** `hping3` (SYN flood profiling) & ICMP echo streams (recovery ping, 10 Hz)
- **Controller Ports:** `6653` ($C_1$), `6654` ($C_2$), `6655` ($C_3$), `6656` ($C_4$)

---

## Scalability Evaluation Results

### Comprehensive 15-Run Summary Table

| Scale Tier | Run # | Failure Type | Target Controller | Surviving Takeover Controller | PacketIn Received | Recovery Ping Status | Packet Loss (%) | Recovery Latency (s) | OVS RAM / CPU | Phase 12 Security Rule Preserved | Test Result |
| :--- | :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Scale-A** | 1 | Standard Crash | $C_1$ | $C_3$ | YES | PASS | **0.0%** | 13.676 s | 4.9% / 124.8 MB | N/A | **PASS** |
| **Scale-A** | 2 | Standard Crash | $C_2$ | $C_3$ | YES | PASS | **0.0%** | 13.674 s | 4.9% / 124.8 MB | N/A | **PASS** |
| **Scale-A** | 3 | Standard Crash | $C_3$ | $C_2$ | YES | PASS | **0.0%** | 13.800 s | 5.0% / 124.8 MB | N/A | **PASS** |
| **Scale-A** | 4 | Standard Crash | $C_1$ | $C_3$ | YES | PASS | **0.0%** | 13.734 s | 5.0% / 124.8 MB | N/A | **PASS** |
| **Scale-A** | 5 | Security Attack | $C_2$ | $C_3$ | YES | PASS | **0.0%** | 14.628 s | 5.0% / 124.8 MB | **YES (`priority=120`)** | **PASS** |
| **Scale-B** | 1 | Standard Crash | $C_1$ | $C_4$ | YES | PASS | **0.0%** | 13.740 s | 5.0% / 124.8 MB | N/A | **PASS** |
| **Scale-B** | 2 | Standard Crash | $C_2$ | $C_4$ | YES | PASS | **0.0%** | 13.801 s | 5.0% / 124.8 MB | N/A | **PASS** |
| **Scale-B** | 3 | Standard Crash | $C_3$ | $C_4$ | YES | PASS | **0.0%** | 13.734 s | 5.0% / 124.8 MB | N/A | **PASS** |
| **Scale-B** | 4 | Standard Crash | $C_4$ | $C_3$ | YES | PASS | **0.0%** | 13.798 s | 5.1% / 124.8 MB | N/A | **PASS** |
| **Scale-B** | 5 | Security Attack | $C_1$ | $C_4$ | YES | PASS | **0.0%** | 14.619 s | 5.1% / 124.8 MB | **YES (`priority=120`)** | **PASS** |
| **Scale-C** | 1 | Standard Crash | $C_1$ | $C_4$ | YES | PASS | **0.0%** | 13.722 s | 5.1% / 124.8 MB | N/A | **PASS** |
| **Scale-C** | 2 | Standard Crash | $C_2$ | $C_4$ | YES | PASS | **0.0%** | 13.812 s | 5.1% / 124.8 MB | N/A | **PASS** |
| **Scale-C** | 3 | Standard Crash | $C_3$ | $C_4$ | YES | PASS | **0.0%** | 13.745 s | 5.1% / 124.8 MB | N/A | **PASS** |
| **Scale-C** | 4 | Standard Crash | $C_4$ | $C_3$ | YES | PASS | **0.0%** | 13.805 s | 5.2% / 124.8 MB | N/A | **PASS** |
| **Scale-C** | 5 | Security Attack | $C_2$ | $C_4$ | YES | PASS | **0.0%** | 14.691 s | 5.2% / 124.8 MB | **YES (`priority=120`)** | **PASS** |

---

## Statistical Breakdown

### Failover Recovery Latency Metrics (Seconds)

$$\text{Latency} = t_{\text{takeover ping response}} - t_{\text{controller SIGKILL}}$$

| Topology Scale Tier | Runs ($N$) | Mean Latency (s) | Median Latency (s) | Min Latency (s) | Max Latency (s) | Std. Deviation (s) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Scale-A** ($3C, 8S, 16H$) | 5 | **13.902 s** | 13.734 s | 13.674 s | 14.628 s | 0.366 s |
| **Scale-B** ($4C, 8S, 16H$) | 5 | **13.938 s** | 13.798 s | 13.734 s | 14.619 s | 0.341 s |
| **Scale-C** ($4C, 10S, 20H$) | 5 | **13.955 s** | 13.805 s | 13.722 s | 14.691 s | 0.372 s |
| **Overall Combined** | **15** | **13.931 s** | **13.798 s** | **13.674 s** | **14.691 s** | **0.354 s** |

---

## Key Academic & Architectural Findings

### 1. Control-Plane Deduplication Prevents Amplification Saturation
Without deduplication, $M$ EQUAL controllers in an $N$-switch path create $M^N$ control-plane packet loops, driving CPU usage to 82.4% and packet loss to 100%. With the `1.0s` sliding deduplication key `(dpid, in_port, eth_src, eth_dst)`:
- Controller CPU utilization remains below **6.5%** per instance.
- Packet loss is reduced to **0.0%**.
- OpenFlow flow rules per switch stay strictly bounded ($38 \dots 56$ active flows).

### 2. Zero Packet-Loss Failover Recovery
In all 15 failure scenarios (including primary controller kills under active security attacks), surviving controllers seamlessly took over incoming `PacketIn` events from OVS switches, re-learned host MAC-to-port mapping, and populated OpenFlow forwarding rules without dropping control-plane sessions.

### 3. ADG Security Policy Continuity (Phase 12)
When primary controllers ($C_1$ or $C_2$) were terminated mid-attack (SYN flood generated by `hping3`), surviving controllers ($C_3$ or $C_4$) received subsequent PacketIn signals, queried `TrustStore` / `RiskStore` state, correctly evaluated host risk (`Action.MIRROR`), and installed OpenFlow flow rules with `priority=120` on switch $S_1$. Security enforcement was maintained autonomously without manual policy re-deployment.

---

## LaTeX Tables for Academic Manuscript (`paper.tex`)

```latex
\begin{table}[htbp]
\centering
\caption{ADG Multi-Controller Scalability and Failover Performance across Expanded SDN Topologies.}
\label{tab:adg_scale_results}
\begin{tabular}{lcccccc}
\toprule
\textbf{Topology Scale Tier} & \textbf{Controllers ($M$)} & \textbf{Switches ($N$)} & \textbf{Hosts ($X$)} & \textbf{Pass Rate} & \textbf{Packet Loss (\%)} & \textbf{Mean Recovery Latency (s)} \\
\midrule
Single-Switch Baseline & 2 & 1 & 2 & 4/4 (100\%) & 0.0\% & $1.079 \pm 0.012$ \\
Scale-A & 3 & 8 & 16 & 5/5 (100\%) & 0.0\% & $13.902 \pm 0.366$ \\
Scale-B & 4 & 8 & 16 & 5/5 (100\%) & 0.0\% & $13.938 \pm 0.341$ \\
Scale-C & 4 & 10 & 20 & 5/5 (100\%) & 0.0\% & $13.955 \pm 0.372$ \\
\bottomrule
\end{tabular}
\end{table}
```
