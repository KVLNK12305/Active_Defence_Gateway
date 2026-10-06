# **Active Defense Gateway (ADG): Proactive Network Camouflage and Deception in Software-Defined Infrastructures**

## **Project Status: Phase 1 Completed (Intelligent Trust-Based SDN)**

The Active Defense Gateway has successfully completed **Phase 1** of its implementation. ADG has evolved from a theoretical framework into a fully functional, closed-loop, adaptive security system capable of high-speed telemetry, behavioral profiling, and dynamic OpenFlow enforcement.

### **Phase 1 Accomplishments**
- **Observation Plane (eBPF/XDP):** High-performance, in-kernel telemetry tracking packets, bytes, TCP/UDP/ICMP ratios, SYN floods, and **Fragmented Packet (Evasion)** anomalies.
- **Trust Engine (Rust):** A mathematically rigorous, stateless behavioral profiler that translates network telemetry into a dynamic 0-100 `HOST_TRUST` score.
- **Enforcement Plane (Python OS-Ken):** An SDN controller that polls the Trust Engine without executing heavy logic, triggering dynamic OpenFlow `FlowMod` rules.
- **Adaptive Policy States:** Hosts automatically transition between `ALLOW`, `MIRROR`, and `DROP` based on their real-time behavior, with proactive fallback and recovery capabilities.
- **Automated Evaluation Suite:** Python-based simulation scripts generating thesis-ready metrics and `matplotlib` graphs (Trust vs. Time, Telemetry Correlation).
- **Network Intelligence Layer:** Real-time event streaming (`PerfEventArray`) mapping TCP control events (`SYN`, `FIN`, `RST`) to userspace for continuous, non-blocking flow and graph analysis.
- **Proactive Risk Mitigation:** Dynamic `SecurityGraph` computing node degrees and Network Risk metrics, enforcing strict `MIRROR`/`DROP` rules on high-risk traffic.

---

## **1. Problem Statement**

The evolution of network security has reached a critical inflection point where traditional reactive measures are no longer sufficient to combat the sophistication of modern adversarial tactics. The fundamental architecture of current enterprise networks suffers from a condition known as Static Topology Persistence. In these environments, once an adversary breaches the initial perimeter defense, they encounter an internal landscape that is predictable, unchanging, and largely transparent. Servers maintain fixed IP addresses, critical services listen on standard ports, and the network graph remains consistent over long durations. This structural stability provides a significant asymmetric advantage to the attacker, who can conduct extensive reconnaissance and lateral movement with minimal risk of detection.

Internal reconnaissance is the foundational phase of the cyber kill chain. Attackers utilize automated scanning tools to map the network, identifying live hosts, open ports, and operating system versions. In a static network, the information gathered during this phase remains valid indefinitely. 

Current security solutions fail to address the simultaneous requirements for high-speed packet processing and deep architectural intelligence. Legacy firewalls operate with high performance but lack contextual awareness. Standard responses like "dropping" traffic are binary and provide zero intelligence to the defender.

There is a critical need for a system that can actively deceive attackers at wire speed, invalidating their reconnaissance data and disrupting the lateral movement process. This project proposes an Active Defense Gateway (ADG) that utilizes Software-Defined Networking (SDN) and kernel-resident eBPF programs to implement "Cognitive Network Camouflage."

## **2. Architecture Overview**

![SDN Architecture Diagram](https://raw.githubusercontent.com/ksskarthik18/Active_Defence_Gateway/main/adg_architectureDiagram.png)

### **2.1 The Three-Plane Security Model**

* **Observation Plane (eBPF/XDP):** Sitting directly on the Network Interface Card (NIC), this Rust-based eBPF program parses packet headers (including IPv4 fragmentation flags) at wire speed. It maintains a `HOST_STATS` map tracking granular behaviors like SYN ratios and fragment counts.
* **Control Plane (Rust Userspace):** The "Trust Engine" reads the telemetry, builds a `HostProfile`, and calculates a `TrustScore` (0-100). This score is pinned to a global eBPF map (`/sys/fs/bpf/HOST_TRUST`).
* **Enforcement Plane (SDN Controller):** The Python-based `OS-Ken` controller polls the pinned trust map via `ctypes`. A stateless `PolicyEngine` determines the appropriate action (`ALLOW`, `MIRROR`, `DROP`), and a `FlowInstaller` dynamically pushes high-priority OpenFlow rules to the switches.

## **3. Advanced Threat Mitigation**

The ADG evaluates traffic continuously, allowing it to adapt to complex, multi-stage attacks:

* **Volumetric SYN Floods:** Detected via anomalous TCP SYN ratios in the eBPF map. The Trust Engine applies heavy penalties, transitioning the host to a `DROP` state, triggering a hardware-offloaded OpenFlow drop rule.
* **Fragmented Packet Evasion (Teardrop / Ping of Death):** Tools like `hping3 -f` use fragmentation to bypass IDSs. ADG's eBPF parser natively detects IPv4 `More Fragments (MF)` flags and non-zero offsets, triggering an immediate 85-point trust plunge.
* **Stealth Scans:** Slow-rate attacks that do not trigger volumetric thresholds slowly degrade trust, isolating the attacker into a `MIRROR` port for IDS analysis without breaking network connectivity.
* **Gaming the System:** "Ping-Pong" attackers who pause their attacks to regain trust are countered by mathematical decay functions in the recovery algorithm.

## **4. Quick Start / Installation**

### **Prerequisites**
- Ubuntu 22.04 LTS (or compatible Linux)
- Rust Toolchain (`cargo`, `rustc`)
- Python 3.10+ with `os-ken` installed
- Mininet & Open vSwitch (OVS)

### **Compiling the eBPF Observation Plane**
```bash
cd adg-xdp
cargo build --release
sudo target/release/adg-xdp --iface <network_interface>
```
*Note: The Rust daemon must be run with `sudo` to pin the `HOST_TRUST` map to the sysfs.*

### **Running the Python Enforcement Plane**
```bash
cd controller
ryu-manager adg_controller.py
```

### **Generating Evaluation Metrics (Thesis Validation)**
An automated evaluation suite is provided to orchestrate simulated attacks and generate high-DPI `matplotlib` graphs for academic validation.
```bash
cd results
# Make sure pandas, matplotlib, and numpy are installed
python simulate_advanced_cases.py
python simulate_fragmentation.py
```

## **5. Roadmap**

- [x] **Phase 1:** Intelligent Trust-Based SDN (eBPF Telemetry, Trust Engine, Dynamic OpenFlow)
- [x] **Phase 1.5:** Live Network Intelligence (PerfEventArray Streaming, Network Risk Scoring, Dynamic Security Graph)
- [x] **Phase 2:** Multi-controller SDN (Distributed control, failover, synchronization)
- [ ] **Phase 3:** Active Deception (Honeypots, Tarpits, moving target defense logic)
- [ ] **Phase 4:** AI-assisted Trust (ML models, anomaly detection enhancements)
- [ ] **Phase 5:** Production Hardening (Scalability tests, Kubernetes deployment)

## **6. License**
Dual MIT/GPL - See individual source files for details.
