# ADG Capability Report

> Active Defense Gateway — Current vs. Future Capabilities
> Date: 2026-08-13

---

## Current Detection Capabilities

### 1. SYN Flood Detection
- **Mechanism**: XDP counts TCP SYN packets per host. Rust TrustEngine computes `syn_packets / tcp_packets` ratio per 2-second window.
- **Thresholds**: Normal (<5%), Moderate (5-20%, −20 trust), Aggressive (>20%, −50 trust).
- **Policy outcome**: ALLOW → MIRROR → DROP escalation.
- **Validated with**: `hping3 --syn --flood`, `nc -z` rapid connections.

### 2. SYN Scan Detection
- **Mechanism**: Same SYN ratio analysis. Port scans generate many SYN packets with few data packets, producing high ratios.
- **Limitation**: Cannot distinguish between SYN flood and SYN scan (both produce high SYN ratios). No destination port diversity tracking.

### 3. Fragmentation Anomaly Detection
- **Mechanism**: XDP inspects IPv4 `frag_off` field — detects More Fragments (MF) flag and non-zero fragment offset.
- **Threshold**: >5% fragmented packets → ANOMALOUS → −85 trust (immediate UNTRUSTED).
- **Validated with**: `hping3 -f` (fragmented SYN), `nmap -f` (fragmented scan).

---

## Current Prevention Capabilities

| Action | Trust Range | OpenFlow Priority | Behavior |
|--------|------------|-------------------|----------|
| **ALLOW** | ≥90 | 1 | Normal L2 forwarding |
| **LOG** | 70-89 | 1 (ALLOW + log) | Forward normally, internal log event |
| **MIRROR** | 40-69 | 120 | Forward via `OFPP_NORMAL` + copy to `OFPP_CONTROLLER` (128 bytes) |
| **DROP** | <40 | 200 | Empty action list (hardware-offloaded drop) |

### Key Architectural Strengths
- **Autonomous recovery**: Windowed delta computation means trust naturally returns to 100 when malicious traffic stops.
- **Background enforcement**: `TrustChangeDetector` polls HOST_TRUST every 2s and proactively pushes/removes OpenFlow rules without waiting for PacketIn events.
- **Multi-switch support**: Policy flows are installed across all connected datapaths.
- **EQUAL role**: Controller requests `OFPCR_ROLE_EQUAL` for multi-controller failover compatibility.

---

## Future Capabilities — Extension Roadmap

### HIGH Priority (Sprint 7)

#### Port Scan Detection
- **Requires**: Destination port tracking in `HOST_STATS`, unique port count per host.
- **Signal**: Host contacts >20 unique ports in a window → port scan signature.
- **New metric**: `unique_dst_ports / tcp_packets` ratio.

#### Lateral Movement Detection
- **Requires**: Destination IP tracking, unique destination count per host.
- **Signal**: Host contacts >10 unique internal IPs in a window → lateral movement indicator.
- **New metric**: `unique_dst_ips / total_flows` ratio (destination diversity).

#### Risk-Aware Flow Tracking
- **Requires**: Flow count (unique src_ip:src_port → dst_ip:dst_port tuples).
- **Signal**: Unusually high flow creation rate with low data volume → reconnaissance.

#### Trust History
- **Requires**: Circular buffer of recent trust scores in Rust daemon.
- **Signal**: Oscillating trust (attack-pause-attack pattern) → "gaming the system" detection.

### MEDIUM Priority (Sprint 8)

#### TCP RST Ratio
- **Requires**: RST flag extraction in XDP (already parsing `data_offset_reserved_flags`).
- **Signal**: High RST:SYN ratio → connection failures → scanning or blocked service probing.

#### Failed Connection Ratio
- **Requires**: SYN sent vs SYN-ACK received tracking.
- **Signal**: High failure rate → active reconnaissance against filtered ports.

#### Packet Size Statistics
- **Requires**: Min/max/mean packet size per host.
- **Signal**: Uniform small packets → scan. Uniform large packets → exfiltration.

#### Bandwidth Rate
- **Requires**: `bytes / time_window` computation.
- **Signal**: Sudden bandwidth spike → volumetric attack or data exfiltration.

#### Connection Duration
- **Requires**: TCP session state tracking (SYN → FIN/RST timing).
- **Signal**: Very short connections → scan. Very long → C2 beaconing.

### LOW Priority (Sprint 9+)

#### Network Graph Construction
- **Requires**: Global view of all host-to-host communication pairs.
- **Application**: Identify critical network paths, single points of failure.

#### Attack Propagation Modeling
- **Requires**: Temporal correlation of trust degradation across hosts.
- **Application**: Detect worm propagation (Host A compromised → Host A scans → Host B compromised).

#### Path Risk Scoring
- **Requires**: Graph algorithms (shortest path, centrality).
- **Application**: Risk-aware routing — steer traffic away from compromised segments.

#### WMMF Resource Control
- **Requires**: Weighted Max-Min Fairness bandwidth allocation.
- **Application**: Throttle suspicious hosts rather than binary DROP.

---

## Test Coverage Summary

| Test File | Type | What It Tests |
|-----------|------|---------------|
| `test_policy.py` | Unit | All trust→action threshold boundaries |
| `test_trust_store.py` | Unit | BPF map lookup (missing, existing, error cases) |
| `test_controller_mock.py` | Integration | PacketIn handling for ALLOW/MIRROR/DROP + EQUAL role |
| `test_escalation.py` | Integration | ALLOW→MIRROR→DROP→ALLOW full lifecycle |
| `test_trust.py` | E2E script | Real traffic generation for live trust observation |
| `test_traffic.py` | E2E script | Protocol-diverse traffic generation |
| `test_bpf.py` | Utility | Raw BPF syscall validation |
| `test_api.py` | Utility | Unix socket trust API query |
| `trust.rs::tests` | Unit (Rust) | 8 tests covering all TrustEngine compute paths |
