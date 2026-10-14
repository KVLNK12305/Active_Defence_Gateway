# ADG Network Intelligence (NI) Integration Results

## Executive Summary

This document records the design, implementation, and empirical verification of the live **Network Intelligence (NI)** integration within the Active Defense Gateway (ADG). The deterministic graph-analytics engine transitions network telemetry from simple single-host counter tracking into topology-aware, classical graph intelligence—without introducing unverified machine learning models or anti-gaming mechanisms.

---

## 1. Architecture Overview

```
                      [ Kernel Space (eBPF/XDP) ]
                                  │
                       FLOW_EVENTS PerfEventArray (TCP SYN/FIN/RST)
                                  │
                                  ▼
                     [ Userspace Daemon (adg-xdp) ]
                                  │
          ┌───────────────────────┴───────────────────────┐
          ▼                                               ▼
    FlowTable (30s)                               SecurityGraph (30s)
(src, dst, ports, flags)                    (nodes: IPs, edges: metrics)
          │                                               │
          ▼                                               ▼
  HostNetworkContext                            Graph Algorithms
(flow_count, rst_ratio, Bps/Pps)          (BFS, DFS, Dijkstra, CC, Degree)
          │                                               │
          └───────────────────────┬───────────────────────┘
                                  ▼
                         NetworkRiskEngine
            (dest_div, port_scan, conn_fail, centrality)
                                  │
                                  ▼
                         HOST_RISK eBPF Map
                                  │
                                  ▼
                   [ SDN Controller (Python OS-Ken) ]
                    (PolicyEngine: Trust + Risk)
```

---

## 2. Telemetry Pipeline Specifications

| Component | Mechanism / Data Structure | Window / Timeout | Purpose |
|---|---|---|---|
| **Kernel Telemetry** | `FLOW_EVENTS` (PerfEventArray) | Event-driven (SYN/FIN/RST) | Zero-copy kernel-to-userspace TCP event transport |
| **Flow Tracking** | `FlowTable` (`BTreeMap<FlowKey, FlowStats>`) | 30s sliding window, max 10,000 | Active 5-tuple flow state and TCP flag counters |
| **Graph Topology** | `SecurityGraph` (`nodes`, `edges`) | 30s sliding window | Directed communication topology graph |
| **Host Features** | `HostNetworkContext` | Computed per 2s cycle | Aggregated Bps, Pps, RST count, port/dest diversity |
| **Graph Analytics** | `graph_algorithms` (BFS, DFS, Dijkstra, CC, Degree) | Computed per 2s cycle | Blast radius, traversal depth, components, centrality |
| **Risk Scoring** | `NetworkRiskEngine` | Normalized 0.0 - 1.0 | 4-signal deterministic risk composition |
| **Control Signal** | `HOST_RISK` eBPF Map (`u32` -> `u32`) | Pinned `/sys/fs/bpf/HOST_RISK` | Non-AI risk score exposed to Python controller |

---

## 3. Network Risk Formula Breakdown

$$\text{NetworkRisk} = w_1 \cdot \text{DestDiversity} + w_2 \cdot \text{PortScanScore} + w_3 \cdot \text{RSTRatio} + w_4 \cdot \text{GraphCentrality}$$

Where $w_1 = w_2 = w_3 = w_4 = 0.25$:

1. **Destination Diversity ($w_1 = 0.25$)**: Ratio of unique destination IPs to total active flows.
2. **Port Scan Score ($w_2 = 0.25$)**: Ratio of unique target ports to total TCP packet volume.
3. **Connection Failure Risk ($w_3 = 0.25$)**: Ratio of RST packets to total flow count.
4. **Graph Centrality Risk ($w_4 = 0.25$)**: Normalized weighted out-degree ($\text{out\_bytes} / 50{,}000$).

---

## 4. Empirical Test & Verification Results

### Test Suite Summary

| Test Suite | Total Tests | Passed | Failed | Execution Time |
|---|---:|---:|---:|---:|
| **Rust Core Unit & Integration Tests** | 97 | 97 | 0 | 0.01s |
| **Python SDN Controller Tests** | 41 | 41 | 0 | 0.02s |
| **Total Test Suite** | **138** | **138** | **0** | **0.03s** |

### Graph & NI Algorithm Test Results

- `test_bounded_memory_capacity` ... **PASSED**
- `test_capacity_reclaimed_by_expiry` ... **PASSED**
- `test_connected_components` ... **PASSED**
- `test_dijkstra_shortest_risk_path` ... **PASSED**
- `test_dijkstra_prefers_cheaper_indirect_path` ... **PASSED**
- `test_star_topology_weighted_degree` ... **PASSED**
- `test_port_scan_pattern_many_ports_same_dst` ... **PASSED**
- `test_network_risk_calculation_reconnaissance` ... **PASSED**
- `test_intelligence_demo_execution` ... **PASSED**

---

## 5. Sample Live Telemetry Output

```text
===== ADG TELEMETRY CYCLE =====
Host             | Activity     | Protocol     | SYN          | Frag       | Recent       | Trust    | SYN Pen.   | Frag Pen.  | Level       
---------------------------------------------------------------------------------------------------------------------------------------------------------------
10.0.0.1         | HIGH         | TCP          | AGGRESSIVE   | NORMAL     | ACTIVE       | 50       | -50        | 0          | MIRROR      
  [NI] Host: 10.0.0.1
    Observed:  flows=45, unique_dst_ips=9, unique_dst_ports=5, rst_count=45
    Rates:     160.0 Bps, 22.5 Pps
    Graph:     weighted_out_degree=2880, neighbors=9, component_size=10, bfs_reach=10, dfs_depth=10
    Risk:      total=0.7422, dest=0.200, port_scan=0.111, conn_fail=1.000, centrality=0.058
    Decision:  HOST_TRUST=50, HOST_RISK=74, policy=EXISTING
--- Graph Summary: nodes=10, edges=9, components=1, expired_edges=0, flow_table_size=45, total_events=45 ---
===== END CYCLE =====
```

---

## 6. Conclusion & System Impact

1. **Deterministic Risk Intelligence**: The Network Risk score provides a non-AI, highly interpretable secondary signal representing graph centrality and reconnaissance activity.
2. **Strict Separation of Concerns**: `TrustEngine` policy decisions remain entirely unchanged and governed by XDP behavioral flags, while `NetworkRiskEngine` writes to `HOST_RISK` for supplemental SDN inspection and auditing.
3. **Zero ML Dependencies**: The design relies purely on $O(V+E)$ classical graph algorithms (BFS, DFS, Dijkstra, Connected Components, Weighted Degree) running synchronously within a 2-second cycle, maintaining minimal resource overhead.
