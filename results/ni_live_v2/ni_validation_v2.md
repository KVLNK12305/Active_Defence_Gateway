# Network Intelligence Live Validation v2

Run date: 2026-10-14. Harness: `tests/run_ni_validation_v2.py` (+ `tests/ni_v2_helpers.py`, `tests/ni_v2_reanalyze.py`, `tests/ni_v2_summarize.py`).
Raw evidence: `results/ni_live_v2/runs/<run_id>/` (30 measured runs). Derived CSVs in `results/ni_live_v2/*.csv`.

## 1. Verdict
**PASS WITH LIMITATIONS — for the mechanical chain only. NOT a validation of detection quality.**

- PROVEN (live, 15/15 trials in B, D1, D2 at triggers T_b and T_c): real traffic → XDP FLOW_EVENTS → Rust FlowTable/graph → NetworkRiskEngine → HOST_RISK=100 → Python RiskStore → PolicyEngine with **trust=100, risk=100 → MIRROR** → priority-120 `ip,nw_src=10.0.0.1 actions=NORMAL,CONTROLLER:128` present in OVS (`ovs_flows_T_*_post.txt`), traffic still forwarded (ping replies received).
- NOT SOUND: the risk value that drives that decision is produced by a zero-denominator/window artifact in the risk computation, not by behaviour that the formula is meant to measure. Risk never decays, RSTs from scan targets are never counted for the scanner, and benign traffic reaches 75/100.

## 2. Repository and Environment
- HEAD `1368ef0`, branch `main`; worktree still only `M controller/adg_controller.py` (diff identical to before: dedup env switch + logger). No production file touched, nothing committed.
- Root obtained via the password supplied by the user; used for Mininet/XDP/BPF-map/tcpdump only.
- Ubuntu 22.04, kernel 6.8, Mininet + OVS (bridge `s1`, OpenFlow13), osken-manager, `adg-xdp` release binary (up to date with source), XDP attached to `s1-eth1` (verified in `ip -d link`, `xdp_link.txt`).
- Cleanup was limited to processes spawned by the harness (SIGINT/terminate on own Popen handles); no global pkill; no leftover processes or bridges afterwards.
- Preliminary artifacts (first smoke run; CSVs produced before a parser fix on `-0`/negative-zero fields) were removed as superseded; all CSVs here are re-derived offline from the raw logs by `ni_v2_reanalyze.py`.

## 3. Actual Risk Formula (source-verified, then confirmed by runtime values)
| Feature | Implementation (`network_risk.rs`, `telemetry_extensions.rs`, `main.rs`) | Observed consequence |
|---|---|---|
| total | `0.25*(dest+port+rst+cent)`, only the total is clamped to [0,1] | components exceed 1 |
| dest | `unique_dst_ips / flow_count` (0 if flows==0); `unique_dst_ips = max(flow-table dst count, graph neighbors)` | 1.0 for 1 flow/1 dst (A, F) → +0.25 for any trivial host |
| port | `unique_dst_ports / max(1, (pps*2) as u64)`, `pps = flow_table_packets / (delta.packets/2)` where `delta.packets` is ALL packets the host sent in the last 2 s cycle | **33.3 (B), up to 100 on idle cycles**: denominator collapses to 1 when the host is silent |
| rst | `rst_count / flow_count`, counted only for flows whose **source** is the host and only for packets seen at XDP ingress | 0 for scanner when target replies RST (D1); 1.05 when host itself aborts (D2) |
| cent | `clamp(weighted_out_degree/50000, 0, 1)`; wod = Σ IP total-length of SYN/FIN/RST events on edges | 1120 in C equals pcap sum 1120 (verified); `-0` printed when no edges |
| HOST_RISK | `(total*100.0) as u32` (truncation) | 0.5056 → 50 |
| Update | every 2 s for every host in HOST_STATS; never deleted | stale values persist |
| FlowTable expiry | `expire()` only runs when table is full | `flow_table_size` stays 100/20/10 at +36 s (never expires) |
| SecurityGraph expiry | `remove_expired_edges(30 s)` every cycle | edges expire at +30.0–31.7 s (verified) |
| Policy | `risk>=80 → MIRROR` before trust; background detector calls `evaluate(trust)` **without risk**, so risk only acts on PacketIn | confirmed |

## 4. Experiment Setup
Topology: s1 + h1..h14 (h1 source, h2..h11 destinations with listeners on 80 and 8001–8020, h2 also HTTP :8080 serving 1 MB, h12–h14 trigger targets). Per trial: fresh topology, daemon, controller. Sequence: start daemon → verify XDP attach + pinned maps → start controller → verify EQUAL-role handshake + table-miss flow → 4 s warm-up → workload → trigger T_a (immediately), T_b (+4 s idle), T_c (+34 s idle). Each trigger = one ICMP echo from h1 to a never-contacted host, forcing a table miss; the decision is correlated by (src IP, destination MAC, time window). Timestamps are harness-side line-arrival times (±~50 ms), not in-process stamps.

## 5. 6A — Benign baseline (A, n=5, all identical)
Traffic: 5 pings, 1 MB HTTP GET (h2:8080), 20-packet TCP exchange (h3:80). XDP events 4 = pcap 4 (2 SYN, 2 FIN).
Context: flows=2, dst_ips=2, dst_ports=2, rst=0, wod=224. Components: dest 1.000, port 2.000, rst 0, cent 0.004 → total 0.7511 → **HOST_RISK=75 at trust 100**; decisions ALLOW (risk 0 at T_a, 75 at T_b/T_c). Result: no benign false MIRROR here, but baseline is 5 points under the override threshold; a third distinct destination port (port=3.0) saturates risk. Risk 75 persists while idle.

## 6. 6B — SYN scan (B, n=5)
`connect()` scan h1→h2 ports 1–100: 100 attempted, 1 open, 98 refused, 1 timeout. XDP events 101 = pcap SYN/FIN/RST from h1 (101); 100 SYN. Peak: flows 100, dst_ips 1, dst_ports 100, **rst 0**, dest 0.01, port 33.333, rstr 0, cent 0.121 → total 1.0, HOST_RISK 100, trust 50 (AGGRESSIVE SYN). 98 RSTs exist in the pcap but come from h2 and are not attributed to h1 (`pcap_other_rst_pkts=98`). Trust-driven MIRROR at T_a in 1/5 trials (trust still 50).

## 7. 6C — Destination diversity (C, n=5)
h1 → 10 hosts :80, 30 payload packets each. Flows 10, dst_ips 10, neighbors 10, ports 1; dest 1.000, port 1.000, cent 0.022 → total 0.5056, HOST_RISK 50, trust 100; ALLOW at every trigger. Unique IPs and graph neighbors coincide here (10 = 10). Increasing diversity changes `dest` only in the ratio sense (unique/flows); 10 destinations with 1 flow each equals a single destination with 1 flow (both 1.0), so the feature is not diversity-sensitive.

## 8. 6D — TCP RST (D1/D2, n=5 each)
- D1 (20 closed ports on h2): pcap shows 19 RSTs from h2; XDP rst_count for h1 = **0** → RST feature structurally blind for the scanner (ingress-only XDP + source-attributed counting). Risk 100 comes from port-score artifact, not RST. Classification: **RST detection FAILED for responder-generated RSTs**.
- D2 (h1 aborts 20 connections with SO_LINGER 0): pcap 21 RSTs from h1; XDP rst 21 = pcap (event parity). rstr = 1.05 (>1, unclamped; RST/flows). **Verified for host-generated RSTs.**

## 9. 6E — Graph runtime validation
| Algorithm | Input (live, from pcap) | Expected | Observed | Evidence |
|---|---|---|---|---|
| Weighted degree | C: 10 edges × (SYN 60 + FIN 52 B) | 1120 | 1120 | `runs/C_t*/adg_xdp.log`, pcap IP-length sum 1120 |
| Connected components | star h1+10 dst | 11 | 11 (5/5) | ni_diversity.csv `max_comp` |
| BFS reach | same | 11 | 11 (5/5) | `max_bfs` |
| DFS visited | same | 11 | 11 (5/5) | `max_dfs` |
| Edge expiry (real 30 s window) | C: 10 edges | 10 expired at ~30 s | 10 at +31.3 s | ni_graph.csv |
| Dijkstra | — | — | **Not exercised by live loop** (only boot-time synthetic demo; cost 1.70 path h1→h5→server) | `main.rs`, `demo.rs`; no live runtime validation |
BFS/DFS only run when risk>0.3 so values are 0 on low-risk cycles.

## 10. 6F — Risk-driven end-to-end enforcement
Trigger decisions (controller `[POLICY]` log, matched to the trigger packet; source `ni_e2e.csv`):
| cfg | trigger | trust | risk | decision | n | class |
|---|---|---|---|---|---|---|
| B,D1,D2 | T_b (+4 s) | 100 | 100 | MIRROR (prio 120) | 15 | **RISK_DRIVEN** |
| B,D1,D2 | T_c (+34 s) | 100 | 100 | MIRROR (prio 120) | 15 | **RISK_DRIVEN** |
| A | T_b/T_c | 100 | 75 | ALLOW | 10 | control (below 80) |
| A,B,C,D1,D2,F | T_a | 100 | 0 | ALLOW | 24 | control (risk map not yet updated) |
| B,C,D1,D2 | T_a | 50 | 0–100 | MIRROR | 6 | TRUST_DRIVEN (confounded) |
| C,F | T_b/T_c | 100 | 50 | ALLOW | 20 | control |
Chain evidence per stage:
1. Real traffic: pcap `s1-eth1.pcap`. 2. FLOW_EVENTS: `xdp_events` = pcap SYN/FIN/RST count in every run. 3. Rust state & risk: `adg_xdp.log` NI blocks. 4. HOST_RISK: `maps_poll.csv` (harness read of pinned map) and `HOST_RISK=` log field. 5. Controller read: controller.log `Risk : 100`. 6. Decision: `Decision : MIRROR / Priority : 120` with trust 100. 7. FlowMod/OVS: `ovs_flows_T_b_post.txt` shows new `priority=120,ip,nw_src=10.0.0.1 actions=NORMAL,CONTROLLER:128` absent in `_pre`. 8. Dataplane: ping reply received (traffic forwarded, mirrored copies to controller). No OpenFlow-message capture was possible (NXST flow-monitor rejected by OF1.3-only bridge: `OFPBRC_BAD_VERSION`), so FlowMod issuance is inferred from flow-table appearance; no per-stage latency claims are made. PacketIn arrives 2.8–60.9 ms after the trigger packet (n=90).
Timing stages T1–T5 (event, recompute, map write, read) are not independently instrumented; only the 2 s recompute cadence is observable: T_a (immediately after the workload) read risk 0 in 24 of 30 trials (stale; the other 6 had trust 50), and risk became visible within the next 2 s cycle.

**Isolation caveat (decisive):** during active traffic no trial produced risk ≥80 with trust ≥70 (A peaks 75; B/D peak 100 only at trust 50). The risk-driven MIRRORs occur only on **idle** cycles where `delta.packets==0` makes `port = ports/1`, i.e. risk 100 is an artifact of a zero denominator after the host stops sending. A single packet in the cycle (the trigger ping itself) drops the next value to 6–31. So the risk-only enforcement path works, but it is driven by an artifact and is non-monotonic.

## 11. 6G — Recovery (all 30 runs, `ni_recovery.csv`)
- Risk does **not** decay: while idle HOST_RISK stays at its peak (A 75, B/D1/D2 100, C 50, F 50) through +34 s. FlowTable entries never expire (size unchanged at +36 s). Only SecurityGraph edges expire (+30–32 s) and this does not affect the risk value.
- Trust does recover (50→100 within ~2–4 s of silence), so after recovery trust 100 + stale risk 100 → MIRROR persists. MIRROR at T_c (+34 s) in 15/15 B/D1/D2 trials; no ALLOW recovery was observed.
- Single-packet probes make risk fall transiently (e.g. 100→6, 100→9) then return to 100, so recovery is also unobservable by naive polling.

## 12. Trial Statistics
All 30 trials status OK (0 failed, 0 discarded); every metric listed above had sd = 0 across the 5 trials of its config except D1 `peak_port` (5–6.67, sd 0.82) — outcomes are deterministic under this synthetic workload. The preliminary smoke run is not counted (removed as superseded). n=5 per config, single topology, single host observed.

## 13. Risk Formula and Policy Semantics — defects found (not patched)
1. Zero-denominator artifact: idle host with non-empty FlowTable → port score = unique_ports (≥ 4 saturates total) → HOST_RISK 100 indefinitely.
2. `port_scan` denominator mixes flow-table events with total host packets of the last cycle (`delta.packets`), so it is not a ratio of anything defined and is unbounded (33.3 observed).
3. Component values are not clamped (rstr 1.05, port 33.3); a single component can decide the total.
4. FlowTable never expires entries unless full → stale risk.
5. RSTs are attributed to the sender and only observed at the XDP ingress port → scanned-host RSTs never reach the scanner's `rst_count`.
6. `dest` is 1.0 for any single-flow host (+25 baseline), indistinguishable from diversity.
7. Risk override precedence (risk≥80 → MIRROR over DROP-range trust) unchanged; the background detector ignores risk.
8. Cosmetic: `weighted_out_degree=-0`, `centrality=-0.000` printed (negative zero from in−out subtraction).
A separate explicit approval is required before any correction; none was applied.

## 14. Evidence Matrix
| Stage | Evidence file |
|---|---|
| Traffic generated | `runs/*/meta.json` (workload JSON), `s1-eth1.pcap` |
| FLOW_EVENTS | `adg_xdp.log` (`total_events`), `ni_*.csv:xdp_events` vs `pcap_h1_syn_fin_rst_pkts` |
| FlowTable/context | `adg_xdp.log` `[NI] Observed:` |
| Graph | `adg_xdp.log` `Graph:`, `ni_graph.csv` |
| Risk | `adg_xdp.log` `Risk:`; `ni_*.csv` peak_* |
| HOST_RISK | `maps_poll.csv`, `HOST_RISK=` |
| Controller read/decision | `controller.log`, `ni_e2e.csv` |
| OVS flow | `ovs_flows_T_{a,b,c}_{pre,post}.txt`, `ovs_flows_after.txt` |
| Dataplane | `ni_e2e.csv:reply` |

## 15. Failures and Limitations
- OpenFlow FlowMod messages not captured (see §10); no per-stage latency.
- XDP sees only h1's ingress; other hosts invisible; single switch, single source.
- Dijkstra not live-validated.
- Synthetic traffic; no external or real attack tooling; n=5.
- Timestamps are file-arrival based.

## 16. Paper-Defensible Claims
- The pipeline XDP → perf events → userspace graph/flow state → HOST_RISK pinned map → OS-Ken policy → OVS flow rule is implemented and exercised live (event counts match pcap exactly; weighted degree matches pcap bytes; graph BFS/DFS/CC match topology).
- A risk value ≥80 stored by the Rust daemon causes the controller to install a priority-120 MIRROR rule for a host whose trust is 100 (15/15 trials), while a value of 75 does not.
- Host-generated RSTs are observed 1:1 by the consumer (D2).
- SecurityGraph edges expire after the 30 s window.

## 17. Claims That Must Not Be Made
- That the risk score detects scans, diversity, or RST failures (risk 100 is an artifact; RSTs from scanned hosts are not counted).
- That risk recovers or decays; that Dijkstra was validated live; that benign traffic yields low risk (75 observed).
- Latency of any stage of the NI-to-OVS chain; FlowMod capture.
- That risk-driven enforcement was demonstrated under attack conditions (it appears only in idle cycles after traffic).
- Any earlier claim from `sprint8_ni_validation.md` (risk 100/31/100 per experiment): not reproduced.

## 18. Recommended Follow-Up
1. Obtain explicit approval to fix the formula defects (§13 items 1–5) and re-run this harness unchanged (it is the regression test).
2. Decide risk/trust precedence and make the detector risk-aware.
3. Add OpenFlow message capture (e.g. OF1.3-capable tooling) for FlowMod timestamps.
4. Then reconcile paper §NI to §16/§17.
