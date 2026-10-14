# NI Live Validation v2 — after risk-engine fixes (re-run, 30 trials, 0 failed)

Harness unchanged (`tests/run_ni_validation_v2.py`); raw runs in `runs/`, CSVs alongside. Pre-fix evidence: `../ni_live_v2/`.

## Code changes (uncommitted; HEAD 1368ef0)
| File | Change | Defect |
|---|---|---|
| `network_risk.rs` | `port` denominator = flow events in window (`pps*FLOW_WINDOW_SECS`), no `.max(1)`; zero events -> 0 | idle zero-denominator artifact; unbounded port score |
| `network_risk.rs` | dest / port / rst each clamped to [0,1]; new const `FLOW_WINDOW_SECS=30` | unclamped components |
| `main.rs` | `FlowTable::expire(now)` every 2 s cycle (write guard); context window = 30 s instead of `delta.packets/2` | flows never expiring; nonsensical rate window |
| `network_risk.rs` tests | +2 regression tests (idle host, clamping) | - |
Not changed: weights, thresholds, PolicyEngine, trust, controller, dest `max(neighbors)` override, RST attribution (needs egress/victim-port visibility = architecture change).
Rust tests: 100/100 pass (98 + 2 new).

## Results (n=5 per config; peak HOST_RISK, trust during workload)
| cfg | before | after | components after (dest/port/rst/cent) | trust |
|---|---|---|---|---|
| A benign | 75 | 37 | 1.0/0.5/0/0.004 | 100 |
| B scan | 100 | 28-50 (mean 32.4) | 0.01/0.99/0/0.12 | 50 |
| C diversity | 50 | 26 | 1.0/0.05/0/0.02 | 100 |
| D1 closed ports | 100 | 26-37 | 0.05/1.0/0/0.02 | 50 |
| D2 abortive RST | 100 | 39-50 | 0.05-0.5/0.49/1.0/0.02 | 50 |
| F bulk | 50 | 37 | 1.0/0.5/0/0.002 | 100 (one trial 50) |
XDP event count equals pcap SYN/FIN/RST count in every run (unchanged).

## Recovery
Risk is constant while flows are inside the window and drops to 0 at ~+31 s (flow-table size 100 -> 0, edges expire at the same time). T_c (+34 s) reads risk 0 in 30/30 trials.

## Enforcement
- 0/30 trials reached risk >= 80 -> no risk-driven MIRROR occurred; every T_b/T_c decision is ALLOW (trust 100, risk 0-39). The only MIRRORs are trust-driven T_a cases (trust 50).
- The earlier "15/15 risk-driven MIRROR" came entirely from the removed artifact.
- Reaching 80 needs ~all four components near 1; rst is blind for scanned hosts and cent needs ~40 kB of control bytes, so scans top out near 0.5. The override threshold is unreachable with these workloads (design limitation; thresholds/weights untouched pending approval).

## Verdict
Defects 1-4 fixed and verified live (bounded components, decay to 0, no stale risk). Defect 5 (responder-generated RSTs invisible to the scanner) remains open (D1 rst=0). The risk-to-enforcement chain was proven mechanically pre-fix (HOST_RISK>=80 -> MIRROR -> OVS flow) but no realistic workload triggers it post-fix; an isolation test needs either an approved weight/threshold change or synthetic HOST_RISK injection.
