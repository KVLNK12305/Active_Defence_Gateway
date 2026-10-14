# Risk Threshold (80) — Documented Limitation

Status: threshold and weights **unchanged** (`PolicyConfig.RISK_MIRROR = 80`, four components × 0.25). No post-hoc tuning.

## Evidence (`ni_live_v2_fixed/`, post-fix engine, n=5 per config)
Peak per-trial values (min–max across trials):

| cfg | label | HOST_RISK | dest | port | rst | cent | min trust |
|---|---|---|---|---|---|---|---|
| A | benign | 37 | 1.0 | 0.5 | 0 | 0.004 | 100 |
| F | benign bulk | 37 | 1.0 | 0.5 | 0 | 0.002 | 50–100 |
| C | dest diversity | 26 | 1.0 | 0.05 | 0 | 0.022 | 100 |
| B | SYN scan | 28–50 | 0.01–1.0 | 0.99–1.0 | 0 | 0.001–0.121 | 50 |
| D1 | scan, closed ports | 26–37 | 0.05–0.5 | 1.0 | 0 | 0.002–0.024 | 50 |
| D2 | abortive RST | 39–50 | 0.05–0.5 | 0.49–0.5 | 1.0 | 0.004–0.046 | 50 |

Max observed HOST_RISK = 50; 0/30 trials reached 80.

## Why the threshold is unreachable — and why lowering it is not justified
1. **No separation between benign and attack.** Benign A/F (37) score *higher* than typical scans B/D1 (26–28). Any threshold that catches B would also flag benign traffic.
2. **`dest` saturates on tiny samples.** `unique_dst_ips / flow_count` = 1.0 for a benign host with 2 flows to 2 hosts. It measures sample size, not behaviour.
3. **`rst` is blind for scanners** (D1 rst = 0): responder RSTs aren't attributed to the scanner. This is an architecture limitation (needs egress/victim-side visibility).
4. **`cent` stays near 0** with these workloads (needs ~40 kB weighted out-degree for 1.0).
5. In practice, enforcement on these workloads came from **trust** (scans drop trust to 50 → MIRROR), not risk.

The enforcement path itself (HOST_RISK ≥ 80 → MIRROR → OVS priority-120 flow) is verified separately with injected values: `risk_enforcement_isolation/`.

## Required before any tuning
1. **Labelled baseline:** a benign corpus (varied flow counts, multi-host, long-lived sessions) and an attack corpus (SYN/connect/stealth scans at several rates, sweeps, RST-heavy), each with ≥5 trials and persisted raw logs.
2. **Inspect per-component distributions** per label (benign vs attack), including small-sample behaviour of `dest` (e.g. minimum flow count before scoring).
3. **Tune on one dataset, evaluate on a separate held-out dataset**; report TPR/FPR at the chosen threshold, not just a single triggering run.
4. Change weights/threshold only if the held-out evidence supports it. Record the change and its rationale.

## Paper wording
State that risk-driven enforcement is implemented and mechanically verified, that the current scoring does not separate benign from attack traffic on the tested workloads, and that the threshold is not reached by realistic traffic.
