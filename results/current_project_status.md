# ADG — Current Project Status (Repository-Evidence Audit)

Audit date: 2026-10-14. Audit-only: no production code, paper, thresholds or formulas were modified. This is the only file created.

## 1. Repository state

| Item | Finding |
|---|---|
| CWD / branch | `/home/kushal/FYP`, `main` |
| HEAD | `1368ef0 test(failover): add rigorous new-flow and continuity takeover latency experiments and results` |
| Recent commits | `2dd9afa` NI report in profiler; `9a0c376` trust comments/frag test; `f8039c5` remove REDIRECT placeholder, adjust DROP threshold; `18ae500`; `af9ee13`; `8f371a2` Sprint 8.1 dedup |
| Uncommitted | `M controller/adg_controller.py` (only change). Staged: none. |
| Content of uncommitted diff | (a) `ADG_DISABLE_DEDUP=1` env switch around the dedup cache; (b) `print()` → `logger.info()` for `[POLICY]` block; (c) a new "Not an IPv4 packet" debug log line. |
| Consequence | The CPU benchmark's DEDUP_DISABLED arm **depends on an uncommitted change**. HEAD cannot reproduce it. |
| Gitignore effects | `tests/` and `results/` were untracked in `03f6937`; only 5 result files + 2 test scripts + `paper.tex` are force-tracked. `tests/run_cpu_benchmark.py`, `tests/run_ni_validation.py`, `tests/run_sprint8_scale.py`, `results/cpu_benchmark_*`, `results/sprint8_ni_validation.md`, `results/sprint8_latency_audit.md` etc. are **not under version control**. |
| Paper | `results/paper.tex` (946 lines), last committed in `18ae500` (2026-10-06). Contains none of the CPU / trust-policy corrections. |
| Real layout | `adg-xdp/{adg-xdp,adg-xdp-common,adg-xdp-ebpf}`, `controller/{adg_controller,policy,trust,risk,flow,detector,utils}.py`, `tests/`, `results/`, `docs/`, `os-ken/`. |

## 2. Implementation audit

**A. Trust.** Rust `trust.rs` levels: 90–100 Trusted, 70–89 Normal, 40–69 Suspicious, else Untrusted. Python `PolicyEngine.evaluate`: ≥90 ALLOW, ≥70 ALLOW(log), ≥40 MIRROR, else DROP. Consistent. Missing-map: `TrustStore`/`RiskStore` reopen lazily; `RiskStore.get` returns 0 on any error (fail-open on risk); trust ENOENT handled (tests cover). `Action.REDIRECT` enum member and `priority = 150` branch still exist in code (never produced by `evaluate`) — placeholder residue.

**B. Network Intelligence.** Present and wired in `main.rs`: FLOW_EVENTS consumer → FlowTable → SecurityGraph → HostNetworkContext → `NetworkRiskEngine::compute` → `HOST_RISK` (pinned `/sys/fs/bpf/HOST_RISK`, `total*100 as u32`). Formula: equal weights 0.25 × {DestDiversity, PortScanScore, RSTRatio, min(weighted_out_degree/50000,1)}, total clamped [0,1]; zero-denominator cases covered by tests. Observations:
- `main.rs:291` overrides `unique_dst_ips` with `max(ctx, graph neighbors)` — a patch, not in paper.
- `port_scan` denominator is `packets_per_second*2` (approximate window count), not TCP packets as paper/validation doc state.
- `wmmf.rs` (Weighted Max-Min Fairness) **exists** and is exercised by `demo.rs` printed at every daemon boot; it is not part of enforcement. Paper lists WMMF as future work — wording must say "allocator module + demo only".
- Python policy: `risk >= 80 → MIRROR` overrides trust (even over DROP-range trust! trust 10 with risk 80 → MIRROR, i.e. *weaker* than DROP). Risk can never cause DROP. This precedence is a design defect worth stating in the paper or fixing deliberately.

**C. Multi-controller.** `OFPCR_ROLE_EQUAL` on switch features; 1.0 s dedup cache keyed `(dpid,in_port,src,dst)`, per-process, no shared state, no MASTER/SLAVE, no replication. Cache is checked before the MAC/IP policy path, so a first PacketIn on any controller wins.

**D. Tests (re-run this session).**
| Suite | Result | Notes |
|---|---|---|
| Rust | **98 passed, 0 failed** | `cargo test` itself needs `sudo` (configured runner); test binary was executed directly, unprivileged. 98 `#[test]` attributes match. |
| Python (`unittest discover`) | **41 passed, 0 failed** | 42 `def test_` found by grep; 41 executed (one is not a unittest test case / diagnostic). Several print "Permission denied" for BPF maps — mock/fallback paths, expected unprivileged. |
| Total | **139** | Matches historical figure. `tests/run_all_tests.py` was not executed (compiles/runs binaries; not needed). |
| Not automated | `test_api.py, test_bpf.py, test_ip.py, test_traffic.py, test_trust.py, test_mininet_setup.py` are diagnostics/live scripts; not counted. |

Mock concern: controller-mock tests print `Risk : <MagicMock>`; the risk path is not meaningfully exercised in those tests.

## 3. Experiment audit

| Claim | Artifact | Method | Reproducible? | Defensible? | Limitations |
|---|---|---|---|---|---|
| Existing-flow continuity, mean 4.113 ms, 0 loss, n=5 | `sprint8_failover_instrumented.{md,csv}` | SIGKILL C1, raw-socket sniffer on h1, ping `-i 0.01` | CSV matches md; script tracked | **Only as "no observable interruption"**. 4.1 ms is bounded by the 10 ms ping interval, not a failover time. | 2 controllers, 1 switch; `Loss = 0/0` (total_packets recorded as 0 — loss column is uninformative); PacketIn/FlowMod N/A. |
| New-flow PacketIn→FlowMod mean 0.511 ms (n=5) | `sprint8_newflow_takeover.{md,csv}` | MAC/IP spoof post-kill, in-controller timestamps | CSV matches | Yes, as controller *processing* time only | T0→T1 = ~1018 ms is the script's 0.5 s sleep + ARP artifact; not detection latency. Sub-timers T1c/T1d are blank in CSV yet the md reports 0.000 ms means (**reporting bug**). |
| "True failover latency 19.48 ± 0.35 ms", 17.90 ms on 1 switch | `sprint8_latency_audit.md` (§3) | "tests/audit_latency_breakdown.py" | **No raw CSV exists**; timeline is a hand-written listing; components don't sum (1.36+1.85+3.42+1.12 ≈ 7.75 + 17.9 RTT ≠ 19.48) | **Unsupported** | Paper uses it as a headline number and a "scale-invariant" claim. |
| 15/15 failover runs, 0% loss, 13.9 s harness metric | `sprint8_scale_results.md`; paper Table | Scale-A/B/C | Raw per-run data not in `results/*.csv` | Pass-rate OK; latency is harness artifact (self-admitted) | Linear topologies; `ping -c 10` 1 s interval. |
| CPU: 99.95% → 17.19% per controller (−82.80%); PacketIn 9,586 → 70 pkt/s | `cpu_benchmark_raw.csv`, `_summary.md`, `_audit.md` | psutil 100 ms, 30 s window, 3 ctl / 8 sw / 16 hosts, hping3 1000 pps, n=5 + validation trial 0 | **Recomputed from CSV: 99.952% / 17.188% / 82.80% — matches.** Script untracked; DISABLED arm needs uncommitted env switch | Yes, with caveats | DISABLED arm is saturation (single-core cap ≈100%/proc) so 82.8% is not a "dedup efficiency" but a saturated-vs-unsaturated comparison; PacketIn counts are post-dedup log lines, not raw arrivals; synthetic unknown-MAC UDP flood; n=5; no CI; audit's suggested paper text says "10-switch" but benchmark used 8. CPU is psutil process CPU (can exceed 100% aggregate). |
| Old 82.4% → 6.2% CPU | paper Fig/caption l.809; latency audit §4 | none | No raw data | **Unsupported — still in paper** | |
| NI live validation 6A–6G | `sprint8_ni_validation.md` | `tests/run_ni_validation.py` | **Raw logs absent**: `/tmp/c1.log` gone; `xdp.log` holds only the last run (6D) | See §4 | |

## 4. Network Intelligence validation status

Only evidence on disk: `xdp.log` from the final run (6D, 2026-10-07 02:02, root-owned). It shows, for 10.0.0.1: `flows=20, unique_dst_ports=20, **rst_count=0**, Risk total=0.081, **HOST_RISK=8**, trust=100`, with an earlier cycle at trust 50 (SYN AGGRESSIVE). The narrative report claims 6D measured risk **100**. That contradicts the only surviving raw artifact (risk 8, zero RSTs observed).

Additional methodology flaws in `run_ni_validation.py` that undermine the causal chain:
- The controller decision is read from a `PacketIn` of a **ping** issued after `del-flows`; the policy line printed is for whichever packet came last, and ICMP is ignored by FLOW_EVENTS (the report itself says so).
- XDP is attached to `s1-eth1` only, started *after* traffic is not guaranteed (`nc … &` backgrounded, 2 s sleep).
- MIRROR in 6B/6C/6D is indistinguishable from **trust**-driven MIRROR (trust fell to 50 from SYN behaviour). No run isolates risk-driven action (trust held ≥70, risk ≥80). 6C "risk 31 → MIRROR" is impossible via the risk override (threshold 80) so it was trust-driven.
- No OVS `dump-flows` evidence captured; no per-run raw log persisted; one trial each; no statistics.
- 6E: three log lines of graph stats from one host pair; BFS/DFS/CC only, Dijkstra not runtime-exercised; 6G is a code-reading argument, not an experiment.

| Exp | Classification |
|---|---|
| 6A Benign | EXECUTED BUT INSUFFICIENT EVIDENCE (result plausible, raw log absent) |
| 6B SYN scan | EXECUTED BUT INSUFFICIENT EVIDENCE |
| 6C Dest diversity | EXECUTED BUT INSUFFICIENT EVIDENCE (decision trust-driven) |
| 6D RST | EXECUTED BUT INSUFFICIENT EVIDENCE — surviving log **contradicts** claim (rst_count=0, risk 8) |
| 6E Graph runtime | EXECUTED BUT INSUFFICIENT EVIDENCE |
| 6F E2E enforcement | EXECUTED BUT INSUFFICIENT EVIDENCE — no OVS flow dump; risk-driven path never isolated |
| 6G Recovery | IMPLEMENTED BUT NOT EXECUTED |

Report `sprint8_ni_validation.md` verdict "PASS WITH MINOR CORRECTIONS" is **not supported** by repository evidence.

## 5. Paper audit (`results/paper.tex`, not edited)

| Sev | Location | Issue |
|---|---|---|
| CRITICAL | Table `tab:actions` l.411–420, l.428–429 | 5-tier policy with REDIRECT 20–39 and DROP 0–19; code is 4-tier, DROP <40, REDIRECT removed. |
| CRITICAL | Fig. caption l.809, l.804 | CPU "82.4% → 6.2%", "5 repeated 60-s trials per tier" — superseded; measured 99.95% → 17.19%, 30-s windows. |
| CRITICAL | l.604 | "50 tests" — current 139 (98 Rust + 41 Python). |
| CRITICAL | l.819–824 | NI evaluation: risk 0.742/74, "Because R > 0.30 ... BFS/DFS", REDIRECT enforcement. Current engine yields 0.3422 for the same demo scenario (equal 0.25 weights), no 0.30 gate in code that I found as stated, REDIRECT does not exist. Labelled as "synthesized patterns" yet claims runtime pipeline. |
| CRITICAL | l.793–795 | 19.48 ± 0.35 ms "true failover latency", scale-invariance; no raw data (see §3). |
| MAJOR | l.165, l.150 | "Equal-role multi-controller failover with zero packet loss" — acceptable only with scope: no detection, no state sync, 0/0 loss counters. |
| MAJOR | l.789–795 | Mixes harness metric with unsupported decomposition; must cite instrumented 4.1 ms / 0.51 ms results with definitions. |
| MAJOR | l.868–876 | Future-work list; confirm no implication that WMMF/persistent history exist (WMMF module exists in repo). |
| MAJOR | Risk→policy | Risk override semantics (risk≥80 → MIRROR over DROP) undocumented. |
| MINOR | l.146 | "Manual / Master-Slave" comparison column vs "Equal Role" — fine but add that ADG has no coordination. |
| MINOR | Figures `Images/scale_failover_latency.png`, `dedup_cpu_comparison.png` | CPU figure likely still shows old numbers; regenerate from `cpu_benchmark_raw.csv`. |
| NONE | CPU 82.80% reduction (once inserted), 98/41/139 counts | Supported. |

## 6. Milestone status

| # | Task | Status | Evidence | Remaining work |
|---|---|---|---|---|
| 1 | Trust policy consistency | PARTIALLY COMPLETE | Rust/Python agree (90/70/40); paper table stale; dead REDIRECT branch in controller | Paper table; remove dead `REDIRECT` priority branch or document |
| 2 | Automated test-count audit | VERIFIED COMPLETE | Re-run: 98 + 41 = 139, 0 failures | Update paper count (milestone 7) |
| 3 | Failover latency audit | PARTIALLY COMPLETE | Instrumented & new-flow audits sound; 19.48 ms has no raw data | Remove/replace 19.48 ms claim; fix 0.000 ms sub-timer reporting |
| 4 | Failover experiments | PARTIALLY COMPLETE | n=5 existing-flow, n=5 new-flow, 2 controllers/1 switch | Failure-detection time not measured; loss counters 0/0 |
| 5 | CPU benchmark and audit | PARTIALLY COMPLETE | Numbers recomputed and match | Commit env switch + script; state saturation caveat; regenerate figure |
| 6 | Live NI validation | PARTIALLY COMPLETE | Script exists, run once; raw evidence missing/contradictory | Re-run with persisted logs, trust held high, OVS flow dumps |
| 7 | Paper reconciliation | NOT COMPLETE | 5 CRITICAL stale items | Rewrite §policy, §eval, §NI, figures |
| 8 | Final hostile IEEE audit | NOT COMPLETE | Blocked by 6, 7 | After paper |
| 9 | Code & paper freeze | NOT COMPLETE | Uncommitted controller diff; untracked artifacts | After 5–8 |

**Verified-complete milestones: 1 of 9 (11%)** — simple unweighted count; no weighting scheme claimed. Four more (1,3,4,5) are close.

## 7. Remaining work

- **Engineering:** commit (or consciously discard) the `adg_controller.py` diff; decide risk-vs-trust precedence; remove dead REDIRECT priority branch; fix sub-timer 0.000 ms reporting; track benchmark scripts in git.
- **Experiments:** NI 6A–6G re-run with per-experiment persisted xdp/controller logs, `ovs-ofctl dump-flows` before/after, trust held ≥70 so the risk override is isolated, ≥5 trials, a true recovery run (6G); real raw data for any failover decomposition or drop the claim.
- **Paper:** all CRITICAL items above, regenerated CPU/failover figures, scoped failover claims.
- **Blockers:** privileged operations (sudo/Mininet/BPF maps) were unavailable in this audit session, so no live experiments were re-run.

## 8. Top issues
1. NI validation report asserts results the surviving raw log contradicts (6D risk 8 vs claimed 100).
2. No NI experiment isolates risk-driven enforcement; all MIRROR outcomes are confounded with trust.
3. Paper contains five CRITICAL stale/unsupported claims (policy table, 82.4→6.2% CPU, 50 tests, NI 0.742/REDIRECT, 19.48 ms).
4. CPU benchmark reproducibility depends on an uncommitted diff and untracked scripts.
5. Risk override can *downgrade* DROP-range trust to MIRROR; risk never causes DROP.

## 9. Single next action
Re-run the NI validation (6A–6G) with persisted raw logs, OVS flow-table dumps and trust held ≥70, to produce real end-to-end evidence — then reconcile paper §NI and the policy table against it.
