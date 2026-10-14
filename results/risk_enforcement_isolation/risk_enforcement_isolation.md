# Risk-to-OVS Enforcement Isolation Test (SYNTHETIC)

**Scope: validates the enforcement path only (map → RiskStore/TrustStore → PolicyEngine → FlowInstaller → OpenFlow → OVS). It is NOT evidence of attack-detection quality.** The Rust detector (`adg-xdp`) was not running; every HOST_RISK / HOST_TRUST value below is synthetic test input written by the harness.

Authoritative run: `run_20261014T222219/` + `isolation_results_20261014T222219.csv`. Harness: `tests/run_risk_isolation.py`.
Superseded runs kept: `run_20261014T221839/` (aborted: bpffs refuses rename; nothing executed), `run_20261014T221853/` + its CSV (first full run without retry logic: 3 of 24 cases had no valid decision/stale flows, which led to the retry/clean-verification logic).

## 1. Test setup
- Mininet: s1 (OpenFlow13) + h1 (10.0.0.1, injected host) + h2 (10.0.0.2). One real `osken-manager controller/adg_controller.py` (production code, `ADG_DISABLE_DEDUP` unset, no `ADG_MOCK_TRUST`).
- Per case: (1) maps set to trust 100 / risk 0 and 2.6 s wait so the trust-only background detector converges; (2) host-specific flows deleted (`ip,nw_src=10.0.0.1`, `dl_src/dl_dst` of h1,h2) and verified that only priority 0 and 10 remain (recorded in `flows_clean_before.txt`); (3) synthetic values injected; (4) one ICMP echo from h1 immediately (table miss → PacketIn); (5) OVS dump at +0.4 s ("immediate") and +3.0 s ("settled", after the 2 s detector cycle); (6) controller log excerpt persisted.
- Each case has a unique id `ISO-<runtag>-<n>-T<trust>-R<risk>` and its own evidence directory `<id>-a<attempt>/`.
- Every attempt (valid or not) is in the CSV; an attempt is valid only if the flow table was clean before and a controller decision for 10.0.0.1 was captured in the case window.

## 2. Injection mechanism
- `bpftool map create` of pinned `/sys/fs/bpf/HOST_RISK` and `/sys/fs/bpf/HOST_TRUST` (hash, key u32, value u32 / 4-byte `TrustEntry{score,level,version,flags}`) with the same layout the Rust daemon uses; key = native-endian u32 of `10.0.0.1` as `(a<<24|b<<16|c<<8|d)` — verified indirectly because the controller read back exactly the injected numbers.
- Values written with `bpftool map update pinned …`. The controller opened the maps itself via `BPF_OBJ_GET` and read them with `BPF_MAP_LOOKUP_ELEM` (production `RiskStore.get` / `TrustStore.get`). No mock, no second policy implementation.
- Expected outcomes were derived by calling the real `PolicyEngine.evaluate(trust, risk)` and `evaluate(trust, 0)` (trust-only baseline) — not hard-coded.
- Cleanup: pins created here were unlinked; no pre-existing HOST_RISK/HOST_TRUST pin existed (only EXTENDED_HOST_STATS, untouched); bridge `s1` removed; controller stopped by its own handle; no unrelated process touched.

## 3. Actual policy decision table (valid attempts, 24/24 cases)
Current PolicyEngine: `risk>=80 → MIRROR` first; else trust ≥70 ALLOW, ≥40 MIRROR, else DROP.

### M1 — trust fixed 100, risk swept
| risk | read by controller (trust/risk) | decision | priority | expected | OVS immediate | OVS settled |
|---|---|---|---|---|---|---|
| 0 | 100/0 | ALLOW | 1 | ALLOW | prio1 | prio1 |
| 39 | 100/39 | ALLOW | 1 | ALLOW | prio1 | prio1 |
| 40 | 100/40 | ALLOW | 1 | ALLOW | prio1 | prio1 |
| 69 | 100/69 | ALLOW | 1 | ALLOW | prio1 | prio1 |
| 70 | 100/70 | ALLOW | 1 | ALLOW | prio1 | prio1 |
| 79 | 100/79 | ALLOW | 1 | ALLOW | prio1 | prio1 |
| **80** | 100/80 | **MIRROR** | 120 | MIRROR | prio120 | prio120 |
| 100 | 100/100 | MIRROR | 120 | MIRROR | prio120 | prio120 |

### M2 — risk fixed 100, trust swept (precedence)
| trust | trust-only action (risk 0) | decision with risk 100 | priority | conflict | OVS immediate | OVS settled |
|---|---|---|---|---|---|---|
| 30 | DROP | MIRROR | 120 | **yes** | prio120 | prio120 **+ prio200** |
| 39 | DROP | MIRROR | 120 | **yes** | prio120 | prio120 **+ prio200** |
| 40 | MIRROR | MIRROR | 120 | no | prio120 | prio120 |
| 69 | MIRROR | MIRROR | 120 | no | prio120 | prio120 |
| 70 | ALLOW | MIRROR | 120 | yes (escalation) | prio120 | prio120 |
| 89 | ALLOW | MIRROR | 120 | yes (escalation) | prio120 | prio120 |
| 90 | ALLOW | MIRROR | 120 | yes (escalation) | prio120 | prio120 |
| 100 | ALLOW | MIRROR | 120 | yes (escalation) | prio120 | prio120 |

### M3 — risk 0, trust swept (control for M2)
30/39 → DROP (prio200); 40/69 → MIRROR (prio120); 70/89/90/100 → ALLOW (prio1). All as expected.

## 4. Risk-boundary results
- The only boundary in the risk dimension is 79 → 80; ALLOW at ≤79 and MIRROR at ≥80 (trust 100). Values 39/40/69/70 are trust thresholds, not risk thresholds, and had no effect on the decision at trust 100 — confirmed.
- 24/24 valid cases: controller read value == injected value (trust and risk); decision == PolicyEngine expectation; expected rule present immediately.

## 5. Trust-precedence results (documented, unchanged)
- With risk ≥80 the PacketIn path returns MIRROR **for DROP-range trust (30, 39)**: the risk override *weakens* the trust-only DROP decision. This is the conflict flagged in earlier audits.
- Real effective state in that case: the background `TrustChangeDetector` evaluates trust only (no risk) and, within its 2 s cycle, installs a priority-200 DROP flow in addition to the priority-120 MIRROR flow, so the *settled* flow table contains both and the higher priority (DROP) wins. Net effect: the override is only transient (≈ ≤2 s) for DROP-range trust, but the two enforcement paths disagree by design.
- For trust ≥70, risk ≥80 escalates ALLOW → MIRROR immediately and persistently (detector says ALLOW, the priority-120 rule stays).

## 6. OVS evidence (per case)
`results/risk_enforcement_isolation/run_20261014T222219/<case>-a<n>/{flows_clean_before.txt, flows_immediate.txt, flows_settled.txt, controller_excerpt.log}`. Rule shapes observed:
- ALLOW: `priority=1,in_port=1,dl_src=00:00:00:00:00:01,dl_dst=00:00:00:00:00:02 actions=output:2`
- MIRROR: `priority=120,ip,nw_src=10.0.0.1 actions=NORMAL,CONTROLLER:128`
- DROP: `priority=200,ip,nw_src=10.0.0.1 actions=drop`
Stale-flow control: `flow_table_clean_before=True` for every valid attempt (only priorities 0 and 10 present).

## 7. Failures and limitations
- 3 invalid attempts (cases 08, 09, 12, attempt 1): no PacketIn/decision and the ping failed even though the table was clean (no controller log line); cause not established (likely a lost first ICMP/ARP after flow deletion). Retried; attempt 2 valid. Not hidden — listed in the CSV.
- First run (`run_20261014T221853`) showed a race: the 2 s trust-only detector can install DROP before the trigger when the harness waits ≥1.2 s after injection; the final harness triggers immediately. This race is itself a property of the production design.
- Only one source host, one switch, one trial per cell (deterministic function; no statistics claimed).
- FlowMod messages themselves were not captured (OF1.3-only bridge rejects the flow-monitor extension); installation is evidenced by flow-table appearance.
- The trust-only detector is part of the real controller and cannot be disabled without editing production code; its interaction is reported, not removed.
- `TrustEntry.level` was set by the harness from score bands; the controller reads only `score`.

## 8. Synthetic enforcement validation vs. real detector validation
| Claim | Supported by this test? |
|---|---|
| Controller reads HOST_RISK/HOST_TRUST through the production map path | Yes (24/24) |
| PolicyEngine thresholds behave as coded, incl. risk≥80 override | Yes |
| Decisions become OVS flow rules of the expected priority/action | Yes |
| The Rust detector ever produces risk ≥80 on realistic traffic | **No** — latest live run: max risk 50 |
| Risk values correlate with attacks | **No** — values were injected |
| Detection quality / recovery of detector-driven risk | **No** (see `results/ni_live_v2_fixed/`) |

## 9. Repository state
No production file modified by this task. Pre-existing uncommitted changes remain (see final Git status in the task summary). Nothing committed; paper untouched.
