# CPU Benchmark Summary

This rigorous CPU benchmark replaces the historically unsupported 82.4% -> 6.2% claim.

## Methodology
- **Topology:** 3 Controllers, 8 Switches, 16 Hosts.
- **Hardware CPU Allocation:** As per underlying VM/metal running the test.
- **Workload:** 1,000 UDP pkts/s destined to an unknown MAC to guarantee 100% `PacketIn` translation without `FlowMod` caching.
- **Measurement:** `psutil` sampling of `osken-manager` at 100ms intervals over a 30s steady-state window.

## Results

| Config | Trial | PacketIns (30s) | Rate (pkt/s) | Per-Ctl Mean CPU (%) | Agg Mean CPU (%) |
|---|---|---|---|---|---|
| DEDUP_DISABLED | 0 | 295030 | 9834.33 | 99.92 | 299.76 |
| DEDUP_ENABLED | 0 | 2060 | 68.67 | 17.18 | 51.54 |
| DEDUP_DISABLED | 1 | 272077 | 9069.23 | 99.94 | 299.82 |
| DEDUP_DISABLED | 2 | 293138 | 9771.27 | 99.98 | 299.94 |
| DEDUP_DISABLED | 3 | 277515 | 9250.5 | 99.99 | 299.97 |
| DEDUP_DISABLED | 4 | 296226 | 9874.2 | 99.93 | 299.78 |
| DEDUP_DISABLED | 5 | 299011 | 9967.03 | 99.92 | 299.76 |
| DEDUP_ENABLED | 1 | 2144 | 71.47 | 16.93 | 50.78 |
| DEDUP_ENABLED | 2 | 2074 | 69.13 | 16.89 | 50.67 |
| DEDUP_ENABLED | 3 | 2095 | 69.83 | 17.32 | 51.95 |
| DEDUP_ENABLED | 4 | 2107 | 70.23 | 16.93 | 50.79 |
| DEDUP_ENABLED | 5 | 2105 | 70.17 | 17.87 | 53.62 |
