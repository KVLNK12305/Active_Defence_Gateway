#!/usr/bin/env python3
"""Aggregate results/ni_live_v2/*.csv into a statistics table (stdout)."""
import csv, statistics as st, sys, collections
from pathlib import Path
base = Path(sys.argv[1] if len(sys.argv) > 1 else "results/ni_live_v2")
def rd(n):
    p = base / n
    return list(csv.DictReader(open(p))) if p.exists() else []
def f(x):
    try: return float(x)
    except: return None
def ms(v):
    v = [x for x in v if x is not None]
    return "n=%d mean=%.3f sd=%.3f min=%g max=%g" % (len(v), st.mean(v), st.pstdev(v), min(v), max(v)) if v else "n=0"
runs = []
for n in ["ni_baseline.csv","ni_syn_scan.csv","ni_diversity.csv","ni_rst.csv","ni_bulk_probe.csv"]:
    runs += rd(n)
by = collections.defaultdict(list)
for r in runs: by[r["cfg"]].append(r)
for cfg, rs in sorted(by.items()):
    ok = [r for r in rs if r["status"] == "OK"]
    print("### %s  trials=%d ok=%d failed=%d" % (cfg, len(rs), len(ok), len(rs)-len(ok)))
    for k in ["pre_trust","pre_risk","min_trust_during","peak_host_risk","peak_risk_total","peak_dest","peak_port","peak_rstr","peak_cent","peak_flows","peak_dst_ips","peak_dst_ports","peak_rst","peak_wod","max_comp","max_bfs","max_dfs","max_neighbors","xdp_events","pcap_h1_syn_fin_rst_pkts","pcap_h1_syn_pkts","pcap_h1_rst_pkts","pcap_other_rst_pkts","max_expired_edges","post_first_risk","late_risk","final_ft","final_edges"]:
        print("  %-26s %s" % (k, ms([f(r.get(k)) for r in ok])))
    print("  prio120/200 flow after:", collections.Counter((r["after_has_prio120_ipsrc_h1"], r["after_has_prio200_ipsrc_h1"]) for r in ok))
print("### E2E triggers")
e = rd("ni_e2e.csv")
c = collections.Counter((r["cfg"], r["trigger"], r["ctrl_trust"], r["ctrl_risk"], r["decision"], r["classification"]) for r in e)
for k, v in sorted(c.items()): print(" ", v, k)
print("### FlowMod evidence (prio120/200 appears after trigger when decision != ALLOW)")
c = collections.Counter((r["cfg"], r["trigger"], r["decision"], r["prio120_ipsrc_before"], r["prio120_ipsrc_after"], r["prio200_ipsrc_after"]) for r in e)
for k, v in sorted(c.items()): print(" ", v, k)
