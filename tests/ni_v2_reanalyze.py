#!/usr/bin/env python3
"""Offline re-derivation of results/ni_live_v2/*.csv from persisted raw run artifacts (no live execution)."""
import json, sys, types
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_ni_validation_v2 as H

base = Path(sys.argv[1] if len(sys.argv) > 1 else "results/ni_live_v2")
for csvf in base.glob("*.csv"):
    csvf.unlink()
for d in sorted((base / "runs").iterdir()):
    meta = json.loads((d / "meta.json").read_text())
    tail = types.SimpleNamespace(lines={})
    for k in ("daemon", "ctrl", "ovsmon"):
        p = d / ("stamped_%s.log" % k)
        L = []
        if p.exists():
            for ln in p.read_text(errors="replace").split("\n"):
                if "\t" in ln:
                    t, txt = ln.split("\t", 1); L.append((float(t), txt))
        tail.lines[k] = L
    summ, e2e, rec, graph = H.analyse(d, meta, tail, None)
    H.write_csv(base / H.CSV_FOR[meta["cfg"]], [summ])
    H.write_csv(base / "ni_e2e.csv", e2e)
    H.write_csv(base / "ni_recovery.csv", rec)
    H.write_csv(base / "ni_graph.csv", graph)
print("reanalysed", len(list((base / "runs").iterdir())), "runs")
