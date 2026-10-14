#!/usr/bin/env python3
"""
run_risk_isolation.py -- CONTROLLED, SYNTHETIC risk-to-OVS enforcement test.

Run as root:  sudo python3 tests/run_risk_isolation.py

What is real:     osken controller (adg_controller.py), RiskStore/TrustStore BPF_OBJ_GET +
                  MAP_LOOKUP read path, PolicyEngine, FlowInstaller, OpenFlow 1.3, OVS.
What is synthetic: the VALUES in the pinned HOST_RISK / HOST_TRUST maps. They are written by this
                  harness with bpftool; the Rust detector (adg-xdp) is NOT running.
Pre-existing pins are renamed aside and restored; only resources created here are removed.
"""
import csv, datetime, json, os, re, shutil, signal, struct, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "controller"))
from policy import PolicyEngine, Action          # real production class (expected-value derivation only)

OUT = ROOT / "results" / "risk_enforcement_isolation"
PIN_RISK, PIN_TRUST = Path("/sys/fs/bpf/HOST_RISK"), Path("/sys/fs/bpf/HOST_TRUST")
SRC_IP, DST_IP = "10.0.0.1", "10.0.0.2"
OF_PORT = 6653
RUN_TAG = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
PRIO = {Action.ALLOW: 1, Action.MIRROR: 120, Action.DROP: 200}


def sh(cmd, check=False):
    r = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError("%s -> %s" % (cmd, r.stderr))
    return r


def ip_key_hex(ip):
    v = struct.unpack("!I", bytes(int(x) for x in ip.split(".")))[0]
    return " ".join("%02x" % b for b in struct.pack("<I", v))      # native-endian u32 (x86)


def set_maps(trust, risk):
    k = ip_key_hex(SRC_IP)
    sh("bpftool map update pinned %s key hex %s value hex %s" %
       (PIN_RISK, k, " ".join("%02x" % b for b in struct.pack("<I", risk))), check=True)
    level = 3 if trust >= 90 else 2 if trust >= 70 else 1 if trust >= 40 else 0
    sh("bpftool map update pinned %s key hex %s value hex %02x %02x 01 00" % (PIN_TRUST, k, trust, level), check=True)


def flows():
    return sh("ovs-ofctl -O OpenFlow13 dump-flows s1").stdout


def cleanup_flows():
    """Remove only flows this test can create (host-specific); keep table-miss + ARP flood."""
    for m in ("ip,nw_src=%s" % SRC_IP, "dl_src=00:00:00:00:00:01", "dl_dst=00:00:00:00:00:01",
              "dl_src=00:00:00:00:00:02", "dl_dst=00:00:00:00:00:02"):
        sh(["ovs-ofctl", "-O", "OpenFlow13", "del-flows", "s1", m])


def only_default(dump):
    pr = re.findall(r"priority=(\d+)", dump)
    return sorted(set(pr)) in (["0", "10"], ["0"], ["10"])


def parse_decisions(text):
    out, cur = [], None
    for ln in text.splitlines():
        if "[POLICY]" in ln:
            cur = {}
            continue
        if cur is None:
            continue
        for key, rx in (("ip", r"Host : (\S+)"), ("trust", r"Trust : (\S+)"), ("risk", r"Risk : (\S+)"),
                        ("decision", r"Decision : (\S+)"), ("priority", r"Priority : (\S+)")):
            m = re.search(rx, ln)
            if m:
                cur[key] = m[1]
        if "priority" in cur:
            out.append(cur); cur = None
    return out


def classify(dump):
    d = {"prio1": bool(re.search(r"priority=1,in_port=1,dl_src=00:00:00:00:00:01,dl_dst=00:00:00:00:00:02 .*actions=output:2", dump)),
         "prio120": bool(re.search(r"priority=120,ip,nw_src=10\.0\.0\.1 .*actions=NORMAL,CONTROLLER:128", dump)),
         "prio200": bool(re.search(r"priority=200,ip,nw_src=10\.0\.0\.1 .*actions=drop", dump))}
    return d


def main():
    if os.geteuid() != 0:
        sys.exit("run as root")
    OUT.mkdir(parents=True, exist_ok=True)
    base = OUT / ("run_" + RUN_TAG)
    base.mkdir()
    pe = PolicyEngine()
    meta = {"run": RUN_TAG, "synthetic": True, "detector_running": False, "backups": []}
    rows = []
    ctrl = net = None
    moved = []
    created = []
    try:
        assert sh("ovs-vsctl br-exists s1").returncode != 0, "bridge s1 already exists"
        assert "adg-xdp" not in sh("ps -eo comm").stdout, "adg-xdp is running; refusing"
        # bpffs does not allow rename, so pre-existing pins are used in place: contents are snapshotted
        # and restored afterwards; pins created here are unlinked afterwards.
        for p, nm in ((PIN_RISK, "HOST_RISK"), (PIN_TRUST, "HOST_TRUST")):
            if p.exists():
                snap = sh("bpftool map dump pinned %s" % p).stdout
                (base / ("original_%s_dump.txt" % nm)).write_text(snap)
                moved.append((p, snap))
                meta["backups"].append("%s pre-existing, snapshot original_%s_dump.txt" % (nm, nm))
            else:
                sh("bpftool map create %s type hash key 4 value 4 entries 64 name %s" % (p, nm), check=True)
                created.append(p)
        set_maps(100, 0)

        from mininet.net import Mininet
        from mininet.node import OVSSwitch, RemoteController
        from mininet.log import setLogLevel
        setLogLevel("warning")
        net = Mininet(controller=None, switch=OVSSwitch, autoSetMacs=True, build=False)
        net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=OF_PORT)
        s1 = net.addSwitch("s1", protocols="OpenFlow13")
        h1 = net.addHost("h1", ip="10.0.0.1/8"); h2 = net.addHost("h2", ip="10.0.0.2/8")
        net.addLink(h1, s1); net.addLink(h2, s1)
        net.start()

        ctrl_log = base / "controller.log"
        env = {k: v for k, v in os.environ.items() if k not in ("ADG_MOCK_TRUST", "ADG_DISABLE_DEDUP")}
        env["ADG_CONTROLLER_ID"] = "ISO"
        lf = open(ctrl_log, "wb")
        ctrl = subprocess.Popen(["osken-manager", "controller/adg_controller.py", "--ofp-tcp-listen-port", str(OF_PORT)],
                                stdout=lf, stderr=subprocess.STDOUT, cwd=str(ROOT), env=env)
        t0 = time.time()
        while "Requested EQUAL role" not in ctrl_log.read_text(errors="replace"):
            if time.time() - t0 > 60 or ctrl.poll() is not None:
                raise RuntimeError("controller handshake not observed")
            time.sleep(0.2)
        while "priority=0" not in flows():
            time.sleep(0.2)
        h1.cmd("ping -c 1 -W 1 %s" % DST_IP)         # teach MACs/ARP once (not a measured case)
        time.sleep(1.5)

        cases = []
        for r in (0, 39, 40, 69, 70, 79, 80, 100):
            cases.append(("M1_risk_sweep", 100, r))
        for t in (30, 39, 40, 69, 70, 89, 90, 100):
            cases.append(("M2_precedence_risk100", t, 100))
        for t in (30, 39, 40, 69, 70, 89, 90, 100):
            cases.append(("M3_trust_only_risk0", t, 0))

        def attempt(cid, matrix, trust, risk, n):
            cdir = base / ("%s-a%d" % (cid, n)); cdir.mkdir()
            # 1. neutral state, let the trust-only background detector converge, then clean flows
            set_maps(100, 0); time.sleep(2.6)
            for _ in range(5):                       # cleanup must be verified, not assumed
                cleanup_flows(); time.sleep(0.5)
                pre = flows()
                if only_default(pre):
                    break
            (cdir / "flows_clean_before.txt").write_text(pre)
            clean = only_default(pre)
            # 2. inject synthetic values and trigger immediately (keeps the 2 s trust-only detector
            #    from acting first; dedup window already elapsed during the neutral phase)
            log_off = len(ctrl_log.read_bytes())
            set_maps(trust, risk)
            out = h1.cmd("ping -c 1 -W 1 %s" % DST_IP)
            time.sleep(0.4)
            imm = flows(); (cdir / "flows_immediate.txt").write_text(imm)
            time.sleep(2.6)                          # let the background detector act
            settled = flows(); (cdir / "flows_settled.txt").write_text(settled)
            new_log = ctrl_log.read_bytes()[log_off:].decode("utf-8", "replace")
            (cdir / "controller_excerpt.log").write_text(new_log)
            decs = [d for d in parse_decisions(new_log) if d.get("ip") == SRC_IP]
            first = decs[0] if decs else {}
            exp = pe.evaluate(trust, risk)
            trust_only = pe.evaluate(trust, 0)
            ci, cs = classify(imm), classify(settled)
            exp_key = {Action.ALLOW: "prio1", Action.MIRROR: "prio120", Action.DROP: "prio200"}[exp]
            return dict(case_id=cid, matrix=matrix, attempt=n, injected_trust=trust, injected_risk=risk,
                        ctrl_read_trust=first.get("trust", ""), ctrl_read_risk=first.get("risk", ""),
                        read_matches_injection=(first.get("trust") == str(trust) and first.get("risk") == str(risk)),
                        expected_by_PolicyEngine=exp.name, trust_only_action=trust_only.name,
                        precedence_conflict=(exp != trust_only),
                        controller_decision=first.get("decision", ""), controller_priority=first.get("priority", ""),
                        decision_matches_expected=(first.get("decision") == exp.name),
                        flow_table_clean_before=clean,
                        expected_rule_present_immediate=ci[exp_key],
                        immediate_rules="+".join(k for k, v in ci.items() if v) or "none",
                        settled_rules="+".join(k for k, v in cs.items() if v) or "none",
                        ping_reply=("1 received" in out), n_policy_records=len(decs),
                        valid=bool(clean and first), evidence=str(cdir.relative_to(ROOT)))

        for i, (matrix, trust, risk) in enumerate(cases, 1):
            cid = "ISO-%s-%02d-T%d-R%d" % (RUN_TAG, i, trust, risk)
            for n in (1, 2, 3):
                row = attempt(cid, matrix, trust, risk, n)
                rows.append(row)                     # every attempt is persisted, valid or not
                print(cid, "a%d" % n, "VALID" if row["valid"] else "INVALID", row["controller_decision"],
                      "exp", row["expected_by_PolicyEngine"], "imm", row["immediate_rules"],
                      "settled", row["settled_rules"], flush=True)
                if row["valid"]:
                    break
        set_maps(100, 0)
    finally:
        if rows:
            with open(OUT / ("isolation_results_%s.csv" % RUN_TAG), "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
        meta["end"] = datetime.datetime.now().isoformat()
        try:
            if ctrl and ctrl.poll() is None:
                ctrl.send_signal(signal.SIGINT)
                try: ctrl.wait(5)
                except Exception: ctrl.kill()
        except Exception:
            pass
        if net:
            try: net.stop()
            except Exception: pass
        for p in created:
            try: p.unlink()
            except FileNotFoundError: pass
        for p, snap in moved:
            k = ip_key_hex(SRC_IP)
            sh("bpftool map delete pinned %s key hex %s" % (p, k))
            for m in re.finditer(r"key:((?: [0-9a-f]{2})+)\s+value:((?: [0-9a-f]{2})+)", snap):
                sh("bpftool map update pinned %s key hex%s value hex%s" % (p, m[1], m[2]))
        (base / "meta.json").write_text(json.dumps(meta, indent=1))


if __name__ == "__main__":
    main()
