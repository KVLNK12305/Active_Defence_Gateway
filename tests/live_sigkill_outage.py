#!/usr/bin/env python3
"""
live_sigkill_outage.py -- live acceptance test: adg-xdp daemon killed abruptly with SIGKILL.

Validates:
  1. SIGKILL terminates daemon #1 abruptly, preventing a 'stopped' heartbeat from being written.
  2. The controller detects staleness (STALE) after the 5s freshness timeout.
  3. Host 10.0.0.1 trust is HELD at last valid value (15) during the bounded 30s hold.
  4. The 30s hold duration is measured from the heartbeat timestamp, not controller read time.
  5. Hold expiry applies degraded DROP (trust unavailable -> DROP).
  6. Existing DROP rule is never released or weakened to trust 100 during degradation.
  7. Starting daemon #2 causes the controller to detect map replacement.
  8. Fresh benign traffic causes daemon #2 to rescore trust 100 and controller releases DROP.
  9. Ping replies resume after recovery.
"""
import json, os, re, signal, subprocess, sys, threading, time, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from live_harness import (LiveRun, Interrupted, SignalTracer, ensure_own_session, run_bounded,
                          parse_signal_trace, cleanup_from_manifest)

ROOT = Path(__file__).resolve().parent.parent
XDP_BIN = ROOT / "adg-xdp" / "target" / "release" / "adg-xdp"
OF_PORT = 6653
OF_TARGET = "tcp:127.0.0.1:%d" % OF_PORT
H1, H2 = "10.0.0.1", "10.0.0.2"
HOLD_S = 30.0
SILENT_S = 45.0
HB_NAME = "heartbeat.json"


def sh(cmd, timeout=20):
    return subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True, timeout=timeout)


def flows():
    return sh("ovs-ofctl -O OpenFlow13 dump-flows s1").stdout


def adg_rules(dump):
    return {p: bool(re.search(r"priority=%d,ip,nw_src=10\.0\.0\.1 " % p, dump)) for p in (120, 200)}


def wait_for(fn, timeout, step=0.2):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if fn():
            return True
        time.sleep(step)
    return False


class Sampler(threading.Thread):
    COLS = ("t", "prio120", "prio200", "hb_incarnation", "hb_state", "hb_generation", "hb_wall_ms",
            "hb_trust_ok", "hb_risk_ok")

    def __init__(self, out, hb_path, ctrl_log):
        super().__init__(daemon=True)
        self.hb_path, self.ctrl_log, self.pos = hb_path, ctrl_log, 0
        self.rows, self.ctrl_lines = [], []
        self.stop_ev = threading.Event()
        self.csv = open(out / "timeline.csv", "w", buffering=1)
        self.csv.write(",".join(self.COLS) + "\n")

    def read_hb(self):
        try:
            return json.loads(self.hb_path.read_text())
        except Exception:
            return {}

    def run(self):
        while not self.stop_ev.is_set():
            t = time.time()
            try:
                r = adg_rules(flows())
            except Exception:
                r = {120: None, 200: None}
            hb = self.read_hb()
            row = dict(t=t, prio120=r[120], prio200=r[200], hb_incarnation=hb.get("incarnation"),
                       hb_state=hb.get("state"), hb_generation=hb.get("generation"),
                       hb_wall_ms=hb.get("wall_unix_ms"), hb_trust_ok=hb.get("trust_ok"),
                       hb_risk_ok=hb.get("risk_ok"))
            self.rows.append(row)
            self.csv.write(",".join(str(row[c]) for c in self.COLS) + "\n")
            try:
                data = self.ctrl_log.read_bytes()[self.pos:]
                self.pos += len(data)
                for ln in data.decode("utf-8", "replace").splitlines():
                    self.ctrl_lines.append((t, ln))
            except FileNotFoundError:
                pass
            time.sleep(0.25)
        self.csv.close()


def scenario(run: LiveRun, state):
    out = run.out
    hb_path = out / HB_NAME

    def read_hb():
        try:
            return json.loads(hb_path.read_text())
        except Exception:
            return {}

    state["phase"] = "preconditions"
    if sh("ovs-vsctl br-exists s1").returncode == 0:
        raise RuntimeError("bridge s1 already exists; refusing to touch it")
    if sh("ss -ltn 'sport = :%d'" % OF_PORT).stdout.count("LISTEN"):
        raise RuntimeError("port %d already in use" % OF_PORT)
    if sh("pgrep -x adg-xdp").stdout.strip():
        raise RuntimeError("an adg-xdp daemon is already running; refusing")
    for iface in ("s1", "s1-eth1", "s1-eth2"):
        if sh("ip link show %s" % iface).returncode == 0:
            raise RuntimeError("interface %s already exists; refusing to touch it" % iface)
    if sh("pgrep -f '[o]sken-manager.*adg_controller.py'").stdout.strip():
        raise RuntimeError("an ADG controller process is already running; refusing")

    state["phase"] = "setup"
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController
    from mininet.log import setLogLevel
    setLogLevel("warning")
    net = Mininet(controller=None, switch=OVSSwitch, autoSetMacs=True, build=False)
    state["net"] = net
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=OF_PORT)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    h1 = net.addHost("h1", ip=H1 + "/8"); h2 = net.addHost("h2", ip=H2 + "/8")
    net.addLink(h1, s1); net.addLink(h2, s1)
    run.register_bridge("s1", OF_TARGET)
    net.start()
    for h in (h1, h2):
        run.manifest["processes"]["mininet_" + h.name] = {"pid": h.pid, "cmd": ["mininet:" + h.name]}
    run.save_manifest()
    run.mark("net_started")
    sh("ip link set s1-eth1 up")
    run.spawn("tcpdump", ["tcpdump", "-i", "s1-eth1", "-nn", "-U", "-w", str(out / "s1-eth1.pcap")],
              out / "tcpdump.log")

    def start_daemon(n):
        log = out / ("adg_xdp_%d.log" % n)
        p = run.spawn("daemon%d" % n, [str(XDP_BIN), "--iface", "s1-eth1", "--heartbeat-path", str(hb_path)],
                      log, env=dict(os.environ, RUST_LOG="info"))
        ok = wait_for(lambda: "Attached XDP program" in log.read_text(errors="replace")
                      and Path("/sys/fs/bpf/HOST_TRUST").exists() and read_hb().get("pid") == p.pid, 40)
        if not ok or p.poll() is not None:
            raise RuntimeError("adg-xdp #%d did not become ready (see %s)" % (n, log.name))
        hb = read_hb()
        run.mark("daemon%d_ready" % n)
        run.mark("daemon%d_map_ids" % n, [hb.get("trust_map_id"), hb.get("risk_map_id")])
        return p

    start_daemon(1)
    ctrl_log = out / "controller.log"
    cenv = {k: v for k, v in os.environ.items() if k not in ("ADG_MOCK_TRUST", "ADG_DISABLE_DEDUP",
                                                             "ADG_HEARTBEAT_REQUIRED")}
    cenv.update(ADG_CONTROLLER_ID="C1", ADG_HEARTBEAT_PATH=str(hb_path), PYTHONUNBUFFERED="1")
    run.spawn("controller", ["osken-manager", "controller/adg_controller.py", "--ofp-tcp-listen-port",
                             str(OF_PORT)], ctrl_log, env=cenv, cwd=str(ROOT))
    if not wait_for(lambda: "Requested EQUAL role" in ctrl_log.read_text(errors="replace"), 60):
        raise RuntimeError("controller/switch handshake not observed")
    wait_for(lambda: "priority=0" in flows(), 10)
    sampler = Sampler(out, hb_path, ctrl_log)
    state["sampler"] = sampler
    sampler.start()
    time.sleep(3)

    # P0 benign
    state["phase"] = "p0_benign"
    run.mark("p0_start")
    (out / "ping_p0.txt").write_text(h1.cmd("ping -c 3 -i 0.5 -w 10 %s" % H2))
    time.sleep(3)
    run.mark("p0_rules", adg_rules(flows()))

    # P1 attack: fragmented ICMP until DROP is installed (+4 s so several cycles score it)
    state["phase"] = "p1_attack"
    run.mark("p1_start")
    attack = h1.popen(["ping", "-s", "3000", "-i", "0.2", H2], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    run.register_process("attack_ping", attack, ["ping", "-s", "3000", "-i", "0.2", H2])
    if not wait_for(lambda: adg_rules(flows())[200], 25):
        raise RuntimeError("DROP (priority 200) never installed during attack")
    run.mark("drop_installed")
    time.sleep(4)

    # P2 SIGKILL: abruptly terminate daemon #1 with SIGKILL
    state["phase"] = "p2_sigkill"
    run.mark("daemon1_sigkill_time")
    run.stop("daemon1", steps=[(signal.SIGKILL, 2.0)])
    hb_after_kill = read_hb()
    run.mark("hb_after_daemon1_sigkill", hb_after_kill)
    run.stop("attack_ping")
    out_bytes = b""
    try:
        out_bytes, _ = attack.communicate(timeout=5)
    except Exception:
        pass
    (out / "ping_p1_attack.txt").write_bytes(out_bytes)
    run.mark("attack_stopped")

    # Let staleness occur (5s) and hold expire (30s) while daemon is dead
    time.sleep(SILENT_S)

    # P3 recovery: start daemon #2 and send benign traffic
    state["phase"] = "p3_recovery"
    start_daemon(2)
    time.sleep(2.0)
    run.mark("p3_start")
    (out / "ping_p3.txt").write_text(h1.cmd("ping -c 16 -i 0.5 -w 20 %s" % H2))
    time.sleep(3)
    run.mark("p3_end")
    (out / "final_flows.txt").write_text(flows())
    (out / "host_trust_dump.txt").write_text(sh("bpftool map dump pinned /sys/fs/bpf/HOST_TRUST").stdout)
    run.stop("daemon2")
    run.mark("hb_after_daemon2_stop", read_hb())
    state["phase"] = "completed"


def analyse(run: LiveRun, state):
    ev, out = run.events, run.out
    sampler = state.get("sampler")
    rows = sampler.rows if sampler else []
    lines = sampler.ctrl_lines if sampler else []
    (out / "controller_stamped.log").write_text("".join("%.3f %s\n" % (t, l) for t, l in lines))

    def first_line(pat, after=0.0):
        for t, l in lines:
            if t >= after and re.search(pat, l):
                return t, l
        return None, None

    checks, data = {}, {}
    hb1_last = ev.get("hb_after_daemon1_sigkill") or {}
    obs_wall = (hb1_last.get("wall_unix_ms") or 0) / 1000.0 or None
    data.update(daemon1_final_heartbeat=hb1_last, last_obs_wall=obs_wall,
                daemon_map_ids={k: ev.get(k) for k in ("daemon1_map_ids", "daemon2_map_ids")},
                daemon_stops={k: ev.get(k) for k in ("stop_daemon1", "stop_daemon2")})

    # P0 checks
    if "p0_start" in ev:
        checks["p0_no_adg_rule_for_benign"] = ev.get("p0_rules") == {120: False, 200: False}
    else:
        checks["p0_no_adg_rule_for_benign"] = "NOT_RUN"

    # P1 checks
    if "p1_start" in ev:
        checks["drop_installed_during_attack"] = "drop_installed" in ev
    else:
        checks["drop_installed_during_attack"] = "NOT_RUN"

    # SIGKILL specifics: stopped heartbeat NOT written (state still 'running')
    if "daemon1_sigkill_time" in ev:
        st1 = ev.get("stop_daemon1") or {}
        checks["daemon1_terminated_by_sigkill"] = st1.get("signal") == "SIGKILL"
        checks["no_stopped_heartbeat_on_sigkill"] = hb1_last.get("state") != "stopped"
    else:
        checks["daemon1_terminated_by_sigkill"] = "NOT_RUN"
        checks["no_stopped_heartbeat_on_sigkill"] = "NOT_RUN"

    # Staleness detection at ~5s threshold
    t_stale, l_stale = first_line(r"telemetry DEGRADED: STALE", ev.get("daemon1_sigkill_time", 0))
    data["stale_line"] = l_stale
    checks["staleness_detected_on_outage"] = t_stale is not None

    # Hold detection & hold expiry
    t_held, l_held = first_line(r"Host=10\.0\.0\.1 trust HELD", ev.get("daemon1_sigkill_time", 0) - 5)
    t_alert, l_alert = first_line(r"\[TELEMETRY ALERT\] Host=10\.0\.0\.1 trust unavailable", ev.get("daemon1_sigkill_time", 0))
    data.update(held_line=l_held, alert_line=l_alert,
                alert_minus_last_obs_s=round(t_alert - obs_wall, 2) if t_alert and obs_wall else None)
    checks["trust_held_during_outage"] = t_held is not None
    checks["hold_expiry_at_30s"] = (data["alert_minus_last_obs_s"] is not None
                                    and HOLD_S <= data["alert_minus_last_obs_s"] <= HOLD_S + 3.0)

    # DROP persistence throughout outage
    if "drop_installed" in ev:
        span = [r for r in rows if ev.get("drop_installed", 1e18) <= r["t"] <= ev.get("p3_start", 0)]
        gaps = [r["t"] for r in span if not r["prio200"]]
        data.update(drop_span_samples=len(span), drop_gap_samples=len(gaps), first_gap=gaps[:3])
        checks["drop_never_released_during_outage"] = bool(span) and not gaps
        checks["no_mirror_rule_in_span"] = bool(span) and not any(r["prio120"] for r in span)
    else:
        checks["drop_never_released_during_outage"] = "NOT_RUN"
        checks["no_mirror_rule_in_span"] = "NOT_RUN"

    # Daemon 2 start & new maps
    if "daemon2_ready" in ev:
        ids1, ids2 = ev.get("daemon1_map_ids"), ev.get("daemon2_map_ids")
        checks["daemon2_new_maps"] = bool(ids1 and ids2) and set(ids1).isdisjoint(ids2)
        t_rep, l_rep = first_line(r"HOST_TRUST map was replaced|restart detected", ev.get("daemon1_sigkill_time", 0))
        data["replaced_line"] = l_rep
        checks["map_replacement_detected"] = t_rep is not None
    else:
        checks["daemon2_new_maps"] = "NOT_RUN"
        checks["map_replacement_detected"] = "NOT_RUN"

    # P3 recovery checks
    if "p3_start" in ev:
        p3 = (out / "ping_p3.txt").read_text() if (out / "ping_p3.txt").exists() else ""
        m = re.search(r"(\d+) packets transmitted, (\d+) received", p3)
        data["p3_ping"] = m.group(0) if m else None
        rel = [r["t"] for r in rows if r["t"] >= ev.get("p3_start", 1e18) and r["prio200"] is False]
        data["release_after_p3_start_s"] = round(rel[0] - ev["p3_start"], 2) if rel else None
        checks["released_after_rescoring"] = bool(rel)
        checks["replies_resume_after_release"] = bool(m) and int(m.group(2)) > 0
    else:
        checks["released_after_rescoring"] = "NOT_RUN"
        checks["replies_resume_after_release"] = "NOT_RUN"

    # Daemon 2 shutdown checks
    if "hb_after_daemon2_stop" in ev:
        st2 = ev.get("stop_daemon2") or {}
        hb2_last = ev.get("hb_after_daemon2_stop") or {}
        checks["daemon2_exits_within_5s_of_sigint"] = (st2.get("signal") == "SIGINT"
                                                      and st2.get("exit_s", 99) <= 5.0)
        checks["daemon2_final_heartbeat_stopped"] = hb2_last.get("state") == "stopped"
        checks["daemon2_clean_stop_heartbeat"] = (hb2_last.get("trust_ok") is True
                                                  and hb2_last.get("risk_ok") is True)
    else:
        checks["daemon2_exits_within_5s_of_sigint"] = "NOT_RUN"
        checks["daemon2_final_heartbeat_stopped"] = "NOT_RUN"
        checks["daemon2_clean_stop_heartbeat"] = "NOT_RUN"

    # Signal attribution
    ours = {rec["pid"] for rec in run.manifest["processes"].values()} | {os.getpid()}
    trace = parse_signal_trace(out / "signals_trace.log")
    aimed = [s for s in trace if s["tpid"] in ours]
    external = [s for s in aimed if s["spid"] != os.getpid()]
    data.update(signals_to_run_processes=aimed, signals_not_sent_by_harness=external,
                harness_signals_received=run.signals)
    checks["no_external_signals_to_harness"] = not [s for s in run.signals]

    return checks, data


def main():
    if "--cleanup" in sys.argv:
        run_dir = Path(sys.argv[sys.argv.index("--cleanup") + 1]).resolve()
        print(json.dumps(cleanup_from_manifest(run_dir), indent=2))
        return
    if os.geteuid() != 0:
        sys.exit("run as root")
    if not XDP_BIN.exists():
        sys.exit("missing %s (cargo build --release --manifest-path adg-xdp/Cargo.toml)" % XDP_BIN)
    run_dir = Path(os.environ.get("ADG_HARNESS_RUN") or
                   ROOT / "results" / "live_acceptance" /
                   ("sigkill_outage_" + datetime.datetime.now().strftime("%Y%m%dT%H%M%S")))
    ensure_own_session(run_dir)

    run = LiveRun(run_dir)
    run.install_signal_handlers()
    run.mark("harness_session", {"pid": os.getpid(), "sid": os.getsid(0), "pgid": os.getpgid(0)})
    tracer = SignalTracer(run, "adg_" + run_dir.name)
    tracer.start()
    state = {"phase": "init"}
    try:
        scenario(run, state)
    except Interrupted as e:
        state["failure_phase"] = state.get("phase", "interrupted")
        run.note("interrupted by %s during %s" % (e, state["failure_phase"]))
    except Exception as e:
        state["failure_phase"] = state.get("phase", "unknown")
        run.note("ERROR during %s: %r" % (state["failure_phase"], e))
    finally:
        run.cleaning = True
        sampler = state.get("sampler")
        if sampler:
            sampler.stop_ev.set(); sampler.join(5)
        cleanup_results = run.cleanup_processes()
        net = state.get("net")
        if net is not None:
            net_stopped = run_bounded(net.stop, 60, "net.stop", run)
            cleanup_results["net_stop"] = "completed" if net_stopped else "timed_out"
        tracer.stop()
        try:
            checks, data = analyse(run, state)
        except Exception as e:
            checks, data = {}, {}
            run.note("analysis failed: %r" % (e,))
        exit_codes = {name: p.poll() for name, p in run.procs.items()}
        summary = dict(
            test="sigkill_outage",
            out=str(run.out),
            failure_phase=state.get("failure_phase"),
            exit_codes=exit_codes,
            cleanup_results=cleanup_results,
            checks=checks,
            all_passed=bool(checks) and all(v is True for v in checks.values()) and not run.notes,
            data=data,
            notes=run.notes,
            events=run.events,
        )
        (run.out / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
        run.log("summary written; all_passed=%s" % summary["all_passed"])
        print(json.dumps(dict(checks=checks, all_passed=summary["all_passed"], notes=run.notes,
                              failure_phase=state.get("failure_phase")),
                         indent=2, default=str))


if __name__ == "__main__":
    main()
