"""Deterministic tests for telemetry freshness and pinned-map replacement.

A fake kernel models bpffs pins, kernel map IDs, file descriptors and lookups, so daemon
restart / crash / clean stop / pipeline errors can be simulated without root."""
import ctypes
import errno
import json
import os
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from typing import Optional
from unittest.mock import MagicMock, patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../controller')))
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

import trust as trust_mod
import risk as risk_mod
from trust import TrustStore, TrustEntry
from risk import RiskStore
from telemetry import (TelemetryMonitor, SignalState, LookupStatus, MapRefresh, read_heartbeat, Reading,
                       BpfMapInfoHead)
from detector import TrustChangeDetector
from flow import FlowInstaller
from policy import PolicyEngine, Action, Quality, Resolved

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "heartbeat_v1.json")
HOST = "10.0.0.1"
HOST_KEY = 0x0A000001   # struct.unpack("!I", inet_aton("10.0.0.1"))
SEC = 1_000_000_000


class FakeMap:
    def __init__(self, map_id, kind):
        self.id, self.kind, self.entries = map_id, kind, {}


class FakeKernel:
    """bpf(2) subset: OBJ_GET (7), OBJ_GET_INFO_BY_FD (15), MAP_LOOKUP_ELEM (1)."""

    def __init__(self):
        self.pins, self.fds, self.next_fd, self.next_id = {}, {}, 100, 1
        self.lookup_errno: Optional[int] = None
        self.closed = []

    def pin_new_map(self, path, kind):
        m = FakeMap(self.next_id, kind)
        self.next_id += 1
        self.pins[path] = m
        return m

    def syscall(self, cmd, attr):
        if cmd == 7:
            path = ctypes.string_at(attr.pathname).decode()
            if path not in self.pins:
                raise OSError(errno.ENOENT, "No such file or directory")
            fd = self.next_fd
            self.next_fd += 1
            self.fds[fd] = self.pins[path]
            return fd
        m = self.fds.get(attr.map_fd if cmd == 1 else attr.bpf_fd)
        if m is None:
            raise OSError(errno.EBADF, "Bad file descriptor")
        if cmd == 15:
            BpfMapInfoHead.from_address(attr.info).id = m.id
            return 0
        if cmd == 1:
            if self.lookup_errno:
                raise OSError(self.lookup_errno, os.strerror(self.lookup_errno))
            key = ctypes.c_uint32.from_address(attr.key).value
            if key not in m.entries:
                raise OSError(errno.ENOENT, "No such file or directory")
            if m.kind == "trust":
                TrustEntry.from_address(attr.value).score = m.entries[key]
            else:
                ctypes.c_uint32.from_address(attr.value).value = m.entries[key]
            return 0
        raise OSError(errno.EINVAL, "unsupported")

    def close(self, fd):
        if fd not in self.fds:
            raise AssertionError("close of unknown or already closed fd %s" % fd)
        del self.fds[fd]
        self.closed.append(fd)

    def open_fds_for(self, kind):
        return [fd for fd, m in self.fds.items() if m.kind == kind]


class TelemetryTestBase(unittest.TestCase):
    def setUp(self):
        self.k = FakeKernel()
        self.patches = [patch('trust.bpf_syscall', side_effect=self.k.syscall),
                        patch('risk.bpf_syscall', side_effect=self.k.syscall)]
        for p in self.patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self.patches])
        self.dir = tempfile.mkdtemp(prefix="adg-telemetry-test-")
        self.addCleanup(shutil.rmtree, self.dir)
        self.hb_path = os.path.join(self.dir, "heartbeat.json")
        self.now = 1000 * SEC
        self.incarnation_seq = 0

    # --- simulated daemon -------------------------------------------------------------
    def daemon_start(self, trust=None, risk=None):
        """Like adg-xdp startup: remove old pins, pin brand-new maps, write a 'starting' heartbeat."""
        self.tmap = self.k.pin_new_map(trust_mod.HOST_TRUST_MAP_PATH, "trust")
        self.rmap = self.k.pin_new_map(risk_mod.HOST_RISK_MAP_PATH, "risk")
        if trust is not None:
            self.tmap.entries[HOST_KEY] = trust
        if risk is not None:
            self.rmap.entries[HOST_KEY] = risk
        self.incarnation_seq += 1
        self.hb = {"schema": 1, "incarnation": "4242-%d" % self.incarnation_seq, "pid": 4242,
                   "state": "starting", "generation": 0, "monotonic_ns": self.now,
                   "wall_unix_ms": 0, "trust_map_id": self.tmap.id, "risk_map_id": self.rmap.id,
                   "hosts": 0, "stats_read_errors": 0, "trust_write_errors": 0,
                   "risk_write_errors": 0, "trust_ok": False, "risk_ok": False}
        self.write_hb()

    def daemon_cycle(self, trust_ok=True, risk_ok=True):
        self.hb.update(state="running", generation=self.hb["generation"] + 1,
                       monotonic_ns=self.now, trust_ok=trust_ok, risk_ok=risk_ok)
        self.write_hb()

    def daemon_stop(self):
        self.hb.update(state="stopped", monotonic_ns=self.now)
        self.write_hb()

    def write_hb(self):
        with open(self.hb_path, "w") as f:
            json.dump(self.hb, f)

    # --- controller side --------------------------------------------------------------
    def make_stores(self):
        self.ts, self.rs = TrustStore(), RiskStore()
        self.ts._close = self.rs._close = self.k.close
        self.mon = TelemetryMonitor({"trust": self.ts, "risk": self.rs}, heartbeat_path=self.hb_path,
                                    freshness_s=5, clock=lambda: self.now)

    def states(self):
        return self.mon.check()


class TestLookupStatus(TelemetryTestBase):
    def test_missing_entry_is_not_a_failure(self):
        self.daemon_start()
        self.make_stores()
        self.assertEqual(self.ts.read(HOST), (None, LookupStatus.NO_ENTRY))
        self.assertEqual(self.rs.read(HOST), (None, LookupStatus.NO_ENTRY))
        self.assertEqual((self.ts.get(HOST), self.rs.get(HOST)), (100, 0))   # unchanged fallbacks

    def test_ok_values(self):
        self.daemon_start(trust=35, risk=81)
        self.make_stores()
        self.assertEqual(self.ts.read(HOST), (35, LookupStatus.OK))
        self.assertEqual(self.rs.read(HOST), (81, LookupStatus.OK))

    def test_lookup_error_distinct_from_missing_entry(self):
        self.daemon_start(trust=35, risk=81)
        self.make_stores()
        self.k.lookup_errno = errno.EPERM
        self.assertEqual(self.ts.read(HOST).status, LookupStatus.LOOKUP_ERROR)
        self.assertEqual(self.rs.read(HOST).status, LookupStatus.LOOKUP_ERROR)
        self.assertEqual((self.ts.get(HOST), self.rs.get(HOST)), (100, 0))

    def test_map_unavailable_distinct(self):
        self.make_stores()                                   # daemon never started
        self.assertEqual(self.ts.read(HOST).status, LookupStatus.MAP_UNAVAILABLE)
        self.assertEqual(self.rs.read(HOST).status, LookupStatus.MAP_UNAVAILABLE)


class TestMapReplacement(TelemetryTestBase):
    def test_daemon_restart_reopens_replaced_map(self):
        self.daemon_start(trust=10, risk=90)
        self.make_stores()
        self.assertEqual(self.states(), {"trust": SignalState.STARTING, "risk": SignalState.STARTING})
        old_trust_fd = self.ts.map_fd

        self.daemon_start(trust=95, risk=5)                  # restart: new maps re-pinned
        # Without a refresh the controller still reads the orphaned old map (the original bug)
        self.assertEqual((self.ts.get(HOST), self.rs.get(HOST)), (10, 90))

        self.mon.check()
        self.assertEqual(self.mon.last_refresh, {"trust": MapRefresh.REPLACED, "risk": MapRefresh.REPLACED})
        self.assertEqual((self.ts.get(HOST), self.rs.get(HOST)), (95, 5))
        self.assertIn(old_trust_fd, self.k.closed)
        self.assertEqual(len(self.k.open_fds_for("trust")), 1, "no fd leak")
        self.assertEqual(len(self.k.open_fds_for("risk")), 1)

    def test_unchanged_pin_does_not_leak_fds(self):
        self.daemon_start(trust=50)
        self.make_stores()
        for _ in range(5):
            self.mon.check()
        self.assertEqual(self.mon.last_refresh["trust"], MapRefresh.UNCHANGED)
        self.assertEqual(len(self.k.open_fds_for("trust")), 1)

    def test_controller_started_before_daemon(self):
        self.make_stores()
        self.assertEqual(self.states()["trust"], SignalState.MAP_UNAVAILABLE)
        self.daemon_start(trust=60)
        self.mon.check()
        self.assertEqual(self.mon.last_refresh["trust"], MapRefresh.OPENED)
        self.assertEqual(self.ts.read(HOST), (60, LookupStatus.OK))

    def test_pin_removed_keeps_old_fd_and_reports_unavailable(self):
        self.daemon_start(trust=20)
        self.make_stores()
        del self.k.pins[trust_mod.HOST_TRUST_MAP_PATH]
        self.assertEqual(self.states()["trust"], SignalState.MAP_UNAVAILABLE)
        self.assertEqual(self.ts.read(HOST), (20, LookupStatus.OK))   # old map still readable
        self.daemon_start(trust=70)
        self.mon.check()
        self.assertEqual(self.mon.last_refresh["trust"], MapRefresh.REPLACED)
        self.assertEqual(self.ts.get(HOST), 70)


class TestHeartbeatStates(TelemetryTestBase):
    def setUp(self):
        super().setUp()
        self.daemon_start(trust=80, risk=10)
        self.make_stores()

    def test_shared_fixture_parses(self):
        hb, problem = read_heartbeat(FIXTURE)   # same file the Rust test serialises to
        self.assertIsNone(problem)
        self.assertEqual((hb["incarnation"], hb["generation"], hb["trust_map_id"], hb["risk_map_id"]),
                         ("4242-123456789", 7, 101, 102))

    def test_fresh_after_cycle(self):
        self.daemon_cycle()
        self.assertEqual(self.states(), {"trust": SignalState.FRESH, "risk": SignalState.FRESH})

    def test_freshness_boundary(self):
        self.daemon_cycle()
        self.now += 5 * SEC
        self.assertEqual(self.states()["trust"], SignalState.FRESH)
        self.now += 1
        self.assertEqual(self.states()["trust"], SignalState.STALE)

    def test_crash_is_stale_while_maps_stay_readable(self):
        self.daemon_cycle()
        self.now += 6 * SEC                                  # daemon died; no more heartbeats
        self.assertEqual(self.states(), {"trust": SignalState.STALE, "risk": SignalState.STALE})
        self.assertEqual(self.ts.read(HOST), (80, LookupStatus.OK))

    def test_clean_stop(self):
        self.daemon_cycle()
        self.daemon_stop()
        self.assertEqual(self.states()["trust"], SignalState.DAEMON_STOPPED)

    def test_stuck_in_starting_becomes_stale(self):
        self.assertEqual(self.states()["trust"], SignalState.STARTING)
        self.now += 6 * SEC
        self.assertEqual(self.states()["trust"], SignalState.STALE)

    def test_pipeline_error_is_per_signal(self):
        self.daemon_cycle(trust_ok=True, risk_ok=False)
        self.assertEqual(self.states(), {"trust": SignalState.FRESH, "risk": SignalState.PIPELINE_ERROR})

    def test_missing_and_invalid_heartbeats(self):
        os.remove(self.hb_path)
        self.assertEqual(self.states()["trust"], SignalState.NO_HEARTBEAT)
        for content in ("{not json", json.dumps({"schema": 2}),
                        json.dumps(dict(self.hb, generation=True)),
                        json.dumps(dict(self.hb, state="weird"))):
            with self.subTest(content=content[:30]):
                with open(self.hb_path, "w") as f:
                    f.write(content)
                self.assertEqual(self.states()["trust"], SignalState.HEARTBEAT_INVALID)

    def test_heartbeat_from_future_is_invalid(self):
        self.hb["monotonic_ns"] = self.now + SEC
        self.hb["state"], self.hb["generation"] = "running", 1
        self.write_hb()
        self.assertEqual(self.states()["trust"], SignalState.HEARTBEAT_INVALID)

    def test_restart_sequence_and_recovery(self):
        self.daemon_cycle()
        self.assertEqual(self.states()["trust"], SignalState.FRESH)
        old_hb = dict(self.hb)

        # New daemon re-pins maps, but the old (still young) heartbeat file is what we read
        self.daemon_start(trust=40, risk=0)
        with open(self.hb_path, "w") as f:
            json.dump(old_hb, f)
        self.assertEqual(self.states()["trust"], SignalState.MAP_MISMATCH)

        self.write_hb()                                      # new incarnation, 'starting'
        self.assertEqual(self.states()["trust"], SignalState.STARTING)
        self.now += 2 * SEC
        self.daemon_cycle()
        self.assertEqual(self.states(), {"trust": SignalState.FRESH, "risk": SignalState.FRESH})
        self.assertEqual(self.mon.restarts, 1)
        self.assertEqual(self.ts.get(HOST), 40)

    def test_missing_entry_with_fresh_telemetry(self):
        self.daemon_cycle()
        self.assertEqual(self.states()["trust"], SignalState.FRESH)
        self.assertEqual(self.ts.read("10.0.0.77").status, LookupStatus.NO_ENTRY)


class TestReconcilerUsesRefreshedMaps(TelemetryTestBase):
    @patch('detector.hub.spawn')
    def test_restart_takes_effect_within_one_cycle(self, _spawn):
        from test_policy_reconciliation import FakeSwitch
        self.daemon_start(trust=10, risk=0)
        self.daemon_cycle()
        self.make_stores()
        sw = FakeSwitch(1)
        ctrl = SimpleNamespace(trust_store=self.ts, risk_store=self.rs, policy_engine=PolicyEngine(),
                               flow_installer=FlowInstaller(MagicMock()), datapaths={1: sw},
                               telemetry=self.mon)
        det = TrustChangeDetector(ctrl)
        det.register_host(HOST)
        det.reconcile_once()
        self.assertEqual(sw.adg_rules(HOST), [200])

        self.daemon_start(trust=10, risk=95)                # restart; new map has new values
        self.tmap.entries[HOST_KEY] = 75
        self.daemon_cycle()
        det.reconcile_once()                                 # refresh happens before decisions
        self.assertEqual(sw.adg_rules(HOST), [120])          # trust 75 + risk 95 -> MIRROR
        self.assertEqual(self.mon.state["trust"], SignalState.FRESH)

    @patch('detector.hub.spawn')
    def test_daemon_restart_during_drop_end_to_end(self, _spawn):
        """Real monitor + stores + fake kernel: DROP survives a restart that loses the entry,
        is held, then fails closed, and is released only when the new daemon re-scores the host."""
        from test_policy_reconciliation import FakeSwitch
        self.daemon_start(trust=10, risk=0)
        self.daemon_cycle()
        self.make_stores()
        sw = FakeSwitch(1)
        ctrl = SimpleNamespace(trust_store=self.ts, risk_store=self.rs, policy_engine=PolicyEngine(),
                               flow_installer=FlowInstaller(MagicMock()), datapaths={1: sw},
                               telemetry=self.mon)
        det = TrustChangeDetector(ctrl, clock=lambda: self.now / 1e9)
        det.register_host(HOST)
        det.reconcile_once()
        self.assertEqual(sw.adg_rules(HOST), [200])
        t_cycle = self.now

        self.now += 1 * SEC
        self.daemon_start()                                  # restart: empty maps, 'starting'
        det.reconcile_once()
        self.assertEqual(det.assess(HOST).trust.quality, Quality.HELD)
        self.now += 2 * SEC
        self.daemon_cycle()                                  # new daemon running; host not scored yet
        det.reconcile_once()
        self.assertEqual(self.mon.state["trust"], SignalState.FRESH)
        self.assertEqual(det.assess(HOST).trust, Resolved(10, Quality.HELD))
        self.assertEqual(sw.adg_rules(HOST), [200])

        self.now = t_cycle + 30 * SEC + 1                    # 30 s after the last valid observation
        self.daemon_cycle()
        det.reconcile_once()
        self.assertEqual(det.assess(HOST).trust.quality, Quality.UNAVAILABLE)
        self.assertEqual(sw.adg_rules(HOST), [200])          # still DROP: not released to trust 100

        self.tmap.entries[HOST_KEY] = 95                     # new daemon scores trust only so far:
        self.now += 2 * SEC                                  # risk was scored before and is now
        self.daemon_cycle()                                  # expired -> degraded risk action
        det.reconcile_once()
        self.assertEqual(sw.adg_rules(HOST), [120])
        self.rmap.entries[HOST_KEY] = 0                      # the daemon writes both in one cycle
        self.now += 2 * SEC
        self.daemon_cycle()
        det.reconcile_once()
        self.assertEqual(sw.adg_rules(HOST), [])
        self.assertEqual(det.assess(HOST).trust.quality, Quality.VALID)

    def test_check_runs_before_decisions(self):
        order = []
        ctrl = MagicMock()
        ctrl.datapaths = {1: MagicMock(id=1)}
        ctrl.telemetry.check.side_effect = lambda: order.append("check") or {}
        ctrl.telemetry.state = {}
        ctrl.trust_store.read.side_effect = lambda ip: order.append("trust") or Reading(100, LookupStatus.OK)
        ctrl.risk_store.read.return_value = Reading(0, LookupStatus.OK)
        ctrl.policy_engine.decide_resolved.return_value = Action.ALLOW
        with patch('detector.hub.spawn'):
            det = TrustChangeDetector(ctrl)
        det.register_host(HOST)
        det.reconcile_once()
        self.assertEqual(order, ["check", "trust"])


if __name__ == '__main__':
    unittest.main()
