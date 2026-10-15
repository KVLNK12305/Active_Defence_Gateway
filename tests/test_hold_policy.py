"""Per-signal hold policy under degraded telemetry (decisions locked 2026-10-15):
5 s freshness (telemetry.py), 30 s maximum hold per signal measured from the last valid
observation, independent trust/risk, missing entry != outage, explicit degraded actions on
expiry (trust -> DROP, risk -> MIRROR by default), immediate recovery, explicit first contact."""
import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../controller')))
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from detector import TrustChangeDetector
from flow import FlowInstaller
from policy import Action, PolicyEngine, DegradedConfig, Quality, Resolved, _env_action
from telemetry import Reading, LookupStatus, SignalState
from test_policy_reconciliation import FakeSwitch

HOST = "10.0.0.1"
FRESH, STALE = SignalState.FRESH, SignalState.STALE


class Store:
    """Map stand-in: value per host, or a forced lookup status."""

    def __init__(self):
        self.values, self.status = {}, None

    def read(self, ip):
        if self.status is not None:
            return Reading(None, self.status)
        if ip in self.values:
            return Reading(self.values[ip], LookupStatus.OK)
        return Reading(None, LookupStatus.NO_ENTRY)


class HoldTestBase(unittest.TestCase):
    @patch('detector.hub.spawn')
    def setUp(self, _spawn):
        self.now = 0.0
        self.trust, self.risk = Store(), Store()
        self.telemetry = SimpleNamespace(state={"trust": FRESH, "risk": FRESH})
        self.telemetry.check = lambda: dict(self.telemetry.state)
        self.sw = FakeSwitch(1)
        self.ctrl = SimpleNamespace(trust_store=self.trust, risk_store=self.risk,
                                    policy_engine=PolicyEngine(), flow_installer=FlowInstaller(MagicMock()),
                                    datapaths={1: self.sw}, telemetry=self.telemetry)
        self.det = TrustChangeDetector(self.ctrl, clock=lambda: self.now)
        self.det.register_host(HOST)

    def maps(self, trust=None, risk=None):
        if trust is not None:
            self.trust.values[HOST] = trust
        if risk is not None:
            self.risk.values[HOST] = risk

    def tele(self, trust=FRESH, risk=FRESH):
        self.telemetry.state = {"trust": trust, "risk": risk}

    def at(self, t):
        self.now = t
        self.det.reconcile_once()
        return self.det.assess(HOST)

    def action_at(self, t):
        return self.at(t).action


class TestPrecedenceUnchangedForUsableValues(unittest.TestCase):
    def test_decide_resolved_equals_evaluate_for_valid_provisional_held(self):
        pe = PolicyEngine()
        for q in (Quality.VALID, Quality.PROVISIONAL, Quality.HELD):
            for trust in (0, 39, 40, 69, 70, 89, 90, 100):
                for risk in (0, 79, 80, 100):
                    with self.subTest(q=q, trust=trust, risk=risk):
                        self.assertEqual(pe.decide_resolved(Resolved(trust, q), Resolved(risk, q)),
                                         pe.evaluate(trust, risk))

    def test_unavailable_matrix(self):
        pe, U = PolicyEngine(), Resolved(None, Quality.UNAVAILABLE)
        V = lambda v: Resolved(v, Quality.VALID)
        cases = [  # trust, risk, expected (defaults: trust->DROP, risk->MIRROR)
            (V(10), U, Action.DROP), (V(39), U, Action.DROP),          # <40: DROP regardless
            (V(40), U, Action.MIRROR), (V(69), U, Action.MIRROR),      # 40-69: MIRROR regardless
            (V(70), U, Action.MIRROR), (V(100), U, Action.MIRROR),     # >=70: risk degraded action
            (U, V(0), Action.DROP), (U, V(100), Action.DROP), (U, U, Action.DROP),
        ]
        for trust, risk, expected in cases:
            with self.subTest(trust=trust, risk=risk):
                self.assertEqual(pe.decide_resolved(trust, risk), expected)

    def test_risk_degraded_action_never_overrides_trust_mirror_band(self):
        with patch.object(DegradedConfig, "RISK_UNAVAILABLE_ACTION", Action.DROP):
            pe = PolicyEngine()
            U = Resolved(None, Quality.UNAVAILABLE)
            self.assertEqual(pe.decide_resolved(Resolved(50, Quality.VALID), U), Action.MIRROR)
            self.assertEqual(pe.decide_resolved(Resolved(100, Quality.VALID), U), Action.DROP)

    def test_configured_actions_are_validated(self):
        with patch.dict(os.environ, {"ADG_X": "redirect"}):
            with self.assertRaises(ValueError):
                _env_action("ADG_X", "DROP")
        with patch.dict(os.environ, {"ADG_X": "allow"}):
            self.assertEqual(_env_action("ADG_X", "DROP"), Action.ALLOW)

    def test_defaults(self):
        self.assertEqual((DegradedConfig.MAX_HOLD_S, DegradedConfig.BOOTSTRAP_TRUST,
                          DegradedConfig.BOOTSTRAP_RISK, DegradedConfig.TRUST_UNAVAILABLE_ACTION,
                          DegradedConfig.RISK_UNAVAILABLE_ACTION),
                         (30.0, 100, 0, Action.DROP, Action.MIRROR))


class TestTrustHold(HoldTestBase):
    def test_trust_stale_holds_30s_from_last_valid_then_fails_closed(self):
        self.maps(trust=50, risk=0)
        self.assertEqual(self.action_at(0.0), Action.MIRROR)
        self.tele(trust=STALE)
        self.maps(trust=100)                                   # frozen map content is ignored
        a = self.at(6.0)
        self.assertEqual((a.trust, a.action), (Resolved(50, Quality.HELD), Action.MIRROR))
        self.assertEqual(self.action_at(30.0), Action.MIRROR)  # boundary: still held
        a = self.at(30.001)
        self.assertEqual((a.trust.quality, a.action), (Quality.UNAVAILABLE, Action.DROP))
        self.assertEqual(self.sw.adg_rules(HOST), [200])

    def test_trusted_host_is_not_released_to_trust_100_after_expiry(self):
        self.maps(trust=100, risk=0)
        self.assertEqual(self.action_at(0.0), Action.ALLOW)
        self.tele(trust=STALE)
        self.assertEqual(self.action_at(20.0), Action.ALLOW)   # held trusted value
        self.assertEqual(self.action_at(31.0), Action.DROP)    # explicit fail-closed, not trust 100

    def test_map_and_lookup_errors_never_become_valid(self):
        self.maps(trust=60, risk=0)
        self.at(0.0)
        for status in (LookupStatus.LOOKUP_ERROR, LookupStatus.MAP_UNAVAILABLE):
            with self.subTest(status=status):
                self.trust.status = status                     # telemetry itself reports FRESH
                a = self.at(10.0)
                self.assertEqual(a.trust, Resolved(60, Quality.HELD))
                self.assertEqual(self.det.last_valid[("trust", HOST)], (60, 0.0))  # not refreshed
        self.assertEqual(self.action_at(30.5), Action.DROP)


class TestRiskHoldAndIndependence(HoldTestBase):
    def test_risk_stale_holds_value_then_degraded_action(self):
        self.maps(trust=100, risk=90)
        self.assertEqual(self.action_at(0.0), Action.MIRROR)
        self.tele(risk=STALE)
        self.maps(risk=0)
        self.assertEqual(self.action_at(29.0), Action.MIRROR)  # held risk 90
        a = self.at(31.0)
        self.assertEqual((a.risk.quality, a.action), (Quality.UNAVAILABLE, Action.MIRROR))

    def test_low_risk_hold_then_degraded_mirror(self):
        self.maps(trust=100, risk=10)
        self.at(0.0)
        self.tele(risk=STALE)
        self.assertEqual(self.action_at(15.0), Action.ALLOW)
        self.assertEqual(self.action_at(31.0), Action.MIRROR)  # risk not silently treated as 0

    def test_fresh_trust_decisions_apply_while_risk_stale(self):
        self.maps(trust=100, risk=10)
        self.at(0.0)
        self.tele(risk=STALE)
        self.maps(trust=20)
        self.assertEqual(self.action_at(2.0), Action.DROP)     # <40 DROP regardless of risk
        self.maps(trust=50)
        self.assertEqual(self.action_at(40.0), Action.MIRROR)  # 40-69 MIRROR even after risk expiry

    def test_fresh_risk_applies_while_trust_held(self):
        self.maps(trust=100, risk=0)
        self.at(0.0)
        self.tele(trust=STALE)
        self.maps(risk=85)
        a = self.at(4.0)
        self.assertEqual((a.trust.quality, a.risk.quality, a.action),
                         (Quality.HELD, Quality.VALID, Action.MIRROR))

    def test_independent_timers(self):
        self.maps(trust=100, risk=0)
        self.at(0.0)
        self.tele(risk=STALE)
        self.at(20.0)                                          # trust refreshed at t=20
        self.tele(trust=STALE, risk=STALE)
        a = self.at(40.0)                                      # risk expired (t0=0), trust held (t0=20)
        self.assertEqual((a.trust.quality, a.risk.quality), (Quality.HELD, Quality.UNAVAILABLE))
        self.assertEqual(a.action, Action.MIRROR)
        a = self.at(50.5)
        self.assertEqual((a.trust.quality, a.action), (Quality.UNAVAILABLE, Action.DROP))


class TestStrictAge(HoldTestBase):
    """Hold age is measured from the observation (heartbeat time of the producing cycle), not
    from when the controller happened to read the frozen value."""

    def observed(self, trust, risk):
        self.telemetry.observed_s = {"trust": trust, "risk": risk}

    def test_reads_after_last_cycle_do_not_extend_hold(self):
        self.maps(trust=50, risk=0)
        self.observed(0.0, 0.0)                     # daemon's last completed cycle at t=0
        for t in (0.0, 2.0, 4.0):                   # still FRESH (< 5 s), values VALID
            self.assertEqual(self.at(t).trust.quality, Quality.VALID)
        self.assertEqual(self.det.last_valid[("trust", HOST)], (50, 0.0))
        self.tele(trust=STALE, risk=STALE)          # staleness detected at t=6
        self.observed(None, None)
        self.assertEqual(self.action_at(30.0), Action.MIRROR)
        self.assertEqual(self.action_at(30.001), Action.DROP)   # not 34.001 (last read)

    def test_without_heartbeat_read_time_is_used(self):
        self.maps(trust=50, risk=0)
        self.at(4.0)
        self.assertEqual(self.det.last_valid[("trust", HOST)], (50, 4.0))

    def test_signals_expire_independently_by_their_own_observation(self):
        self.maps(trust=100, risk=10)
        self.observed(0.0, 0.0)
        self.at(0.0)
        self.tele(risk=SignalState.PIPELINE_ERROR)  # risk pipeline broken from t=0, trust keeps cycling
        for t in (2.0, 10.0, 20.0):
            self.observed(t, None)
            self.at(t)
        self.tele(trust=STALE, risk=STALE)
        self.observed(None, None)
        a = self.at(30.5)                           # risk observed 0 -> expired; trust observed 20 -> held
        self.assertEqual((a.trust.quality, a.risk.quality, a.action),
                         (Quality.HELD, Quality.UNAVAILABLE, Action.MIRROR))
        self.assertEqual(self.at(50.0).trust.quality, Quality.HELD)
        a = self.at(50.001)
        self.assertEqual((a.trust.quality, a.action), (Quality.UNAVAILABLE, Action.DROP))


class TestBothStaleAndRecovery(HoldTestBase):
    def test_both_stale_alert_then_drop(self):
        self.maps(trust=100, risk=0)
        self.at(0.0)
        self.tele(trust=STALE, risk=STALE)
        with self.assertLogs("ADG-Detector", level="ERROR") as logs:
            self.assertEqual(self.action_at(31.0), Action.DROP)
        text = "\n".join(logs.output)
        self.assertIn("both degraded", text)
        self.assertIn("[TELEMETRY ALERT] Host=10.0.0.1 trust unavailable", text)

    def test_both_degraded_alert_only_on_transition(self):
        self.maps(trust=100, risk=0)
        self.at(0.0)
        self.tele(trust=STALE, risk=STALE)
        with self.assertLogs("ADG-Detector", level="INFO") as logs:
            for t in (2.0, 4.0, 6.0, 8.0):
                self.at(t)
            self.tele()
            self.at(10.0)
            self.at(12.0)
        text = "\n".join(logs.output)
        self.assertEqual(text.count("both degraded"), 1)
        self.assertEqual(text.count("no longer fully degraded"), 1)

    def test_recovery_applies_in_the_same_cycle(self):
        self.maps(trust=100, risk=0)
        self.at(0.0)
        self.tele(trust=STALE, risk=STALE)
        self.assertEqual(self.action_at(31.0), Action.DROP)
        self.assertEqual(self.sw.adg_rules(HOST), [200])
        self.tele()                                            # fresh data returns
        self.now = 33.0
        self.det.reconcile_once()                              # one cycle: check, then decide
        self.assertEqual(self.sw.adg_rules(HOST), [])
        a = self.det.assess(HOST)
        self.assertEqual((a.trust.quality, a.risk.quality), (Quality.VALID, Quality.VALID))


class TestFirstContactAndMissingEntries(HoldTestBase):
    def test_first_contact_is_provisional_bootstrap(self):
        a = self.at(0.0)                                       # fresh telemetry, no entries
        self.assertEqual((a.trust, a.risk, a.action),
                         (Resolved(100, Quality.PROVISIONAL), Resolved(0, Quality.PROVISIONAL), Action.ALLOW))
        self.assertNotIn(("trust", HOST), self.det.last_valid)  # bootstrap is never "valid"

    def test_first_contact_during_outage_fails_closed(self):
        self.tele(trust=STALE, risk=STALE)
        a = self.at(0.0)
        self.assertEqual((a.trust.quality, a.action), (Quality.UNAVAILABLE, Action.DROP))

    def test_entry_disappears_after_restart_holds_then_drops(self):
        # Restarted daemon has not scored this host yet: not an outage, but not evidence either.
        self.maps(trust=10, risk=0)
        self.assertEqual(self.action_at(0.0), Action.DROP)
        del self.trust.values[HOST]
        a = self.at(10.0)
        self.assertEqual((a.trust, a.action), (Resolved(10, Quality.HELD), Action.DROP))
        a = self.at(30.5)
        self.assertEqual((a.trust, a.action), (Resolved(None, Quality.UNAVAILABLE), Action.DROP))
        self.assertEqual(self.action_at(300.0), Action.DROP)  # never released to bootstrap trust 100
        self.maps(trust=95)                                    # fresh telemetry scores the host
        a = self.at(302.0)
        self.assertEqual((a.trust.quality, a.action), (Quality.VALID, Action.ALLOW))

    def test_trusted_host_entry_disappears_fails_closed_until_rescored(self):
        self.maps(trust=100, risk=0)
        self.at(0.0)
        del self.trust.values[HOST]
        self.assertEqual(self.action_at(29.0), Action.ALLOW)
        self.assertEqual(self.action_at(31.0), Action.DROP)
        self.maps(trust=100)
        self.assertEqual(self.action_at(33.0), Action.ALLOW)

    def test_mock_trust_counts_as_valid(self):
        with patch.dict(os.environ, {"ADG_MOCK_TRUST": "30"}):
            a = self.at(0.0)
        self.assertEqual((a.trust, a.action), (Resolved(30, Quality.VALID), Action.DROP))


class TestNoMonitor(HoldTestBase):
    def test_without_monitor_only_lookup_status_degrades(self):
        self.ctrl.telemetry = None
        self.maps(trust=55, risk=0)
        self.assertEqual(self.det.assess(HOST).trust.quality, Quality.VALID)
        self.trust.status = LookupStatus.MAP_UNAVAILABLE
        self.assertEqual(self.det.assess(HOST).trust.quality, Quality.HELD)


if __name__ == '__main__':
    unittest.main()
