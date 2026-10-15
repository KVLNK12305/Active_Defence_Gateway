"""Regression tests for unified trust/risk enforcement: the background reconciler and the
PacketIn path share one decision function, and ADG IP-level rules converge to the desired action
on a simulated OVS flow table (real os_ken FlowMod objects, strict/non-strict delete semantics)."""
import unittest
import sys
import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../controller')))

from os_ken.ofproto import ofproto_v1_3 as ofp, ofproto_v1_3_parser as ofp_parser
from detector import TrustChangeDetector
from flow import FlowInstaller, ADG_IP_POLICY_COOKIE
from policy import Action, PolicyEngine

HOST = "10.0.0.1"
OTHER = "10.0.0.9"
ADG_MATCH = (("eth_type", 0x0800), ("ipv4_src", HOST))


class FakeSwitch:
    """Minimal OVS flow table: ADD replaces (priority, match); DELETE_STRICT removes exactly that
    entry; DELETE removes every entry whose match contains the given fields."""

    def __init__(self, dpid=1):
        self.id = dpid
        self.ofproto = ofp
        self.ofproto_parser = ofp_parser
        self.table = {}
        self.sent = []

    def send_msg(self, msg):
        self.sent.append(msg)
        if not isinstance(msg, ofp_parser.OFPFlowMod):
            return
        key = (msg.priority, tuple(sorted(msg.match.items())))
        if msg.command == ofp.OFPFC_ADD:
            self.table[key] = msg
        elif msg.command == ofp.OFPFC_DELETE_STRICT:
            self.table.pop(key, None)
        elif msg.command == ofp.OFPFC_DELETE:
            fields = set(msg.match.items())
            for k in [k for k in self.table if fields <= set(k[1])]:
                del self.table[k]

    def add_unrelated(self, priority, **match):
        self.send_msg(ofp_parser.OFPFlowMod(datapath=self, priority=priority,
                                            match=ofp_parser.OFPMatch(**match)))

    def adg_rules(self, ip=HOST):
        """Priorities of ADG IP-level rules for `ip` (exact eth_type+ipv4_src match)."""
        m = tuple(sorted((("eth_type", 0x0800), ("ipv4_src", ip))))
        return sorted(p for (p, k) in self.table if k == m)


class MapValues:
    """Stand-in for TrustStore/RiskStore backed by a mutable dict."""

    def __init__(self, default):
        self.values = {}
        self.default = default

    def get(self, ip):
        return self.values.get(ip, self.default)


class ReconcilerTestBase(unittest.TestCase):
    @patch('detector.hub.spawn')
    def setUp(self, _spawn):
        self.sw = FakeSwitch(1)
        self.trust = MapValues(100)
        self.risk = MapValues(0)
        self.controller = SimpleNamespace(
            trust_store=self.trust, risk_store=self.risk, policy_engine=PolicyEngine(),
            flow_installer=FlowInstaller(MagicMock()), datapaths={1: self.sw})
        self.det = TrustChangeDetector(self.controller)
        self.det.register_host(HOST)

    def set_maps(self, trust, risk):
        self.trust.values[HOST] = trust
        self.risk.values[HOST] = risk

    def cycle(self, trust, risk):
        self.set_maps(trust, risk)
        self.det.reconcile_once()
        return self.sw.adg_rules()


class TestRiskDrivenReconciliation(ReconcilerTestBase):
    def test_risk_rise_79_to_80_escalates_without_packet_in(self):
        self.assertEqual(self.cycle(100, 79), [])
        self.assertEqual(self.cycle(100, 80), [120])
        self.assertEqual(self.det.installed[(1, HOST)], Action.MIRROR)

    def test_risk_fall_80_to_79_restores_allow(self):
        self.assertEqual(self.cycle(100, 80), [120])
        self.assertEqual(self.cycle(100, 79), [])
        self.assertEqual(self.det.installed[(1, HOST)], Action.ALLOW)

    def test_trust_recovery_with_high_risk_keeps_mirror(self):
        self.assertEqual(self.cycle(50, 90), [120])      # trust-driven MIRROR
        sent = len(self.sw.sent)
        self.assertEqual(self.cycle(100, 90), [120])     # trust recovers, risk still >= 80
        self.assertEqual(len(self.sw.sent), sent, "MIRROR must not be torn down and re-added")
        self.assertEqual(self.cycle(100, 79), [])        # only risk falling releases it

    def test_drop_range_trust_stays_drop_at_high_risk(self):
        for trust in (0, 39):
            for risk in (80, 100):
                with self.subTest(trust=trust, risk=risk):
                    self.cycle(100, 0)
                    self.assertEqual(self.cycle(trust, risk), [200])

    def test_mirror_range_trust_stays_mirror_regardless_of_risk(self):
        for trust in (40, 55, 69):
            for risk in (0, 79, 80, 100):
                with self.subTest(trust=trust, risk=risk):
                    self.cycle(100, 0)
                    self.assertEqual(self.cycle(trust, risk), [120])

    def test_risk_rise_from_drop_does_not_weaken(self):
        self.assertEqual(self.cycle(10, 0), [200])
        self.assertEqual(self.cycle(10, 100), [200])


class TestRuleHygiene(ReconcilerTestBase):
    def setUp(self):
        super().setUp()
        # Rules ADG reconciliation must never touch
        self.sw.add_unrelated(0)                                            # table-miss
        self.sw.add_unrelated(10, eth_dst="ff:ff:ff:ff:ff:ff")              # ARP flood
        self.sw.add_unrelated(1, in_port=1, eth_src="00:00:00:00:00:01",
                              eth_dst="00:00:00:00:00:02")                  # learned L2 ALLOW
        self.sw.add_unrelated(120, eth_type=0x0800, ipv4_src=HOST, ip_proto=6)  # more specific, same src
        self.sw.add_unrelated(200, eth_type=0x0800, ipv4_src=OTHER)         # unmanaged host
        self.unrelated = {k for k in self.sw.table}

    def test_no_contradictory_rules_after_any_transition(self):
        # Every ordered pair of actions: ALLOW, MIRROR (trust), MIRROR (risk), DROP
        states = {"ALLOW": (100, 0), "MIRROR_T": (50, 0), "MIRROR_R": (100, 90), "DROP": (20, 100)}
        expected = {"ALLOW": [], "MIRROR_T": [120], "MIRROR_R": [120], "DROP": [200]}
        for a in states:
            for b in states:
                with self.subTest(transition=f"{a}->{b}"):
                    self.cycle(*states[a])
                    rules = self.cycle(*states[b])
                    self.assertEqual(rules, expected[b])
                    self.assertTrue(self.unrelated <= set(self.sw.table),
                                    "unrelated rule removed")

    def test_repeated_reconciliation_is_idempotent(self):
        for trust, risk, rules in ((100, 90, [120]), (10, 0, [200]), (100, 0, [])):
            self.cycle(trust, risk)
            sent, table = len(self.sw.sent), dict(self.sw.table)
            for _ in range(5):
                self.det.reconcile_once()
            self.assertEqual(len(self.sw.sent), sent, "converged state must send no FlowMods")
            self.assertEqual(self.sw.table, table)
            self.assertEqual(self.sw.adg_rules(), rules)

    def test_rules_are_tagged_and_request_flow_removed(self):
        self.cycle(100, 90)
        rule = self.sw.table[(120, tuple(sorted(ADG_MATCH)))]
        self.assertEqual(rule.cookie, ADG_IP_POLICY_COOKIE)
        self.assertTrue(rule.flags & ofp.OFPFF_SEND_FLOW_REM)


class TestStaleState(ReconcilerTestBase):
    def test_flow_removed_of_active_tier_is_reasserted(self):
        self.assertEqual(self.cycle(100, 90), [120])
        del self.sw.table[(120, tuple(sorted(ADG_MATCH)))]   # idle timeout on the switch
        self.det.on_rule_removed(1, HOST, 120)
        self.det.reconcile_once()
        self.assertEqual(self.sw.adg_rules(), [120])

    def test_flow_removed_of_replaced_tier_is_ignored(self):
        self.cycle(10, 0)                                      # DROP
        self.cycle(50, 0)                                      # -> MIRROR (strict-deletes DROP)
        self.det.on_rule_removed(1, HOST, 200)                 # FlowRemoved for the old DROP rule
        self.assertEqual(self.det.installed[(1, HOST)], Action.MIRROR)

    def test_switch_reconnect_reasserts(self):
        self.cycle(100, 90)
        self.sw.table.clear()                                  # switch restarted with empty table
        self.det.forget_datapath(1)
        self.det.reconcile_once()
        self.assertEqual(self.sw.adg_rules(), [120])

    def test_all_datapaths_converge(self):
        sw2 = FakeSwitch(2)
        self.controller.datapaths[2] = sw2
        self.cycle(100, 90)
        self.assertEqual(self.sw.adg_rules(), [120])
        self.assertEqual(sw2.adg_rules(), [120])

    def test_packet_in_and_background_share_state(self):
        # PacketIn path enforces on its switch; background cycle must then be a no-op there.
        self.set_maps(100, 85)
        _, _, action = self.det.decide(HOST)
        self.assertEqual(action, Action.MIRROR)
        self.assertTrue(self.det.enforce(self.sw, HOST, action))
        sent = len(self.sw.sent)
        self.det.reconcile_once()
        self.assertEqual(len(self.sw.sent), sent)


if __name__ == '__main__':
    unittest.main()
