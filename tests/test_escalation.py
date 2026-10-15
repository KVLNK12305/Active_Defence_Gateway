import unittest
from unittest.mock import MagicMock, patch
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../controller')))

from detector import TrustChangeDetector
from policy import Action, Quality, Resolved
from telemetry import Reading, LookupStatus

class TestEscalation(unittest.TestCase):
    @patch('detector.hub.spawn')
    def setUp(self, mock_spawn):
        self.controller = MagicMock()
        # Add a mock datapath
        self.mock_dp = MagicMock()
        self.mock_dp.id = 1
        self.controller.datapaths = {1: self.mock_dp}
        self.controller.telemetry = None
        self.controller.risk_store.read.return_value = Reading(0, LookupStatus.OK)

        self.detector = TrustChangeDetector(self.controller)

    def test_escalation_and_recovery(self):
        ip = "10.0.0.5"
        self.detector.register_host(ip)
        installer = self.controller.flow_installer

        # t0: Host Trust = 100, Policy = ALLOW
        self.controller.trust_store.read.return_value = Reading(100, LookupStatus.OK)
        self.controller.policy_engine.decide_resolved.return_value = Action.ALLOW
        self.detector.reconcile_once()
        self.assertEqual(self.detector.installed[(1, ip)], Action.ALLOW)
        self.controller.policy_engine.decide_resolved.assert_called_with(
            Resolved(100, Quality.VALID), Resolved(0, Quality.VALID))

        # t1: Host starts aggressive SYN, Trust drops to 50, Policy -> MIRROR
        self.controller.trust_store.read.return_value = Reading(50, LookupStatus.OK)
        self.controller.policy_engine.decide_resolved.return_value = Action.MIRROR
        self.detector.reconcile_once()
        self.assertEqual(self.detector.installed[(1, ip)], Action.MIRROR)
        installer.install_ip_policy_flow.assert_called_with(self.mock_dp, ip, Action.MIRROR)

        # t2: Aggressive behavior continues, Trust = 15, Policy -> DROP
        self.controller.trust_store.read.return_value = Reading(15, LookupStatus.OK)
        self.controller.policy_engine.decide_resolved.return_value = Action.DROP
        self.detector.reconcile_once()
        self.assertEqual(self.detector.installed[(1, ip)], Action.DROP)
        installer.install_ip_policy_flow.assert_called_with(self.mock_dp, ip, Action.DROP)

        # t3: Host behavior normalizes, Trust = 100, Policy -> ALLOW
        self.controller.trust_store.read.return_value = Reading(100, LookupStatus.OK)
        self.controller.policy_engine.decide_resolved.return_value = Action.ALLOW
        self.detector.reconcile_once()
        self.assertEqual(self.detector.installed[(1, ip)], Action.ALLOW)
        installer.install_ip_policy_flow.assert_called_with(self.mock_dp, ip, Action.ALLOW)

if __name__ == '__main__':
    unittest.main()
