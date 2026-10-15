import unittest
from unittest.mock import MagicMock, patch
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../controller')))

from detector import TrustChangeDetector
from policy import Action

class TestEscalation(unittest.TestCase):
    @patch('detector.hub.spawn')
    def setUp(self, mock_spawn):
        self.controller = MagicMock()
        # Add a mock datapath
        self.mock_dp = MagicMock()
        self.mock_dp.id = 1
        self.controller.datapaths = {1: self.mock_dp}
        self.controller.risk_store.get.return_value = 0

        self.detector = TrustChangeDetector(self.controller)

    def test_escalation_and_recovery(self):
        ip = "10.0.0.5"
        self.detector.register_host(ip)
        installer = self.controller.flow_installer

        # t0: Host Trust = 100, Policy = ALLOW
        self.controller.trust_store.get.return_value = 100
        self.controller.policy_engine.evaluate.return_value = Action.ALLOW
        self.detector.reconcile_once()
        self.assertEqual(self.detector.installed[(1, ip)], Action.ALLOW)
        self.controller.policy_engine.evaluate.assert_called_with(100, 0)

        # t1: Host starts aggressive SYN, Trust drops to 50, Policy -> MIRROR
        self.controller.trust_store.get.return_value = 50
        self.controller.policy_engine.evaluate.return_value = Action.MIRROR
        self.detector.reconcile_once()
        self.assertEqual(self.detector.installed[(1, ip)], Action.MIRROR)
        installer.install_ip_policy_flow.assert_called_with(self.mock_dp, ip, Action.MIRROR)

        # t2: Aggressive behavior continues, Trust = 15, Policy -> DROP
        self.controller.trust_store.get.return_value = 15
        self.controller.policy_engine.evaluate.return_value = Action.DROP
        self.detector.reconcile_once()
        self.assertEqual(self.detector.installed[(1, ip)], Action.DROP)
        installer.install_ip_policy_flow.assert_called_with(self.mock_dp, ip, Action.DROP)

        # t3: Host behavior normalizes, Trust = 100, Policy -> ALLOW
        self.controller.trust_store.get.return_value = 100
        self.controller.policy_engine.evaluate.return_value = Action.ALLOW
        self.detector.reconcile_once()
        self.assertEqual(self.detector.installed[(1, ip)], Action.ALLOW)
        installer.install_ip_policy_flow.assert_called_with(self.mock_dp, ip, Action.ALLOW)

if __name__ == '__main__':
    unittest.main()
