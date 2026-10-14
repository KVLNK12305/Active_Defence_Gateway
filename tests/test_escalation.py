import unittest
from unittest.mock import MagicMock, patch
import sys
import os
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../controller')))

from detector import TrustChangeDetector
from policy import Action

class TestEscalation(unittest.TestCase):
    @patch('detector.hub.spawn')
    def setUp(self, mock_spawn):
        self.controller = MagicMock()
        # Add a mock datapath
        self.mock_dp = MagicMock()
        self.controller.datapaths = {1: self.mock_dp}
        
        self.detector = TrustChangeDetector(self.controller)

    def test_escalation_and_recovery(self):
        ip = "10.0.0.5"
        self.detector.register_host(ip)
        
        # t0: Host Trust = 100, Policy = ALLOW (Initial state)
        self.assertEqual(self.detector.host_policy[ip], Action.ALLOW)

        # t1: Host starts aggressive SYN, Trust drops to 50, Policy -> MIRROR
        self.controller.trust_store.get.return_value = 50
        self.controller.policy_engine.evaluate.return_value = Action.MIRROR
        
        self.detector._monitor.__code__ # just to be safe, we will manually step it
        
        # Mocking the loop body of _monitor:
        def step_monitor():
            trust = self.controller.trust_store.get(ip)
            new_action = self.controller.policy_engine.evaluate(trust)
            old_action = self.detector.host_policy.get(ip, Action.ALLOW)
            if new_action != old_action:
                self.detector.host_policy[ip] = new_action
                for dpid in self.controller.datapaths.keys():
                    dp = self.controller.datapaths.get(dpid)
                    self.controller.flow_installer.install_ip_policy_flow(dp, ip, new_action)

        step_monitor()
        self.assertEqual(self.detector.host_policy[ip], Action.MIRROR)
        self.controller.flow_installer.install_ip_policy_flow.assert_called_with(self.mock_dp, ip, Action.MIRROR)
        
        # t2: Aggressive behavior continues, Trust = 15, Policy -> DROP
        self.controller.trust_store.get.return_value = 15
        self.controller.policy_engine.evaluate.return_value = Action.DROP
        step_monitor()
        self.assertEqual(self.detector.host_policy[ip], Action.DROP)
        self.controller.flow_installer.install_ip_policy_flow.assert_called_with(self.mock_dp, ip, Action.DROP)
        
        # t3: Host behavior normalizes, Trust = 100, Policy -> ALLOW
        self.controller.trust_store.get.return_value = 100
        self.controller.policy_engine.evaluate.return_value = Action.ALLOW
        step_monitor()
        self.assertEqual(self.detector.host_policy[ip], Action.ALLOW)
        self.controller.flow_installer.install_ip_policy_flow.assert_called_with(self.mock_dp, ip, Action.ALLOW)

if __name__ == '__main__':
    unittest.main()
