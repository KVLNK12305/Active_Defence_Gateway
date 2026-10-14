import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Add controller dir to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../controller')))

from adg_controller import ADGController
from policy import Action
from os_ken.lib.packet import packet, ethernet, ipv4

class TestADGController(unittest.TestCase):
    def setUp(self):
        # Create controller instance
        self.controller = ADGController()
        # Mock TrustStore, PolicyEngine, logger, FlowInstaller as MagicMocks
        self.trust_store_mock = MagicMock()
        self.risk_store_mock = MagicMock()
        self.policy_engine_mock = MagicMock()
        self.logger_mock = MagicMock()
        self.flow_installer_mock = MagicMock()

        self.controller.trust_store = self.trust_store_mock  # type: ignore
        self.controller.risk_store = self.risk_store_mock  # type: ignore
        self.controller.policy_engine = self.policy_engine_mock  # type: ignore
        self.controller.logger = self.logger_mock  # type: ignore
        self.controller.flow_installer = self.flow_installer_mock  # type: ignore

    def _create_mock_event(self, src_ip='10.0.0.1', dst_ip='10.0.0.2', src_mac='00:00:00:00:00:01', dst_mac='00:00:00:00:00:02'):
        ev = MagicMock()
        ev.msg.datapath.id = 1
        ev.msg.datapath.ofproto = MagicMock()
        ev.msg.datapath.ofproto.OFP_NO_BUFFER = 0xffffffff
        ev.msg.datapath.ofproto.OFPP_FLOOD = 0xfffffffb
        ev.msg.match = {"in_port": 1}
        ev.msg.buffer_id = 0xffffffff
        
        pkt = packet.Packet()
        eth = ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=0x0800)
        ip = ipv4.ipv4(src=src_ip, dst=dst_ip)
        pkt.add_protocol(eth)
        pkt.add_protocol(ip)
        pkt.serialize()
        ev.msg.data = pkt.data
        return ev

    def test_packet_in_handler_allow(self):
        ev = self._create_mock_event()
        self.trust_store_mock.get.return_value = 100
        self.policy_engine_mock.evaluate.return_value = Action.ALLOW

        # Pre-populate dst MAC in mac_to_port so out_port != FLOOD
        self.controller.mac_to_port[1] = {'00:00:00:00:00:02': 2}

        self.controller.packet_in_handler(ev)

        self.trust_store_mock.get.assert_called_with('10.0.0.1')
        self.risk_store_mock.get.assert_called_with('10.0.0.1')
        self.policy_engine_mock.evaluate.assert_called_with(100, self.risk_store_mock.get.return_value)
        self.flow_installer_mock.install_policy_flow.assert_called_once()
        self.flow_installer_mock.install_ip_policy_flow.assert_not_called()

    def test_packet_in_handler_mirror(self):
        ev = self._create_mock_event()
        self.trust_store_mock.get.return_value = 50
        self.policy_engine_mock.evaluate.return_value = Action.MIRROR

        self.controller.packet_in_handler(ev)

        self.trust_store_mock.get.assert_called_with('10.0.0.1')
        self.risk_store_mock.get.assert_called_with('10.0.0.1')
        self.policy_engine_mock.evaluate.assert_called_with(50, self.risk_store_mock.get.return_value)
        self.flow_installer_mock.install_ip_policy_flow.assert_called_once_with(
            ev.msg.datapath, '10.0.0.1', Action.MIRROR
        )
        self.flow_installer_mock.install_policy_flow.assert_not_called()

    def test_packet_in_handler_drop(self):
        ev = self._create_mock_event()
        self.trust_store_mock.get.return_value = 10
        self.policy_engine_mock.evaluate.return_value = Action.DROP

        self.controller.packet_in_handler(ev)

        self.trust_store_mock.get.assert_called_with('10.0.0.1')
        self.risk_store_mock.get.assert_called_with('10.0.0.1')
        self.policy_engine_mock.evaluate.assert_called_with(10, self.risk_store_mock.get.return_value)
        self.flow_installer_mock.install_ip_policy_flow.assert_called_once_with(
            ev.msg.datapath, '10.0.0.1', Action.DROP
        )
        self.flow_installer_mock.install_policy_flow.assert_not_called()
        ev.msg.datapath.send_msg.assert_not_called()

    def test_switch_features_handler_requests_equal_role(self):
        """Verify switch_features_handler sends EQUAL role request and table-miss flow"""
        ev = MagicMock()
        ev.msg.datapath.id = 1
        ev.msg.datapath.ofproto = MagicMock()
        ev.msg.datapath.ofproto.OFPCR_ROLE_EQUAL = 2
        ev.msg.datapath.ofproto_parser = MagicMock()

        self.controller.switch_features_handler(ev)

        dp = ev.msg.datapath
        parser = dp.ofproto_parser

        # Verify OFPRoleRequest was constructed with EQUAL role
        parser.OFPRoleRequest.assert_called_once_with(dp, 2, 0)

        # Verify the role request was sent to the switch
        role_msg = parser.OFPRoleRequest.return_value
        dp.send_msg.assert_any_call(role_msg)

        # Verify default flows were installed (table-miss and proactive ARP broadcast rule)
        self.assertEqual(self.flow_installer_mock.install_default_flow.call_count, 2)

        # Verify datapath was registered
        self.assertIn(1, self.controller.datapaths)

if __name__ == '__main__':
    unittest.main()
