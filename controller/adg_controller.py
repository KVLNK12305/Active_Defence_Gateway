from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import ipv4
import os
import time
from policy import Action, PolicyEngine
from trust import TrustStore
from risk import RiskStore
from flow import FlowInstaller, ADG_IP_POLICY_COOKIE, IP_POLICY_PRIORITY
from detector import TrustChangeDetector
from utils import get_logger, debug_packet

logger = get_logger("ADG")


class ADGController(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    

    def __init__(self, *args, **kwargs):
        super(ADGController, self).__init__(*args, **kwargs)
        self.controller_id = os.environ.get("ADG_CONTROLLER_ID", "C?")
        self.mac_to_port = {}
        self.policy_engine = PolicyEngine()
        self.trust_store = TrustStore()
        self.risk_store = RiskStore()
        self.flow_installer = FlowInstaller(self.logger)
        self.datapaths = {}
        self.detector = TrustChangeDetector(self)
        self.pkt_seen = {}

    # pyrefly: ignore [missing-attribute]
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        self.detector.forget_datapath(datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Claim EQUAL role so this controller can write flows
        # and receive async messages (PacketIn, PortStatus, etc.)
        role_request = parser.OFPRoleRequest(
            datapath, ofproto.OFPCR_ROLE_EQUAL, 0
        )
        datapath.send_msg(role_request)
        self.logger.info(
            "CONTROLLER=%s SWITCH_FEATURES DPID=%s Requested EQUAL role",
            self.controller_id, datapath.id
        )

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]
        self.flow_installer.install_default_flow(datapath, match, actions)

        # Proactive ARP broadcast rule: flood ARP directly in hardware (prevents multi-controller amplification)
        match_arp = parser.OFPMatch(eth_dst="ff:ff:ff:ff:ff:ff")
        actions_arp = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self.flow_installer.install_default_flow(datapath, match_arp, actions_arp, priority=10)

    # pyrefly: ignore [missing-attribute]
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        dst = eth.dst
        src = eth.src

        # PacketIn Deduplication Cache for EQUAL-mode Multi-Controller setups
        if os.environ.get("ADG_DISABLE_DEDUP") != "1":
            now = time.time()
            pkt_key = (dpid, in_port, src, dst)
            if pkt_key in self.pkt_seen and (now - self.pkt_seen[pkt_key]) < 1.0:
                return
            self.pkt_seen[pkt_key] = now

        self.logger.info(
            "CONTROLLER=%s PACKET_IN Switch=%s SRC=%s DST=%s IN=%s",
            self.controller_id,
            dpid,
            src,
            dst,
            in_port
        )

        # Learn source MAC
        self.mac_to_port[dpid][src] = in_port

        # Determine output port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        src_ip = None
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src  # type: ignore
            
            # Register with detector for background monitoring
            self.detector.register_host(src_ip)
            
            # Same decision function as the background reconciler (trust AND risk)
            trust, risk, decision = self.detector.decide(src_ip)
            priority = IP_POLICY_PRIORITY.get(decision, 1)

            logger.info("[POLICY]")
            logger.info(f"Host : {src_ip}")
            logger.info(f"Trust : {trust}")
            logger.info(f"Risk : {risk}")
            logger.info(f"Decision : {decision.name}")
            logger.info(f"Priority : {priority}")
        else:
            decision = Action.ALLOW

        match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)

        if src_ip:
            # Idempotent: only sends FlowMods when this host's ADG rule on this switch must change
            self.detector.enforce(datapath, src_ip, decision)
        if decision == Action.DROP:
            return

        # ALLOW path (or forwarding for first PacketIn of MIRROR)
        if decision == Action.ALLOW and out_port != ofproto.OFPP_FLOOD:
            self.flow_installer.install_policy_flow(datapath, match, Action.ALLOW, msg.buffer_id, out_port=out_port)

        # Send current packet out
        actions = [parser.OFPActionOutput(out_port)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    # pyrefly: ignore [missing-attribute]
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        msg = ev.msg
        if msg.cookie != ADG_IP_POLICY_COOKIE:
            return
        ip = msg.match.get("ipv4_src")
        if ip:
            self.detector.on_rule_removed(msg.datapath.id, ip, msg.priority)
