from policy import Action

# Identifies ADG IP-level policy rules (eth_type=IPv4, ipv4_src=<host>) in FlowRemoved messages.
ADG_IP_POLICY_COOKIE = 0xAD60001
# IP-level policy tiers; ALLOW is the absence of an ADG IP-level rule.
IP_POLICY_PRIORITY = {Action.MIRROR: 120, Action.DROP: 200}

class FlowInstaller:
    def __init__(self, logger):
        self.logger = logger

    def install_default_flow(self, datapath, match, actions, priority=0):
        """Installs initial or proactive default flows (e.g. priority 0 table-miss or priority 10 ARP broadcast)"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)

    def install_policy_flow(self, datapath, match, action, msg_buffer_id, out_port=None):
        """Installs a flow rule based on the trust policy Action"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        priority = 0
        hard_timeout = 0
        idle_timeout = 0
        actions = []

        if action == Action.DROP:
            priority = 200
            hard_timeout = 30
            idle_timeout = 10
            # No actions == drop
        elif action == Action.MIRROR:
            priority = 120
            idle_timeout = 60
            if out_port is not None:
                actions = [parser.OFPActionOutput(out_port)]
        elif action == Action.ALLOW:
            priority = 1
            idle_timeout = 60
            if out_port:
                actions = [parser.OFPActionOutput(out_port)]

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        kwargs = {
            'datapath': datapath,
            'priority': priority,
            'match': match,
            'instructions': inst,
            'idle_timeout': idle_timeout,
            'hard_timeout': hard_timeout
        }
        
        if msg_buffer_id != ofproto.OFP_NO_BUFFER:
            kwargs['buffer_id'] = msg_buffer_id

        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)
        self.logger.debug("Installed flow: Priority=%s, Action=%s", priority, action.name)

    def install_ip_policy_flow(self, datapath, ip, action):
        """Makes `action` the only ADG IP-level policy rule for `ip` on `datapath` (ALLOW = no rule).

        The new tier is added before the other tier is removed, so there is no unenforced gap and
        no window with contradictory tiers left behind. Removals are strict (exact
        eth_type+ipv4_src match and ADG priority), so rules installed by anything else -- including
        more specific rules for the same source -- are never touched.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)

        if action in IP_POLICY_PRIORITY:
            actions = []  # DROP: no actions == drop
            if action == Action.MIRROR:
                # Forward traffic normally AND send a copy to controller for inspection.
                # OFPP_NORMAL: let OVS handle L2 forwarding as usual.
                # OFPP_CONTROLLER: duplicate a packet header copy (128 bytes) for the SDN controller.
                actions = [
                    parser.OFPActionOutput(ofproto.OFPP_NORMAL),
                    parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, 128),
                ]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(
                datapath=datapath,
                cookie=ADG_IP_POLICY_COOKIE,
                priority=IP_POLICY_PRIORITY[action],
                match=match,
                instructions=inst,
                idle_timeout=60,
                # FlowRemoved lets the reconciler notice idle expiry / deletion by another controller
                flags=ofproto.OFPFF_SEND_FLOW_REM
            )
            datapath.send_msg(mod)

        for other, priority in IP_POLICY_PRIORITY.items():
            if other != action:
                mod = parser.OFPFlowMod(
                    datapath=datapath,
                    command=ofproto.OFPFC_DELETE_STRICT,
                    priority=priority,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=match
                )
                datapath.send_msg(mod)
        self.logger.debug("Applied IP policy: IP=%s, Action=%s", ip, action.name)
