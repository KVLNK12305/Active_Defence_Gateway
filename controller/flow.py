from policy import Action

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
        """Installs or removes a global policy flow matching only ipv4_src"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip)
        
        if action == Action.ALLOW:
            # Delete any existing restrictive policy flows for this IP
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match
            )
            datapath.send_msg(mod)
            self.logger.debug("Deleted policy flows for IP=%s", ip)
            return

        priority = 0
        actions = []

        if action == Action.DROP:
            priority = 200
            # No actions == drop
        elif action == Action.MIRROR:
            priority = 120
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
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=60
        )
        datapath.send_msg(mod)
        self.logger.debug("Installed IP policy flow: IP=%s, Priority=%s, Action=%s", ip, priority, action.name)
