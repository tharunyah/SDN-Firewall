from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp

class FirewallController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # Define block rules (IP and port based)
    BLOCK_RULES = [
        {"src_ip": "10.0.0.1", "dst_port": 23},   # Block Telnet
        {"src_ip": "10.0.0.1", "dst_port": 22},   # Block SSH
    ]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Default: allow all traffic
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 1, match, actions)

        # Install drop rules
        for rule in self.BLOCK_RULES:
            self.install_drop_rule(datapath, **rule)
            print(f"[*] Drop rule installed: {rule}")

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def install_drop_rule(self, datapath, src_ip=None, dst_port=None):
        parser = datapath.ofproto_parser
        match_fields = {"eth_type": 0x0800, "ip_proto": 6}  # IPv4 + TCP
        if src_ip:
            match_fields["ipv4_src"] = src_ip
        if dst_port:
            match_fields["tcp_dst"] = dst_port
        match = parser.OFPMatch(**match_fields)
        # Empty instructions = DROP
        mod = parser.OFPFlowMod(datapath=datapath, priority=100,
                                match=match, instructions=[])
        datapath.send_msg(mod)
