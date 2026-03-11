#!/usr/bin/env python3
"""
SDP Ryu Controller Application
-------------------------------
Implements the SDP access policy via OpenFlow 1.3.
Uses explicit output:PORT actions instead of NORMAL to avoid
OVS MAC learning issues with Mininet host namespaces.

Policy:
  client  (10.0.0.1) → sdp_ctrl (10.0.0.2) : UDP 62201  (SPA)
  client  (10.0.0.1) → gateway  (10.0.0.3) : UDP 51820  (WireGuard)
  gateway (10.0.0.3) → resource (10.0.0.4) : TCP 22     (SSH)
  resource(10.0.0.4) → gateway  (10.0.0.3) : TCP 22 return
  ARP                                        : flooded
  EVERYTHING ELSE                            : DROP

How to run:
  ryu-manager sdp_ryu_app.py
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4

# ── IP addresses ─────────────────────────────────────────────────────────────
IP_CLIENT   = '10.0.0.1'
IP_CTRL     = '10.0.0.2'
IP_GATEWAY  = '10.0.0.3'
IP_RESOURCE = '10.0.0.4'

# ── Ports ─────────────────────────────────────────────────────────────────────
PORT_SPA = 62201
PORT_WG   = 51820
PORT_MTLS = 5000    # mTLS: gateway ↔ sdp_ctrl
PORT_SSH = 22

# ── Flow priorities ───────────────────────────────────────────────────────────
PRIORITY_DROP   = 1
PRIORITY_ARP    = 100
PRIORITY_POLICY = 200
PRIORITY_BLOCK  = 300


class SDPController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDPController, self).__init__(*args, **kwargs)
        # dpid -> {peer_name -> port_no}
        # Populated dynamically when switches connect via packet-in / port-desc
        self.port_map = {}
        self.logger.info('SDP Controller starting — waiting for switches...')

    # ================================================================== #
    #  Switch connect — discover ports then install flows                 #
    # ================================================================== #
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid     = datapath.id
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        self.logger.info(f'Switch connected: dpid={dpid:#010x}')

        # Request port descriptions so we know which port connects where
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

        # Install a temporary table-miss → packet-in rule so ARP works
        # while we wait for port info. Will be replaced by explicit rules.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_handler(self, ev):
        """Receive port descriptions and install explicit flows."""
        datapath = ev.msg.datapath
        dpid     = datapath.id

        ports = {}   # port_name -> port_no
        for p in ev.msg.body:
            ports[p.name.decode()] = p.port_no
            self.logger.info(f'  dpid={dpid:#010x} port {p.port_no}: {p.name.decode()}')

        self.port_map[dpid] = ports
        self.logger.info(f'Port map for dpid={dpid:#010x}: {ports}')
        self._install_sdp_flows(datapath, ports)

    # ================================================================== #
    #  Packet-in — handle ARP and log unmatched IP packets                #
    # ================================================================== #
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']

        pkt     = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if not eth_pkt:
            return

        # Flood ARP so hosts resolve MACs correctly
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            )
            datapath.send_msg(out)
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            self.logger.warning(
                f'UNMATCHED pkt dpid={datapath.id:#010x} '
                f'in_port={in_port} '
                f'{ip_pkt.src} → {ip_pkt.dst} proto={ip_pkt.proto}'
            )

    # ================================================================== #
    #  Flow installation with explicit output ports                       #
    # ================================================================== #
    def _install_sdp_flows(self, datapath, ports):
        """
        Install SDP policy flows using explicit output:PORT_NO actions.

        Port naming convention in Mininet:
          s1-eth1 = host port (client)
          s1-eth2, s1-eth3 = switch-to-switch ports
          s2-eth1 = host port (sdp_ctrl)   etc.
          s4-eth1 = uplink to s3
          s4-eth2 = host port (resource)
        """
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        dpid    = datapath.id

        # ── helper ────────────────────────────────────────────────────
        def port(name):
            """Return port number for a given interface name."""
            p = ports.get(name)
            if p is None:
                self.logger.error(f'Port {name} not found on dpid={dpid:#010x}')
            return p

        def allow(priority, match_kwargs, out_port):
            if out_port is None:
                return
            match   = parser.OFPMatch(**match_kwargs)
            actions = [parser.OFPActionOutput(out_port)]
            self._add_flow(datapath, priority, match, actions)

        def drop(priority, match_kwargs):
            match = parser.OFPMatch(**match_kwargs)
            self._add_flow(datapath, priority, match, [])

        # Remove temporary table-miss rule
        self._del_flow(datapath, 0, parser.OFPMatch())

        # ── Default deny ──────────────────────────────────────────────
        drop(PRIORITY_DROP, {})

        # ── ARP flood on all switches ─────────────────────────────────
        match = parser.OFPMatch(eth_type=0x0806)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self._add_flow(datapath, PRIORITY_ARP, match, actions)

        # ── Hard blocks (highest priority, enforced on every switch) ──
        drop(PRIORITY_BLOCK, dict(eth_type=0x0800,
                                   ipv4_src=IP_CLIENT,   ipv4_dst=IP_RESOURCE))
        drop(PRIORITY_BLOCK, dict(eth_type=0x0800,
                                   ipv4_src=IP_RESOURCE, ipv4_dst=IP_CLIENT))
        drop(PRIORITY_BLOCK, dict(eth_type=0x0800,
                                   ipv4_src=IP_RESOURCE, ipv4_dst=IP_CTRL))
        drop(PRIORITY_BLOCK, dict(eth_type=0x0800,
                                   ipv4_src=IP_CTRL,     ipv4_dst=IP_RESOURCE))

        # ── Per-switch explicit forwarding rules ──────────────────────
        # ─────────────────────────────────────────────────────────────
        # S1  ports: s1-eth1=client  s1-eth2=s2  s1-eth3=s3
        # ─────────────────────────────────────────────────────────────
        if dpid == 1:
            h  = port('s1-eth1')   # client
            p2 = port('s1-eth2')   # towards s2 (sdp_ctrl)
            p3 = port('s1-eth3')   # towards s3 (gateway/resource)

            # client → sdp_ctrl (SPA)
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=17,
                       ipv4_src=IP_CLIENT, ipv4_dst=IP_CTRL, udp_dst=PORT_SPA), p2)
            # client → gateway (WireGuard)
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=17,
                       ipv4_src=IP_CLIENT, ipv4_dst=IP_GATEWAY, udp_dst=PORT_WG), p3)
            # sdp_ctrl → client (return)
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=17,
                       ipv4_src=IP_CTRL, ipv4_dst=IP_CLIENT, udp_src=PORT_SPA), h)
            # gateway → client (WireGuard return)
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=17,
                       ipv4_src=IP_GATEWAY, ipv4_dst=IP_CLIENT, udp_src=PORT_WG), h)
            # gateway → sdp_ctrl (mTLS TCP 5000) transit via s1
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=6,
                       ipv4_src=IP_GATEWAY, ipv4_dst=IP_CTRL, tcp_dst=PORT_MTLS), p2)
            # sdp_ctrl → gateway (mTLS return) transit via s1
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=6,
                       ipv4_src=IP_CTRL, ipv4_dst=IP_GATEWAY, tcp_src=PORT_MTLS), p3)

        # ─────────────────────────────────────────────────────────────
        # S2  ports: s2-eth1=sdp_ctrl  s2-eth2=s1  s2-eth3=s3
        # ─────────────────────────────────────────────────────────────
        elif dpid == 2:
            h  = port('s2-eth1')   # sdp_ctrl
            p1 = port('s2-eth2')   # towards s1 (client)
            p3 = port('s2-eth3')   # towards s3 (gateway)

            # client → sdp_ctrl (SPA arrives from s1)
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=17,
                       ipv4_src=IP_CLIENT, ipv4_dst=IP_CTRL, udp_dst=PORT_SPA), h)
            # sdp_ctrl → client (return via s1)
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=17,
                       ipv4_src=IP_CTRL, ipv4_dst=IP_CLIENT, udp_src=PORT_SPA), p1)
            # sdp_ctrl → gateway (WireGuard — optional, ctrl may need gateway)
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=17,
                       ipv4_src=IP_CTRL, ipv4_dst=IP_GATEWAY, udp_dst=PORT_WG), p3)
            # sdp_ctrl → gateway (mTLS TCP 5000) — sdp_ctrl is server, gateway connects
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=6,
                       ipv4_src=IP_CTRL, ipv4_dst=IP_GATEWAY, tcp_src=PORT_MTLS), p3)
            # gateway → sdp_ctrl (mTLS — incoming connection)
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=6,
                       ipv4_src=IP_GATEWAY, ipv4_dst=IP_CTRL, tcp_dst=PORT_MTLS), h)

        # ─────────────────────────────────────────────────────────────
        # S3  ports: s3-eth1=gateway  s3-eth2=s2  s3-eth3=s1  s3-eth4=s4
        # ─────────────────────────────────────────────────────────────
        elif dpid == 3:
            h  = port('s3-eth1')   # gateway host
            p1 = port('s3-eth3')   # towards s1 (client)   FIX: was s3-eth2
            p2 = port('s3-eth2')   # towards s2 (sdp_ctrl) FIX: was s3-eth3
            p4 = port('s3-eth4')   # towards s4 (resource)

            # client → gateway (WireGuard, arrives from s1)
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=17,
                       ipv4_src=IP_CLIENT, ipv4_dst=IP_GATEWAY, udp_dst=PORT_WG), h)
            # gateway → client (WireGuard return, via s1)
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=17,
                       ipv4_src=IP_GATEWAY, ipv4_dst=IP_CLIENT, udp_src=PORT_WG), p1)
            # gateway → resource (SSH)
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=6,
                       ipv4_src=IP_GATEWAY, ipv4_dst=IP_RESOURCE, tcp_dst=PORT_SSH), p4)
            # resource → gateway (SSH return)
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=6,
                       ipv4_src=IP_RESOURCE, ipv4_dst=IP_GATEWAY, tcp_src=PORT_SSH), h)
            # client → sdp_ctrl transit via s3 (s1→s3→s2 path)
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=17,
                       ipv4_src=IP_CLIENT, ipv4_dst=IP_CTRL, udp_dst=PORT_SPA), p2)
            # sdp_ctrl → client transit via s3 (s2→s3→s1 path)
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=17,
                       ipv4_src=IP_CTRL, ipv4_dst=IP_CLIENT, udp_src=PORT_SPA), p1)
            # gateway → sdp_ctrl (mTLS TCP 5000) transit via s3
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=6,
                       ipv4_src=IP_GATEWAY, ipv4_dst=IP_CTRL, tcp_dst=PORT_MTLS), p2)
            # sdp_ctrl → gateway (mTLS return) transit via s3
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=6,
                       ipv4_src=IP_CTRL, ipv4_dst=IP_GATEWAY, tcp_src=PORT_MTLS), h)

        # ─────────────────────────────────────────────────────────────
        # S4  ports: s4-eth1=resource  s4-eth2=s3
        # ─────────────────────────────────────────────────────────────
        elif dpid == 4:
            p3 = port("s4-eth2")   # towards s3 (gateway)
            h  = port("s4-eth1")   # resource host

            # gateway → resource (SSH)
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=6,
                       ipv4_src=IP_GATEWAY, ipv4_dst=IP_RESOURCE, tcp_dst=PORT_SSH), h)
            # resource → gateway (SSH return)
            allow(PRIORITY_POLICY,
                  dict(eth_type=0x0800, ip_proto=6,
                       ipv4_src=IP_RESOURCE, ipv4_dst=IP_GATEWAY, tcp_src=PORT_SSH), p3)

        self.logger.info(f'✓ Flows installed on dpid={dpid:#010x}')
        if dpid == 4:
            self._log_policy()

    # ================================================================== #
    #  Flow mod helpers                                                    #
    # ================================================================== #
    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        inst    = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)

    def _del_flow(self, datapath, priority, match):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=priority,
            match=match
        )
        datapath.send_msg(mod)

    # ================================================================== #
    #  Logging                                                             #
    # ================================================================== #
    def _log_policy(self):
        self.logger.info('─' * 55)
        self.logger.info('SDP POLICY ACTIVE (explicit port forwarding):')
        self.logger.info(f'  {IP_CLIENT} → {IP_CTRL}     UDP {PORT_SPA}  ✓ SPA')
        self.logger.info(f'  {IP_CLIENT} → {IP_GATEWAY}  UDP {PORT_WG}   ✓ WireGuard')
        self.logger.info(f'  {IP_GATEWAY} → {IP_RESOURCE} TCP {PORT_SSH}  ✓ SSH')
        self.logger.info(f'  {IP_RESOURCE} ↔ client/ctrl               ✗ BLOCKED')
        self.logger.info(f'  gateway ↔ sdp_ctrl TCP 5000               ✓ mTLS ')
        self.logger.info(f'  ALL OTHER TRAFFIC                          ✗ DROP')
        self.logger.info('─' * 55)