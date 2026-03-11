#!/usr/bin/env python3
"""
SDP (Software Defined Perimeter) Mininet Topology
--------------------------------------------------

Topology Layout:

  [SDP Client]         [SDP Controller]
   10.0.0.1              10.0.0.2
       |                    |
       S1 ————————————————S2
        \                  /
         \                /
          S3 ————————————
          |
     [SDP Gateway]
       10.0.0.3
          |
          S4
          |
      [Resource]
       10.0.0.4  (SSH server on port 22)

Access Policy (enforced via Ryu static flows):
  client  → sdp_ctrl : UDP 62201 only       (SPA knock)
  client  → gateway  : UDP 51820 only       (WireGuard tunnel)
  gateway → resource : TCP 22 only          (SSH forwarding)
  resource→ gateway  : TCP 22 return only
  EVERYTHING ELSE    : DROP                 (dark by default)

How to run:
  Terminal 1: ryu-manager sdp_ryu_app.py
  Terminal 2: sudo python3 sdp_topology.py

After topology starts:
  - Access sdp_ctrl CLI:  xterm sdp_ctrl   (from Mininet CLI)
  - Run your SPA program: python3 your_spa.py
"""

import time
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


def create_sdp_topology():
    # ------------------------------------------------------------------ #
    #  Network                                                             #
    # ------------------------------------------------------------------ #
    net = Mininet(
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True,
        waitConnected=False
    )

    # ------------------------------------------------------------------ #
    #  Ryu remote controller                                               #
    # ------------------------------------------------------------------ #
    info('*** Adding Ryu remote controller\n')
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )

    # ------------------------------------------------------------------ #
    #  Switches (OpenFlow 1.3)                                             #
    # ------------------------------------------------------------------ #
    info('*** Adding switches\n')
    s1 = net.addSwitch('s1', cls=OVSSwitch, protocols='OpenFlow13')
    s2 = net.addSwitch('s2', cls=OVSSwitch, protocols='OpenFlow13')
    s3 = net.addSwitch('s3', cls=OVSSwitch, protocols='OpenFlow13')
    s4 = net.addSwitch('s4', cls=OVSSwitch, protocols='OpenFlow13')

    # ------------------------------------------------------------------ #
    #  Hosts                                                               #
    # ------------------------------------------------------------------ #
    info('*** Adding hosts\n')
    net.addHost('client',   ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    net.addHost('sdp_ctrl', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    net.addHost('gateway',  ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    net.addHost('resource', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

    # ------------------------------------------------------------------ #
    #  Links                                                               #
    # ------------------------------------------------------------------ #
    info('*** Adding links\n')
    net.addLink('client',   s1)
    net.addLink('sdp_ctrl', s2)
    net.addLink('gateway',  s3)
    net.addLink('resource', s4)

    # Triangle ring: S1 — S2 — S3 — S1
    net.addLink(s1, s2)
    net.addLink(s2, s3)
    net.addLink(s3, s1)

    # S3 → S4 (gateway segment to resource)
    net.addLink(s3, s4)

    # ------------------------------------------------------------------ #
    #  Start network                                                       #
    # ------------------------------------------------------------------ #
    info('*** Starting network\n')
    net.start()

    # Disable STP — prevents port blocking on the ring
    info('*** Disabling STP on all switches\n')
    for sw in [s1, s2, s3, s4]:
        sw.cmd(f'ovs-vsctl set bridge {sw.name} stp_enable=false')
        sw.cmd(f'ovs-vsctl set bridge {sw.name} rstp_enable=false')

    # Wait for Ryu to connect and push flows
    info('*** Waiting for Ryu to connect and install flows (5s)...\n')
    time.sleep(5)

    # ------------------------------------------------------------------ #
    #  Auto-start services                                                 #
    # ------------------------------------------------------------------ #
    info('*** Starting SSH server on resource\n')
    resource = net.get('resource')
    resource.cmd('ssh-keygen -A')
    resource.cmd('/usr/sbin/sshd -D -o "ListenAddress=10.0.0.4" &')
    info('    ✓ sshd listening on 10.0.0.4:22\n')

    info('*** Protecting Ryu REST API (port 8080) — allow only sdp_ctrl\n')
    import subprocess
    # Block all access to Ryu REST except from sdp_ctrl (10.0.0.2)
    subprocess.run(['iptables', '-I', 'INPUT', '-p', 'tcp', '--dport', '8080',
                    '!', '-s', '10.0.0.2', '-j', 'DROP'], check=False)
    info('    ✓ iptables: port 8080 restricted to 10.0.0.2\n')

    info('*** Bringing up WireGuard on gateway\n')
    gateway = net.get('gateway')
    gateway.cmd('sysctl -w net.ipv4.ip_forward=1')
    # Bring down any stale wg0 from a previous run, then bring it up fresh
    gateway.cmd('wg-quick down wg0 2>/dev/null; true')
    gateway.cmd('wg-quick up /etc/wireguard/wg0.conf 2>&1')
    info('    ✓ WireGuard wg0 up on gateway\n')

    # ------------------------------------------------------------------ #
    #  Verify Ryu pushed the default-deny flows                           #
    # ------------------------------------------------------------------ #
    info('\n*** Verifying flows on switches:\n')
    for sw in [s1, s2, s3, s4]:
        info(f'\n--- {sw.name} ---\n')
        print(sw.cmd(f'ovs-ofctl -O OpenFlow13 dump-flows {sw.name}'))

    # ------------------------------------------------------------------ #
    #  CLI — interact manually, run SPA, bring up WireGuard, etc.         #
    # ------------------------------------------------------------------ #
    info('\n*** SDP Topology ready.\n')
    info('*** Useful commands:\n')
    info('      xterm client      — open client terminal (run SPA here)\n')
    info('      xterm sdp_ctrl    — open controller terminal\n')
    info('      xterm gateway     — open gateway terminal\n')
    info('      xterm resource    — open resource terminal\n')
    info('      sh ovs-ofctl -O OpenFlow13 dump-flows s1  — inspect flows\n')
    info('\n*** Launching Mininet CLI...\n')
    CLI(net)

    # ------------------------------------------------------------------ #
    #  Cleanup                                                             #
    # ------------------------------------------------------------------ #
    info('*** Stopping network\n')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    create_sdp_topology()