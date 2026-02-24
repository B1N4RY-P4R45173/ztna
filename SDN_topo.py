#!/usr/bin/env python3
"""
Mininet Topology for SDP Architecture with mTLS

Topology matches the architecture diagram:
- Client sends SPA directly to Controller (over internet)
- Controller sends mTLS commands to Gateway (over internet)
- Client connects to Gateway via WireGuard after SPA auth
- Gateway forwards to Backend on local network

                    Internet/Cloud
                         |
                   [Controller]
                     10.10.0.2
                    (SPA + mTLS)
                         |
            ┌────────────┴────────────┐
            |                         |
       (SPA packet)              (mTLS policy)
            |                         |
        [Client]                 [Gateway]
       10.10.1.3            10.10.0.3 (external)
            |                   10.10.1.2 (client-facing)
            |                   10.10.2.1 (backend-facing)
            |                   10.9.0.1 (WireGuard)
            |                         |
            └──── WireGuard VPN ──────┤
                                      |
                                 [Backend]
                                  10.10.2.2

Networks:
- Internet: 10.10.0.0/24 (Controller, Gateway external)
- Client Network: 10.10.1.0/24 (Client, Gateway client-facing)
- Backend Network: 10.10.2.0/24 (Backend, Gateway backend-facing)
- VPN: 10.9.0.0/24 (WireGuard tunnel)
"""

from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time


class SDPTopology:
    """SDP Topology - Controller (cloud), Gateway (edge), Client (remote), Backend (local)"""
    
    def __init__(self):
        self.net = None
        
    def create_topology(self):
        """Create the network topology"""
        info('*** Creating SDP Topology\n')
        
        # Create Mininet network
        self.net = Mininet(
            controller=Controller,
            switch=OVSSwitch,
            link=TCLink,
            autoSetMacs=True,
            autoStaticArp=False
        )
        
        info('*** Adding controller\n')
        c0 = self.net.addController('c0')
        
        # Add switches
        info('*** Adding switches\n')
        s_internet = self.net.addSwitch('s1')      # Internet/Cloud network
        s_client = self.net.addSwitch('s2')        # Client network
        s_backend = self.net.addSwitch('s3')       # Backend network
        
        # Add hosts
        info('*** Adding hosts\n')
        
        # Controller - in cloud/internet
        controller = self.net.addHost(
            'controller',
            ip='10.10.0.2/24'
        )
        
        # Gateway - has 3 interfaces
        gateway = self.net.addHost(
            'gateway',
            ip='10.10.0.3/24'  # External interface (internet-facing)
        )
        
        # Client - remote client
        client = self.net.addHost(
            'client',
            ip='10.10.1.3/24'
        )
        
        # Backend - protected resource
        backend = self.net.addHost(
            'backend',
            ip='10.10.2.2/24'
        )
        
        # Add links
        info('*** Creating links\n')
        
        # Internet network connections
        self.net.addLink(controller, s_internet)      # Controller on internet
        self.net.addLink(gateway, s_internet)         # Gateway external interface on internet
        
        # Client network connections
        self.net.addLink(client, s_client)            # Client on client network
        self.net.addLink(gateway, s_client)           # Gateway client-facing interface
        
        # Backend network connections
        self.net.addLink(gateway, s_backend)          # Gateway backend-facing interface
        self.net.addLink(backend, s_backend)          # Backend on backend network
        
        # Connect client network to internet (for Client -> Controller SPA)
        self.net.addLink(s_client, s_internet)
        
        return controller, gateway, client, backend
    
    def configure_network(self, controller, gateway, client, backend):
        """Configure network interfaces and routing"""
        info('*** Configuring network\n')
        
        # Configure Gateway interfaces
        info('  Configuring Gateway interfaces\n')
        # gateway-eth0: 10.10.0.3/24 (internet-facing, for mTLS with Controller)
        # gateway-eth1: 10.10.1.2/24 (client-facing, receives SPA forwarded packets)
        # gateway-eth2: 10.10.2.1/24 (backend-facing, forwards to backend)
        
        gateway.cmd('ifconfig gateway-eth1 10.10.1.2 netmask 255.255.255.0')
        gateway.cmd('ifconfig gateway-eth2 10.10.2.1 netmask 255.255.255.0')
        
        # Enable IP forwarding on gateway
        gateway.cmd('sysctl -w net.ipv4.ip_forward=1')
        
        # Configure routing
        info('  Configuring routing\n')
        
        # Client routing
        # Client needs to reach both Controller (for SPA) and Gateway (for WireGuard)
        client.cmd('ip route add 10.10.0.0/24 via 10.10.1.2')  # Internet via gateway
        client.cmd('ip route add 10.10.2.0/24 via 10.10.1.2')  # Backend via gateway (for VPN)
        
        # Backend routing
        backend.cmd('ip route add default via 10.10.2.1')  # Gateway is default
        
        # Gateway routing
        # Gateway has direct routes to all networks via its interfaces
        # No additional routes needed
        
        # Controller routing
        # Controller should NOT have direct route to backend (Zero Trust)
        # Controller CAN reach client network (for receiving SPA responses if needed)
        controller.cmd('ip route add 10.10.1.0/24 via 10.10.0.3')  # Client network
        # NO route to backend network!
        controller.cmd('ip route add 10.9.0.0/24 via 10.10.0.3')   # VPN network
        
        # Configure iptables on Gateway
        info('  Configuring Gateway firewall\n')
        
        gateway.cmd('iptables -F')
        gateway.cmd('iptables -t nat -F')
        
        # NAT for client to reach internet
        gateway.cmd('iptables -t nat -A POSTROUTING -o gateway-eth0 -j MASQUERADE')
        
        # FORWARD chain - default drop (Zero Trust)
        gateway.cmd('iptables -P FORWARD DROP')
        gateway.cmd('iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT')
        
        # Allow client <-> internet (for SPA to Controller)
        gateway.cmd('iptables -A FORWARD -i gateway-eth1 -o gateway-eth0 -j ACCEPT')
        gateway.cmd('iptables -A FORWARD -i gateway-eth0 -o gateway-eth1 -j ACCEPT')
        
        # DO NOT allow client -> backend before SPA authentication!
        # This is the core of Zero Trust SDP:
        # - Client CANNOT reach backend directly
        # - Client can ONLY reach backend via WireGuard VPN AFTER SPA authentication
        # - mTLS gateway will add: iptables -A FORWARD -i wg0 -o gateway-eth2 -j ACCEPT
        
        # DO NOT allow backend <-> internet direct traffic (Zero Trust)
        # Backend is completely isolated
        
        info('*** Network configuration complete\n')
    
    def test_connectivity(self, controller, gateway, client, backend):
        """Test connectivity between hosts"""
        info('\n*** Testing Connectivity\n')
        
        tests = [
            # Internet connectivity
            ('Controller -> Gateway', controller, '10.10.0.3', True),
            ('Gateway -> Controller', gateway, '10.10.0.2', True),
            
            # Client connectivity
            ('Client -> Gateway (client-side)', client, '10.10.1.2', True),
            ('Client -> Controller (SPA path)', client, '10.10.0.2', True),
            ('Gateway -> Client', gateway, '10.10.1.3', True),
            
            # Backend connectivity
            ('Gateway -> Backend', gateway, '10.10.2.2', True),
            ('Backend -> Gateway', backend, '10.10.2.1', True),
            
            # Zero Trust enforcement
            ('Controller -> Backend (SHOULD FAIL)', controller, '10.10.2.2', False),
            ('Backend -> Controller (SHOULD FAIL)', backend, '10.10.0.2', False),
            
            # TRUE ZERO TRUST: Client CANNOT reach backend before SPA authentication
            ('Client -> Backend (SHOULD FAIL - no SPA yet)', client, '10.10.2.2', False),
        ]
        
        passed = 0
        failed = 0
        
        for test_name, host, target_ip, should_pass in tests:
            result = host.cmd(f'ping -c 1 -W 1 {target_ip}')
            success = '1 received' in result
            
            if should_pass:
                if success:
                    info(f'  ✓ {test_name}\n')
                    passed += 1
                else:
                    info(f'  ✗ {test_name} (FAILED - should pass)\n')
                    failed += 1
            else:
                if not success:
                    info(f'  ✓ {test_name} (correctly blocked)\n')
                    passed += 1
                else:
                    info(f'  ✗ {test_name} (SECURITY ISSUE - should be blocked!)\n')
                    failed += 1
        
        info(f'\n*** Connectivity Test Results: {passed} passed, {failed} failed\n')
        
        if failed == 0:
            info('*** ✓ All connectivity tests passed!\n')
            info('*** ✓ Architecture verified:\n')
            info('***   - Client can send SPA to Controller (direct)\n')
            info('***   - Controller can send mTLS to Gateway (direct)\n')
            info('***   - Client can reach Gateway (for WireGuard setup)\n')
            info('***   - Zero Trust: Controller <-> Backend blocked\n')
            info('***   - Zero Trust: Client <-> Backend blocked (before SPA)\n')
            info('***   → Backend is completely isolated!\n')
            info('***   → Only accessible via WireGuard VPN after SPA auth\n\n')
        else:
            info('*** ✗ Some tests failed\n\n')
    
    def show_configuration(self, controller, gateway, client, backend):
        """Display configuration information"""
        info('\n' + '='*70 + '\n')
        info('*** SDP Topology Configuration\n')
        info('='*70 + '\n\n')
        
        info('Architecture:\n')
        info('  Client ---SPA---> Controller (10.10.0.2)\n')
        info('  Controller ---mTLS---> Gateway (10.10.0.3)\n')
        info('  Client ---WireGuard---> Gateway (10.10.1.2)\n')
        info('  Gateway ---Forward---> Backend (10.10.2.2)\n\n')
        
        info('Controller (Cloud/Internet):\n')
        info(f'  IP: 10.10.0.2/24\n')
        info(f'  SPA Port: 62201 (UDP)\n')
        info(f'  mTLS Port: 5000 (TCP)\n')
        info(f'  Role: Policy Decision Point\n')
        info(f'  Access: Client can send SPA, Gateway can connect via mTLS\n\n')
        
        info('Gateway (Edge/DMZ):\n')
        info(f'  External IP: 10.10.0.3/24 (gateway-eth0) - for Controller mTLS\n')
        info(f'  Client-side IP: 10.10.1.2/24 (gateway-eth1) - for Client access\n')
        info(f'  Backend-side IP: 10.10.2.1/24 (gateway-eth2) - for Backend access\n')
        info(f'  WireGuard IP: 10.9.0.1/24 (wg0 - to be configured)\n')
        info(f'  Role: Policy Enforcement Point\n\n')
        
        info('Client (Remote):\n')
        info(f'  IP: 10.10.1.3/24\n')
        info(f'  Can reach: Controller (SPA), Gateway (WireGuard setup)\n')
        info(f'  CANNOT reach: Backend (isolated - no access before SPA!)\n\n')
        
        info('Backend (Protected Resource):\n')
        info(f'  IP: 10.10.2.2/24\n')
        info(f'  COMPLETELY ISOLATED:\n')
        info(f'    ✗ Controller cannot reach it\n')
        info(f'    ✗ Client cannot reach it (before SPA)\n')
        info(f'    ✓ Only accessible via WireGuard VPN after SPA authentication\n\n')
        
        info('Zero Trust Verification:\n')
        info(f'  ✓ Controller <-> Backend: BLOCKED\n')
        info(f'  ✓ Client <-> Backend: BLOCKED (before SPA)\n')
        info(f'  ✓ Backend is completely isolated\n')
        info(f'  → After SPA: mTLS Gateway adds WireGuard rules\n')
        info(f'  → Only then: Client can access via VPN (10.9.0.x)\n\n')
        
        info('='*70 + '\n\n')
    
    def print_setup_instructions(self):
        """Print setup instructions"""
        info('\n' + '='*70 + '\n')
        info('*** Setup Instructions\n')
        info('='*70 + '\n\n')
        
        info('STEP 1: Configure WireGuard on Gateway\n')
        info('  mininet> gateway ip link add dev wg0 type wireguard\n')
        info('  mininet> gateway ip addr add 10.9.0.1/24 dev wg0\n')
        info('  mininet> gateway wg genkey | tee /tmp/gateway_private.key | wg pubkey > /tmp/gateway_public.key\n')
        info('  mininet> gateway wg set wg0 private-key /tmp/gateway_private.key listen-port 51820\n')
        info('  mininet> gateway ip link set wg0 up\n\n')
        
        info('STEP 2: Start mTLS Gateway (on Gateway host)\n')
        info('  mininet> gateway cd /tmp/sdp && python3 mtls_gateway.py --controller-host 10.10.0.2 &\n\n')
        
        info('STEP 3: Start SPA Server (on Controller host)\n')
        info('  mininet> controller cd /tmp/sdp && python3 spa_server_mtls.py -v &\n\n')
        
        info('STEP 4: Verify mTLS Connection\n')
        info('  Check logs to see Gateway connected to Controller\n\n')
        
        info('STEP 5: Send SPA from Client\n')
        info('  mininet> client python3 spa_client.py --controller 10.10.0.2\n\n')
        
        info('STEP 6: Verify Client can access Backend via VPN\n')
        info('  After WireGuard setup, client should be able to reach backend\n\n')
        
        info('='*70 + '\n\n')
    
    def start(self):
        """Start the topology"""
        info('*** Starting SDP Topology\n')
        
        # Create topology
        controller, gateway, client, backend = self.create_topology()
        
        # Start network
        info('*** Starting network\n')
        self.net.start()
        
        # Configure network
        self.configure_network(controller, gateway, client, backend)
        
        # Test connectivity
        self.test_connectivity(controller, gateway, client, backend)
        
        # Show configuration
        self.show_configuration(controller, gateway, client, backend)
        
        # Print instructions
        self.print_setup_instructions()
        
        # Start CLI
        info('*** Starting CLI\n')
        info('*** Type "help" for Mininet commands\n')
        CLI(self.net)
        
        # Cleanup
        info('*** Stopping network\n')
        self.net.stop()


def main():
    """Main function"""
    setLogLevel('info')
    
    info('\n' + '='*70 + '\n')
    info('*** SDP Topology with mTLS\n')
    info('*** Architecture:\n')
    info('***   - Client sends SPA directly to Controller\n')
    info('***   - Controller sends mTLS policy to Gateway\n')
    info('***   - Client connects to Gateway via WireGuard\n')
    info('***   - Gateway forwards to Backend\n')
    info('='*70 + '\n\n')
    
    topology = SDPTopology()
    
    try:
        topology.start()
    except KeyboardInterrupt:
        info('\n*** Keyboard interrupt detected\n')
    finally:
        info('*** Cleaning up\n')


if __name__ == '__main__':
    main()
