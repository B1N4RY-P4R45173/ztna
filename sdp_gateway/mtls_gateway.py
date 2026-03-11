#!/usr/bin/env python3
"""
mTLS Gateway - Receives policy commands from Controller
Runs ON the gateway host (10.0.0.3) inside Mininet
"""

import ssl
import socket
import json
import logging
import subprocess
import sys
import time
import threading

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


class MTLSGateway:
    """Gateway that receives firewall policy commands via mTLS"""

    def __init__(self,
                 controller_host,
                 controller_port=5000,
                 wg_interface='wg0',
                 forward_interface='gateway-eth0',   # FIX: was ens38, Mininet uses gateway-eth0
                 vpn_subnet='10.9.0.0/24',
                 resource_ip='10.0.0.4',             # FIX: single host IP, not a subnet
                 reconnect_delay=5,
                 max_recv_bytes=65536):               # FIX: increased from 4096

        self.controller_host = controller_host
        self.controller_port = controller_port
        self.wg_interface = wg_interface
        self.forward_interface = forward_interface
        self.vpn_subnet = vpn_subnet
        self.resource_ip = resource_ip               # FIX: renamed from resource_subnet
        self.reconnect_delay = reconnect_delay
        self.max_recv_bytes = max_recv_bytes
        self.connection = None
        self.running = True

        logging.info(f"Gateway initialized")
        logging.info(f"  Controller:          {controller_host}:{controller_port}")
        logging.info(f"  WireGuard interface: {wg_interface}")
        logging.info(f"  Forward interface:   {forward_interface}")
        logging.info(f"  VPN subnet:          {vpn_subnet}")
        logging.info(f"  Resource IP:         {resource_ip}")

    # ------------------------------------------------------------------ #
    #  mTLS                                                                #
    # ------------------------------------------------------------------ #
    def create_ssl_context(self):
        """Create SSL context for mTLS client"""
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_cert_chain(
            certfile='certs/gateway_cert.pem',
            keyfile='certs/gateway_key.pem'
        )
        context.load_verify_locations('certs/ca_cert.pem')
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def connect_to_controller(self):
        """Establish persistent mTLS connection to Controller"""
        try:
            logging.info(f"Connecting to Controller at {self.controller_host}:{self.controller_port}")
            ssl_context = self.create_ssl_context()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            self.connection = ssl_context.wrap_socket(sock)
            self.connection.connect((self.controller_host, self.controller_port))

            cert = self.connection.getpeercert()
            controller_cn = dict(x[0] for x in cert['subject'])['commonName']
            logging.info(f"✓ Connected to Controller: {controller_cn}")
            logging.info(f"✓ mTLS handshake successful")
            self.connection.settimeout(None)  # back to blocking after connect
            return True

        except Exception as e:
            logging.error(f"Failed to connect to Controller: {e}")
            return False

    # ------------------------------------------------------------------ #
    #  Reliable recv — FIX for 4096 byte split issue                      #
    # ------------------------------------------------------------------ #
    def recv_message(self):
        """
        Receive a complete newline-terminated JSON message.
        Avoids the silent truncation bug of fixed recv(4096).
        Controller must send each JSON command terminated with newline.
        """
        buffer = b''
        while True:
            chunk = self.connection.recv(self.max_recv_bytes)
            if not chunk:
                return None
            buffer += chunk
            if b'\n' in buffer:
                line, _ = buffer.split(b'\n', 1)
                return line.decode('utf-8')

    # ------------------------------------------------------------------ #
    #  Command handlers                                                    #
    # ------------------------------------------------------------------ #
    def execute_add_peer(self, command):
        """Add WireGuard peer and set up iptables ACL rules"""
        try:
            vpn_ip     = command['vpn_ip']
            public_key = command['public_key']
            access_port= command['access_port']
            protocol   = command['protocol']
            resource_id= command['resource_id']
            client_id  = command['client_id']

            logging.info(f"Adding peer: {client_id} → {resource_id}:{access_port}/{protocol}")

            # Step 1 — Add WireGuard peer
            wg_cmd = (
                f"wg set {self.wg_interface} peer {public_key} "
                f"allowed-ips {vpn_ip}"             # vpn_ip already includes /32 from server
            )
            self._run(wg_cmd)
            logging.info(f"  ✓ WireGuard peer added: {public_key[:20]}... → {vpn_ip}")

            # Step 2 — Enable IP forwarding
            self._run("sysctl -w net.ipv4.ip_forward=1")

            # Step 3 — iptables: VPN → resource on allowed port only
            # FIX: use resource_ip/32 (single host) not a /24 subnet
            acl_fwd = (
                f"iptables -I FORWARD "
                f"-i {self.wg_interface} -o {self.forward_interface} "
                f"-s {self.vpn_subnet} -d {self.resource_ip}/32 "
                f"-p {protocol} --dport {access_port} -j ACCEPT"
            )
            self._run(acl_fwd)

            # Step 4 — iptables: allow return traffic (established/related)
            acl_ret = (
                f"iptables -I FORWARD "
                f"-i {self.forward_interface} -o {self.wg_interface} "
                f"-s {self.resource_ip}/32 -d {self.vpn_subnet} "
                f"-m state --state ESTABLISHED,RELATED -j ACCEPT"
            )
            self._run(acl_ret)

            # Step 5 — NAT: masquerade WireGuard traffic toward resource
            nat_cmd = (
                f"iptables -t nat -I POSTROUTING "
                f"-s {self.vpn_subnet} -d {self.resource_ip}/32 "
                f"-o {self.forward_interface} -j MASQUERADE"
            )
            self._run(nat_cmd)

            logging.info(f"  ✓ ACL + NAT rules added for {protocol}/{access_port}")

            return {'status': 'success',
                    'message': f'Peer and ACL added for {client_id}',
                    'client_id': client_id}

        except Exception as e:
            return self._error(command, e)

    def execute_remove_peer(self, command):
        """Remove WireGuard peer and corresponding iptables rules"""
        try:
            public_key  = command['public_key']
            vpn_ip      = command['vpn_ip']
            access_port = command['access_port']
            protocol    = command['protocol']
            client_id   = command['client_id']

            logging.info(f"Removing peer: {client_id}")

            # Step 1 — Remove ACL forward rule
            acl_fwd = (
                f"iptables -D FORWARD "
                f"-i {self.wg_interface} -o {self.forward_interface} "
                f"-s {self.vpn_subnet} -d {self.resource_ip}/32 "
                f"-p {protocol} --dport {access_port} -j ACCEPT"
            )
            self._run(acl_fwd)

            # Step 2 — Remove ACL return rule
            acl_ret = (
                f"iptables -D FORWARD "
                f"-i {self.forward_interface} -o {self.wg_interface} "
                f"-s {self.resource_ip}/32 -d {self.vpn_subnet} "
                f"-m state --state ESTABLISHED,RELATED -j ACCEPT"
            )
            self._run(acl_ret)

            # Step 3 — Remove NAT rule
            nat_cmd = (
                f"iptables -t nat -D POSTROUTING "
                f"-s {self.vpn_subnet} -d {self.resource_ip}/32 "
                f"-o {self.forward_interface} -j MASQUERADE"
            )
            self._run(nat_cmd)

            # Step 4 — Remove WireGuard peer
            self._run(f"wg set {self.wg_interface} peer {public_key} remove")
            logging.info(f"  ✓ Peer removed: {public_key[:20]}...")

            # Step 5 — Flush routing cache
            self._run("ip route flush cache")

            return {'status': 'success',
                    'message': f'Peer and ACL removed for {client_id}',
                    'client_id': client_id}

        except Exception as e:
            return self._error(command, e)

    def handle_command(self, command):
        action = command.get('action')
        if action == 'add_peer':
            return self.execute_add_peer(command)
        elif action == 'remove_peer':
            return self.execute_remove_peer(command)
        else:
            return {'status': 'error', 'message': f'Unknown action: {action}'}

    # ------------------------------------------------------------------ #
    #  Main loop — with reconnection logic (FIX)                          #
    # ------------------------------------------------------------------ #
    def listen_for_commands(self):
        """Listen for commands from Controller. Reconnects on disconnect."""
        logging.info("Listening for commands from Controller...")
        try:
            while self.running:
                raw = self.recv_message()
                if raw is None:
                    logging.warning("Connection closed by Controller")
                    break

                try:
                    command  = json.loads(raw)
                    logging.info(f"\nReceived command: {command.get('action')}")
                    response = self.handle_command(command)
                    # FIX: send newline-terminated response to match recv_message protocol
                    self.connection.sendall((json.dumps(response) + '\n').encode('utf-8'))
                    logging.info(f"Response sent: {response['status']}")

                except json.JSONDecodeError as e:
                    logging.error(f"Invalid JSON: {e}")
                    err = {'status': 'error', 'message': 'Invalid JSON'}
                    self.connection.sendall((json.dumps(err) + '\n').encode('utf-8'))

        except Exception as e:
            logging.error(f"Error in command listener: {e}")
        finally:
            if self.connection:
                self.connection.close()
                self.connection = None
            logging.info("Connection closed")

    def start(self):
        """Start Gateway with auto-reconnect on Controller disconnect"""
        logging.info("\n" + "=" * 60)
        logging.info("Starting mTLS Gateway")
        logging.info("=" * 60)

        while self.running:
            if self.connect_to_controller():
                self.listen_for_commands()
            else:
                logging.info(f"Retrying in {self.reconnect_delay}s...")

            if self.running:
                time.sleep(self.reconnect_delay)

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #
    def _run(self, cmd):
        """Run a shell command, raise on failure."""
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, check=True
        )
        return result

    def _error(self, command, exc):
        msg = str(exc)
        logging.error(f"  ✗ {msg}")
        return {'status': 'error',
                'message': msg,
                'client_id': command.get('client_id', 'unknown')}


# ======================================================================== #
#  Entry point                                                              #
# ======================================================================== #
def main():
    import argparse

    parser = argparse.ArgumentParser(description='mTLS Gateway - Policy Enforcement Point')
    parser.add_argument('--controller-host',
                        default='10.0.0.2',          # FIX: default to sdp_ctrl Mininet IP
                        help='Controller IP (default: 10.0.0.2)')
    parser.add_argument('--controller-port',
                        type=int, default=5000,
                        help='Controller port (default: 5000)')
    parser.add_argument('--wg-interface',
                        default='wg0',
                        help='WireGuard interface (default: wg0)')
    parser.add_argument('--forward-interface',
                        default='gateway-eth0',      # FIX: was ens38
                        help='Interface toward resource (default: gateway-eth0)')
    parser.add_argument('--vpn-subnet',
                        default='10.9.0.0/24',
                        help='WireGuard VPN subnet (default: 10.9.0.0/24)')
    parser.add_argument('--resource-ip',
                        default='10.0.0.4',          # FIX: was wrong subnet, now correct host IP
                        help='Resource host IP (default: 10.0.0.4)')

    args = parser.parse_args()

    gateway = MTLSGateway(
        controller_host=args.controller_host,
        controller_port=args.controller_port,
        wg_interface=args.wg_interface,
        forward_interface=args.forward_interface,
        vpn_subnet=args.vpn_subnet,
        resource_ip=args.resource_ip,
    )

    try:
        gateway.start()
    except KeyboardInterrupt:
        logging.info("\nShutting down Gateway...")
        gateway.running = False


if __name__ == '__main__':
    main()