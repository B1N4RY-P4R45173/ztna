#!/usr/bin/env python3
"""
mTLS Gateway - Receives policy commands from Controller
Runs ON the gateway VM where firewall/WireGuard is configured
"""

import ssl
import socket
import json
import logging
import subprocess
import sys
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
                 forward_interface='ens38',
                 vpn_subnet='10.9.0.0/24',
                 resource_subnet='10.10.2.0/24'):
        
        self.controller_host = controller_host
        self.controller_port = controller_port
        self.wg_interface = wg_interface
        self.forward_interface = forward_interface
        self.vpn_subnet = vpn_subnet
        self.resource_subnet = resource_subnet
        self.connection = None
        self.running = True
        
        logging.info(f"Gateway initialized")
        logging.info(f"  WireGuard interface: {wg_interface}")
        logging.info(f"  Forward interface: {forward_interface}")
        logging.info(f"  VPN subnet: {vpn_subnet}")
        logging.info(f"  Resource subnet: {resource_subnet}")
    
    def create_ssl_context(self):
        """Create SSL context for mTLS client"""
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        
        # Load Gateway's certificate and key
        context.load_cert_chain(
            certfile='certs/gateway_cert.pem',
            keyfile='certs/gateway_key.pem'
        )
        
        # Load CA to verify Controller
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
            self.connection = ssl_context.wrap_socket(sock)
            self.connection.connect((self.controller_host, self.controller_port))
            
            # Get Controller's identity
            cert = self.connection.getpeercert()
            controller_cn = dict(x[0] for x in cert['subject'])['commonName']
            
            logging.info(f"✓ Connected to Controller: {controller_cn}")
            logging.info(f"✓ mTLS handshake successful")
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to connect to Controller: {e}")
            return False
    
    def execute_add_peer(self, command):
        """
        Add WireGuard peer and set up ACL rules
        
        Command includes:
        - vpn_ip: Client's VPN IP
        - public_key: Client's WireGuard public key
        - access_port: Port client wants to access
        - protocol: tcp/udp
        - resource_id: Backend resource identifier
        - client_id: Client identifier
        """
        try:
            vpn_ip = command['vpn_ip']
            public_key = command['public_key']
            access_port = command['access_port']
            protocol = command['protocol']
            resource_id = command['resource_id']
            client_id = command['client_id']
            
            logging.info(f"Adding peer for {client_id} → {resource_id}:{access_port}/{protocol}")
            
            # Step 1: Add WireGuard peer
            wg_cmd = f"sudo wg set {self.wg_interface} peer {public_key} allowed-ips {vpn_ip}"
            
            result = subprocess.run(
                wg_cmd,
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            logging.info(f"  ✓ WireGuard peer added: {public_key[:16]}... → {vpn_ip}")
            
            # Step 2: Add ACL rule
            # Allow traffic from VPN subnet to resource subnet on specific port/protocol
            acl_cmd = (
                f"sudo iptables -I FORWARD -i {self.wg_interface} -o {self.forward_interface} "
                f"-s {self.vpn_subnet} -d {self.resource_subnet} "
                f"-p {protocol} --dport {access_port} -j ACCEPT"
            )
            
            subprocess.run(
                acl_cmd,
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            logging.info(f"  ✓ ACL added: {protocol}/{access_port}")
            
            return {
                'status': 'success',
                'message': f'Peer and ACL added for {client_id}',
                'client_id': client_id
            }
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Command failed: {e.stderr}"
            logging.error(f"  ✗ {error_msg}")
            return {
                'status': 'error',
                'message': error_msg,
                'client_id': command.get('client_id', 'unknown')
            }
        except KeyError as e:
            error_msg = f"Missing required field: {e}"
            logging.error(f"  ✗ {error_msg}")
            return {
                'status': 'error',
                'message': error_msg,
                'client_id': command.get('client_id', 'unknown')
            }
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            logging.error(f"  ✗ {error_msg}")
            return {
                'status': 'error',
                'message': error_msg,
                'client_id': command.get('client_id', 'unknown')
            }
    
    def execute_remove_peer(self, command):
        """
        Remove WireGuard peer and corresponding ACL rules
        
        Command includes same info as add_peer so we know exactly what to remove
        """
        try:
            public_key = command['public_key']
            access_port = command['access_port']
            protocol = command['protocol']
            client_id = command['client_id']
            
            logging.info(f"Removing peer for {client_id}")
            
            # Step 1: Remove ACL rule (do this first in case peer removal fails)
            acl_cmd = (
                f"sudo iptables -D FORWARD -i {self.wg_interface} -o {self.forward_interface} "
                f"-s {self.vpn_subnet} -d {self.resource_subnet} "
                f"-p {protocol} --dport {access_port} -j ACCEPT"
            )
            
            subprocess.run(
                acl_cmd,
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            logging.info(f"  ✓ ACL removed: {protocol}/{access_port}")
            
            # Step 2: Remove WireGuard peer
            wg_cmd = f"sudo wg set {self.wg_interface} peer {public_key} remove"
            
            subprocess.run(
                wg_cmd,
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )
            logging.info(f"  ✓ WireGuard peer removed: {public_key[:16]}...")
            
            # Step 3: Flush routing cache
            subprocess.run(
                "sudo ip route flush cache",
                shell=True,
                capture_output=True,
                text=True
            )
            
            return {
                'status': 'success',
                'message': f'Peer and ACL removed for {client_id}',
                'client_id': client_id
            }
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Command failed: {e.stderr}"
            logging.error(f"  ✗ {error_msg}")
            return {
                'status': 'error',
                'message': error_msg,
                'client_id': command.get('client_id', 'unknown')
            }
        except KeyError as e:
            error_msg = f"Missing required field: {e}"
            logging.error(f"  ✗ {error_msg}")
            return {
                'status': 'error',
                'message': error_msg,
                'client_id': command.get('client_id', 'unknown')
            }
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            logging.error(f"  ✗ {error_msg}")
            return {
                'status': 'error',
                'message': error_msg,
                'client_id': command.get('client_id', 'unknown')
            }
    
    def handle_command(self, command):
        """Route command to appropriate handler"""
        action = command.get('action')
        
        if action == 'add_peer':
            return self.execute_add_peer(command)
        elif action == 'remove_peer':
            return self.execute_remove_peer(command)
        else:
            return {
                'status': 'error',
                'message': f'Unknown action: {action}'
            }
    
    def listen_for_commands(self):
        """Listen for commands from Controller over persistent mTLS connection"""
        logging.info("Listening for commands from Controller...")
        
        try:
            while self.running:
                # Receive command from Controller
                data = self.connection.recv(4096)
                
                if not data:
                    logging.warning("Connection closed by Controller")
                    break
                
                try:
                    command = json.loads(data.decode('utf-8'))
                    logging.info(f"\nReceived command: {command['action']}")
                    
                    # Execute command
                    response = self.handle_command(command)
                    
                    # Send response back to Controller
                    self.connection.sendall(json.dumps(response).encode('utf-8'))
                    logging.info(f"Response sent: {response['status']}")
                    
                except json.JSONDecodeError as e:
                    logging.error(f"Invalid JSON received: {e}")
                    error_response = {
                        'status': 'error',
                        'message': 'Invalid JSON'
                    }
                    self.connection.sendall(json.dumps(error_response).encode('utf-8'))
                
        except Exception as e:
            logging.error(f"Error in command listener: {e}")
        finally:
            if self.connection:
                self.connection.close()
            logging.info("Connection closed")
    
    def start(self):
        """Start Gateway - connect to Controller and listen for commands"""
        logging.info("\n" + "="*60)
        logging.info("Starting mTLS Gateway")
        logging.info("="*60)
        
        # Connect to Controller
        if not self.connect_to_controller():
            logging.error("Failed to connect to Controller - exiting")
            return
        
        # Listen for commands
        try:
            self.listen_for_commands()
        except KeyboardInterrupt:
            logging.info("\nShutting down Gateway...")
        finally:
            self.running = False
            if self.connection:
                self.connection.close()


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='mTLS Gateway - Policy Enforcement Point')
    parser.add_argument('--controller-host', required=True, help='Controller IP address')
    parser.add_argument('--controller-port', type=int, default=5000, help='Controller port (default: 5000)')
    parser.add_argument('--wg-interface', default='wg0', help='WireGuard interface (default: wg0)')
    parser.add_argument('--forward-interface', default='ens38', help='Forward interface (default: ens38)')
    parser.add_argument('--vpn-subnet', default='10.9.0.0/24', help='VPN subnet (default: 10.9.0.0/24)')
    parser.add_argument('--resource-subnet', default='10.10.2.0/24', help='Resource subnet (default: 10.10.2.0/24)')
    
    args = parser.parse_args()
    
    gateway = MTLSGateway(
        controller_host=args.controller_host,
        controller_port=args.controller_port,
        wg_interface=args.wg_interface,
        forward_interface=args.forward_interface,
        vpn_subnet=args.vpn_subnet,
        resource_subnet=args.resource_subnet
    )
    
    gateway.start()


if __name__ == '__main__':
    main()