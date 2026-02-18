#!/usr/bin/env python3
"""
SPA Server with mTLS Gateway Integration
Single Packet Authorization server that communicates with Gateway via mTLS
"""

import socket
import json 
import sys 
import logging
import signal
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hmac
import hashlib
import time
import threading
import base64
import argparse
import pprint
import os
import ipaddress
import uuid

# Import mTLS controller
import mtls_controller


class VPNIPPool:
    """Manage VPN IP address pool allocation"""
    
    def __init__(self, ip_pool):
        """
        Initialize IP pool
        
        Args:
            ip_pool: List of available IP addresses
        """
        self.available_ips = set(ip_pool)
        self.allocated_ips = {}  # client_id -> ip mapping
        self.lock = threading.Lock()
        logging.info(f"IP Pool initialized with {len(self.available_ips)} addresses")
    
    def allocate_ip(self, client_id):
        """
        Allocate an IP to a client
        
        Returns:
            IP address string or None if pool exhausted
        """
        with self.lock:
            if not self.available_ips:
                logging.error("IP pool exhausted!")
                return None
            
            # Take first available IP
            ip = self.available_ips.pop()
            self.allocated_ips[client_id] = ip
            logging.info(f"Allocated {ip} to {client_id}")
            return ip
    
    def release_ip(self, client_id):
        """Release IP back to pool when client disconnects"""
        with self.lock:
            if client_id in self.allocated_ips:
                ip = self.allocated_ips[client_id]
                self.available_ips.add(ip)
                del self.allocated_ips[client_id]
                logging.info(f"Released {ip} from {client_id}")
                return True
            return False
    
    def get_allocated_ip(self, client_id):
        """Get IP allocated to a client"""
        return self.allocated_ips.get(client_id)


class SPAServer:
    """SPA Server with mTLS Gateway integration"""
    
    def __init__(self, config_file='server_config.json', verbose=False, port=62201, daemon=False):
        # Load configuration
        self.load_config(config_file)
        
        # Apply config defaults, then command line overrides
        self.verbose = self.config.get('verbose', False)
        self.port = self.config.get('listen_port', 62201)
        self.daemon = self.config.get('daemon', False)
        self.mtls_port = self.config.get('mtls_controller_port', 5000)
        
        # Command line overrides
        if verbose:
            self.verbose = verbose
        if port != 62201:
            self.port = port
        if daemon:
            self.daemon = daemon
        
        # Active sessions: client_id -> session_info
        self.active_sessions = {}
        self.keepalive_timeout = self.config.get("keepalive_timeout", 300)
        
        # Track SPA requests to detect keepalives
        self.spa_requests = {}
        
        # Load gateway configuration
        self.load_gateways()
        
        # Initialize IP pool
        self.ip_pool = VPNIPPool(self.gateway['vpn_ip_pool'])
        
        # Setup
        self.setup_logging()
        self.setup_crypto()
        
        # Socket and threads
        self.socket = None
        self.running = True
        
        # Start session monitor thread
        self.session_monitor_thread = threading.Thread(
            target=self.monitor_sessions,
            daemon=True
        )
        self.session_monitor_thread.start()
        
        logging.info("SPA Server initialized")
    
    def load_config(self, config_file):
        """Load server configuration"""
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            print(f"Error: Configuration file {config_file} not found")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in {config_file}: {e}")
            sys.exit(1)
    
    def load_gateways(self):
        """Load gateway configuration from JSON"""
        gateway_file = self.config.get('gateway_config', 'sdp_gateway_details.json')
        
        try:
            with open(gateway_file, 'r') as f:
                gateways = json.load(f)
            
            # For now, use first gateway only
            if not gateways:
                logging.error("No gateways configured!")
                sys.exit(1)
            
            self.gateway = gateways[0]
            logging.info(f"Loaded gateway: {self.gateway['name']} ({self.gateway['gateway_id']})")
            
        except FileNotFoundError:
            logging.error(f"Gateway config file {gateway_file} not found")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Error loading gateway config: {e}")
            sys.exit(1)
    
    def setup_logging(self):
        """Configure logging"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        log_level = logging.DEBUG if self.verbose else logging.INFO
        handlers = []

        # File handler
        if 'log_file' in self.config:
            try:
                file_handler = logging.FileHandler(self.config['log_file'])
                file_handler.setFormatter(logging.Formatter(log_format))
                handlers.append(file_handler)
            except Exception as e:
                print(f"Failed to set up file logger: {e}")

        # Console handler
        if self.verbose or not self.daemon:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter(log_format))
            handlers.append(console_handler)

        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.handlers = []
        root_logger.setLevel(log_level)
        for handler in handlers:
            root_logger.addHandler(handler)
    
    def setup_crypto(self):
        """Setup encryption keys"""
        if 'encryption_key' not in self.config:
            logging.error("encryption_key not found in configuration")
            sys.exit(1)
            
        password = self.config['encryption_key']
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,
            salt=b'ztna_salt',
            iterations=100000,
            backend=default_backend()
        )
        master_key = kdf.derive(password.encode('utf-8'))
        self.encryption_key = master_key[:32]
        self.hmac_key = master_key[32:]
    
    def verify_hmac(self, data, received_hmac):
        """Verify HMAC signature"""
        h = hmac.new(self.hmac_key, data, hashlib.sha256)
        return hmac.compare_digest(h.digest(), received_hmac)
    
    def decrypt_packet(self, encrypted_data):
        """Decrypt SPA packet"""
        if len(encrypted_data) < 48:
            raise ValueError("Packet too short")
            
        # Extract IV and encrypted data
        iv = encrypted_data[:16]
        encrypted = encrypted_data[16:]
        
        # Decrypt
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        # Split data and HMAC
        json_data = data[:-32]
        received_hmac = data[-32:]
        
        return json_data, received_hmac
    
    def is_ip_allowed(self, ip):
        """Check if source IP is in allowed list"""
        if 'allowed_ips' not in self.config:
            logging.warning("No allowed_ips configured - denying all access")
            return False
            
        try:
            ip_obj = ipaddress.ip_address(ip)
            for net in self.config['allowed_ips']:
                if ip_obj in ipaddress.ip_network(net, strict=False):
                    return True
            return False
        except ValueError:
            return False
    
    def is_keepalive_packet(self, packet_data):
        """
        Determine if this is a keepalive packet
        Same request within 300 seconds = keepalive
        """
        source_ip = packet_data.get('source_ip')
        access_port = packet_data.get('access_port')
        protocol = packet_data.get('protocol')
        
        key = f"{source_ip}:{access_port}:{protocol}"
        current_time = time.time()
        
        if key in self.spa_requests:
            last_request_time = self.spa_requests[key]['timestamp']
            if current_time - last_request_time < 300:
                return True
        
        return False
    
    def generate_client_id(self, source_ip):
        """Generate unique client ID for tracking"""
        timestamp = int(time.time())
        unique_id = str(uuid.uuid4())[:8]
        client_id = f"client-{source_ip}-{timestamp}-{unique_id}"
        return client_id
    
    def handle_packet(self, data, addr):
        """Handle incoming SPA packet"""
        try:
            if self.verbose:
                logging.debug(f"Received packet from {addr[0]}:{addr[1]}")
                logging.debug(f"Raw data (base64): {base64.b64encode(data).decode()}")
            
            # Decrypt packet
            decrypted, received_hmac = self.decrypt_packet(data)
            
            if self.verbose:
                logging.debug(f"Decrypted data: {decrypted}")
            
            # Verify HMAC
            if not self.verify_hmac(decrypted, received_hmac):
                logging.warning(f"Invalid HMAC from {addr[0]}")
                self.send_response(addr, False, "Invalid HMAC")
                return

            # Parse packet
            packet_data = json.loads(decrypted)
            
            if self.verbose:
                logging.debug("Packet contents:")
                pprint.pprint(packet_data)
            
            # Check source IP
            source_ip = packet_data.get('source_ip')
            if not source_ip:
                logging.warning(f"No source_ip in packet from {addr[0]}")
                self.send_response(addr, False, "Missing source_ip")
                return
                
            if not self.is_ip_allowed(source_ip):
                logging.warning(f"Unauthorized IP: {source_ip}")
                self.send_response(addr, False, "Unauthorized IP")
                return
            
            # Check protocol
            protocol = packet_data.get('protocol')
            if 'allowed_protocols' in self.config:
                if protocol not in self.config['allowed_protocols']:
                    logging.warning(f"Unauthorized protocol: {protocol}")
                    self.send_response(addr, False, "Unauthorized protocol")
                    return
            
            # Check if keepalive
            is_keepalive = self.is_keepalive_packet(packet_data)
            
            if is_keepalive:
                # Just update last_seen and acknowledge
                self.handle_keepalive(source_ip, addr)
            else:
                # New connection request
                self.handle_new_connection(packet_data, addr)
            
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON from {addr[0]}: {e}")
            self.send_response(addr, False, "Invalid JSON")
        except Exception as e:
            logging.error(f"Error processing packet from {addr[0]}: {str(e)}")
            self.send_response(addr, False, "Processing error")
            if self.verbose:
                import traceback
                traceback.print_exc()
    
    def handle_keepalive(self, source_ip, addr):
        """Handle keepalive packet - just update timestamp"""
        # Find client_id by source_ip
        client_id = None
        for cid, session in self.active_sessions.items():
            if session.get('source_ip') == source_ip:
                client_id = cid
                break
        
        if client_id and client_id in self.active_sessions:
            self.active_sessions[client_id]['last_seen'] = time.time()
            logging.info(f"Keepalive from {client_id} ({source_ip})")
            self.send_response(addr, True, "Keepalive acknowledged")
        else:
            logging.warning(f"Keepalive from unknown client: {source_ip}")
            self.send_response(addr, False, "Unknown client")
    
    def handle_new_connection(self, packet_data, addr):
        """Handle new SPA connection request"""
        source_ip = packet_data.get('source_ip')
        access_port = packet_data.get('access_port')
        protocol = packet_data.get('protocol')
        resource_id = packet_data.get('resource_ip')  # Using resource_ip as resource_id
        
        # Track this request
        key = f"{source_ip}:{access_port}:{protocol}"
        self.spa_requests[key] = {
            'timestamp': time.time(),
            'data': packet_data
        }
        
        logging.info(f"New SPA request: {source_ip} → {resource_id}:{access_port}/{protocol}")
        
        # Send acknowledgment and wait for WireGuard key
        self.send_response(addr, True, "SPA Verification successful")
        self.receive_wireguard_key(addr, packet_data)
    
    def receive_wireguard_key(self, addr, packet_data):
        """Receive WireGuard public key from client and configure gateway"""
        try:
            # Wait for client's WireGuard public key (max 10s)
            self.socket.settimeout(10)
            data, sender = self.socket.recvfrom(4096)

            # Must come from same IP
            if sender[0] != addr[0]:
                logging.warning(f"Key from different IP: expected {addr[0]}, got {sender[0]}")
                return

            # Decode key
            try:
                public_key = data.decode().strip()
            except UnicodeDecodeError:
                logging.warning(f"Invalid key encoding from {addr[0]}")
                self.send_error(addr, "Invalid key encoding")
                return

            if not public_key:
                logging.warning(f"Empty key from {addr[0]}")
                self.send_error(addr, "Empty key")
                return

            logging.info(f"WireGuard key received from {addr[0]}: {public_key[:16]}...")

            # Extract packet info
            source_ip = packet_data.get('source_ip')
            access_port = packet_data.get('access_port')
            protocol = packet_data.get('protocol')
            resource_id = packet_data.get('resource_ip')
            
            # Generate unique client ID
            client_id = self.generate_client_id(source_ip)
            
            # Allocate VPN IP
            vpn_ip = self.ip_pool.allocate_ip(client_id)
            if not vpn_ip:
                logging.error(f"IP pool exhausted for {client_id}")
                self.send_error(addr, "No available IPs")
                return
            
            # Send policy to gateway via mTLS (with retry)
            success = self.configure_gateway_with_retry(
                vpn_ip=vpn_ip,
                public_key=public_key,
                access_port=access_port,
                protocol=protocol,
                resource_id=resource_id,
                client_id=client_id
            )
            
            if not success:
                # Release IP and fail
                self.ip_pool.release_ip(client_id)
                logging.error(f"Gateway configuration failed for {client_id}")
                self.send_error(addr, "Gateway configuration failed")
                return
            
            # Store session
            self.active_sessions[client_id] = {
                'source_ip': source_ip,
                'client_public_key': public_key,
                'vpn_ip': vpn_ip,
                'access_port': access_port,
                'protocol': protocol,
                'resource_id': resource_id,
                'last_seen': time.time(),
                'created_at': time.time()
            }
            
            logging.info(f"Session created: {client_id} → VPN IP: {vpn_ip}")
            
            # Send gateway details to client
            self.send_gateway_details(addr, vpn_ip)

        except socket.timeout:
            logging.warning(f"No WireGuard key received from {addr[0]} within timeout")
            self.send_error(addr, "Key timeout")

        except Exception as e:
            logging.error(f"Error receiving WireGuard key from {addr[0]}: {str(e)}")
            self.send_error(addr, f"Error: {str(e)}")

        finally:
            self.socket.settimeout(None)
    
    def configure_gateway_with_retry(self, vpn_ip, public_key, access_port, protocol, resource_id, client_id, max_retries=3):
        """
        Send add_peer command to gateway with retry logic
        
        Returns:
            True if successful, False otherwise
        """
        for attempt in range(1, max_retries + 1):
            logging.info(f"Gateway config attempt {attempt}/{max_retries} for {client_id}")
            
            success = mtls_controller.send_add_peer_to_gateway(
                vpn_ip=f"{vpn_ip}/32",
                public_key=public_key,
                access_port=access_port,
                protocol=protocol,
                resource_id=resource_id,
                client_id=client_id
            )
            
            if success:
                logging.info(f"✓ Gateway configured successfully for {client_id}")
                return True
            
            if attempt < max_retries:
                logging.warning(f"Retry {attempt} failed, waiting 2s before next attempt...")
                time.sleep(2)
        
        logging.error(f"✗ All {max_retries} gateway config attempts failed for {client_id}")
        return False
    
    def send_gateway_details(self, addr, vpn_ip):
        """Send gateway connection details to client"""
        gateway_details = {
            'status': 'success',
            'gateway_public_key': self.gateway['wireguard_public_key'],
            'gateway_endpoint': f"{self.gateway['gateway_public_ip']}:{self.gateway['listen_port']}",
            'client_vpn_ip': vpn_ip,
            'vpn_subnet': self.gateway['vpn_subnet'],
            'gateway_vpn_ip': self.gateway['gateway_vpn_ip']
        }
        
        response = json.dumps(gateway_details).encode()
        self.socket.sendto(response, addr)
        logging.info(f"Gateway details sent to {addr[0]}")
    
    def send_response(self, addr, success, message):
        """Send response to client"""
        try:
            self.socket.sendto(message.encode(), addr)
        except Exception as e:
            logging.error(f"Error sending response to {addr[0]}: {e}")
    
    def send_error(self, addr, error_message):
        """Send error response to client"""
        try:
            error_response = json.dumps({
                'status': 'error',
                'message': error_message
            }).encode()
            self.socket.sendto(error_response, addr)
        except Exception as e:
            logging.error(f"Error sending error to {addr[0]}: {e}")
    
    def monitor_sessions(self):
        """Monitor active sessions and timeout inactive clients"""
        logging.info("Session monitor started")
        
        while self.running:
            try:
                now = time.time()
                expired_clients = []

                for client_id, session in list(self.active_sessions.items()):
                    last_seen = session['last_seen']

                    # Check timeout
                    if now - last_seen > self.keepalive_timeout:
                        logging.warning(f"[TIMEOUT] {client_id} inactive for {int(now - last_seen)}s")
                        
                        # Remove from gateway via mTLS
                        success = mtls_controller.send_remove_peer_to_gateway(
                            public_key=session['client_public_key'],
                            access_port=session['access_port'],
                            protocol=session['protocol'],
                            resource_id=session['resource_id'],
                            client_id=client_id
                        )
                        
                        if success:
                            logging.info(f"✓ Removed {client_id} from gateway")
                        else:
                            logging.error(f"✗ Failed to remove {client_id} from gateway")
                        
                        # Release VPN IP
                        self.ip_pool.release_ip(client_id)
                        
                        expired_clients.append(client_id)

                # Remove expired sessions
                for client_id in expired_clients:
                    del self.active_sessions[client_id]
                    logging.info(f"Session removed: {client_id}")

            except Exception as e:
                logging.error(f"Session monitor error: {e}")

            time.sleep(30)
    
    def start(self):
        """Start SPA server"""
        try:
            # Initialize mTLS Controller
            logging.info(f"Initializing mTLS Controller on port {self.mtls_port}...")
            mtls_controller.initialize_mtls_controller(host='0.0.0.0', port=self.mtls_port)
            time.sleep(2)  # Give controller time to start
            
            # Create UDP socket for SPA
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            
            logging.info("="*60)
            logging.info(f"SPA Server started")
            logging.info(f"  SPA Port: {self.port}")
            logging.info(f"  mTLS Port: {self.mtls_port}")
            logging.info(f"  Gateway: {self.gateway['name']}")
            logging.info(f"  Keepalive timeout: {self.keepalive_timeout}s")
            logging.info("="*60)
            
            # Signal handlers
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)
            
            # Main loop
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(4096)
                    self.handle_packet(data, addr)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logging.error(f"Error processing packet: {str(e)}")
                    continue
                    
        except KeyboardInterrupt:
            logging.info("Received KeyboardInterrupt, shutting down...")
        except Exception as e:
            logging.error(f"Server error: {str(e)}")
        finally:
            self.cleanup()

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        if not self.running:
            return
        logging.info(f"Received signal {signum}, shutting down...")
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass

    def cleanup(self):
        """Cleanup resources"""
        logging.info("Cleaning up...")
        
        # Remove all active sessions from gateway
        for client_id, session in list(self.active_sessions.items()):
            try:
                mtls_controller.send_remove_peer_to_gateway(
                    public_key=session['client_public_key'],
                    access_port=session['access_port'],
                    protocol=session['protocol'],
                    resource_id=session['resource_id'],
                    client_id=client_id
                )
                self.ip_pool.release_ip(client_id)
            except Exception as e:
                logging.error(f"Error cleaning up {client_id}: {e}")
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        
        logging.info("SPA Server shutdown complete")


def main():
    parser = argparse.ArgumentParser(
        description='SPA Server with mTLS Gateway Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  Start server with defaults:
    python3 spa_server_mtls.py

  Start with verbose output:
    python3 spa_server_mtls.py -v

  Use custom config:
    python3 spa_server_mtls.py -c custom_config.json

  Custom ports:
    python3 spa_server_mtls.py -p 12345
''')
    
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Verbose output')
    parser.add_argument('-c', '--config', default='server_config.json',
                      help='Config file path (default: server_config.json)')
    parser.add_argument('-p', '--port', type=int, default=62201,
                      help='SPA listen port (default: 62201)')
    parser.add_argument('--daemon', action='store_true',
                      help='Run as daemon')
    
    args = parser.parse_args()

    if args.daemon:
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            print(f"Fork failed: {e}")
            sys.exit(1)

        os.setsid()
        os.umask(0)

        sys.stdout.flush()
        sys.stderr.flush()
        si = open(os.devnull, 'r')
        so = open(os.devnull, 'a+')
        se = open(os.devnull, 'a+')
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

    server = SPAServer(
        config_file=args.config,
        verbose=args.verbose,
        port=args.port,
        daemon=args.daemon
    )
    
    try:
        server.start()
    except KeyboardInterrupt:
        server.cleanup()


if __name__ == "__main__":
    main()