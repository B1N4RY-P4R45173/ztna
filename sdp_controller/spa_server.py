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
import ssh_manager

class SPAServer:
    def __init__(self, config_file='server_config.json', verbose=False, port=62201, daemon=False):
        # Load configuration first
        self.load_config(config_file)
        
        # Apply config defaults first, then command line overrides
        self.verbose = self.config.get('verbose', False)
        self.port = self.config.get('listen_port', 62201)
        self.daemon = self.config.get('daemon', False)
        
        # Command line arguments override config file settings
        if verbose:
            self.verbose = verbose
        if port != 62201:  # Only override if non-default port specified
            self.port = port
        if daemon:
            self.daemon = daemon
        
        self.active_sessions = {}
        self.keepalive_timeout = self.config.get("keepalive_timeout", 300)

        self.running = True
        self.session_monitor_thread = threading.Thread(
            target=self.monitor_sessions,
            daemon=True
        )
        self.session_monitor_thread.start()
        # Initialize other components
        self.setup_logging()
        self.setup_crypto()
        self.socket = None
        self.running = True
        # Track received SPA packets
        self.spa_requests = {}

    def load_config(self, config_file):
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            print(f"Error: Configuration file {config_file} not found")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in configuration file {config_file}: {e}")
            sys.exit(1)

    def setup_logging(self):
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        log_level = logging.DEBUG if self.verbose else logging.INFO
        handlers = []

        # Add file handler if specified in config
        if 'log_file' in self.config:
            try:
                file_handler = logging.FileHandler(self.config['log_file'])
                file_handler.setFormatter(logging.Formatter(log_format))
                handlers.append(file_handler)
            except Exception as e:
                print(f"Failed to set up file logger: {e}")

        # Add console handler if not daemon, or if verbose
        if self.verbose or not self.daemon:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(logging.Formatter(log_format))
            handlers.append(console_handler)

        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.handlers = []  # Clear existing handlers
        root_logger.setLevel(log_level)
        for handler in handlers:
            root_logger.addHandler(handler)
    
    def setup_crypto(self):
        # Derive AES key from encryption key
        if 'encryption_key' not in self.config:
            print("Error: encryption_key not found in configuration")
            sys.exit(1)
            
        password = self.config['encryption_key']
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,  # first 32 bytes for AES and next 32 for HMAC
            salt=b'ztna_salt',  # Fixed salt for consistency
            iterations=100000,
            backend=default_backend()
        )
        master_key = kdf.derive(password.encode('utf-8'))
        self.encryption_key = master_key[:32]
        self.hmac_key = master_key[32:]

    def verify_hmac(self, data, received_hmac):
        h = hmac.new(self.hmac_key, data, hashlib.sha256)
        return hmac.compare_digest(h.digest(), received_hmac)
    
    def decrypt_packet(self, encrypted_data):
        if len(encrypted_data) < 48:  # Minimum: 16 (IV) + 32 (HMAC) = 48 bytes
            raise ValueError("Packet too short")
            
        # Extract IV from the beginning of the packet
        iv = encrypted_data[:16]
        encrypted = encrypted_data[16:]
        
        # Decrypt using AES-CBC
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(encrypted) + decryptor.finalize()
        
        # Unpad the data
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        
        # Split data and HMAC
        json_data = data[:-32]  # HMAC is 32 bytes
        received_hmac = data[-32:]
        
        return json_data, received_hmac
    
    def is_ip_allowed(self, ip):
        if 'allowed_ips' not in self.config:
            logging.warning("No allowed_ips configured - denying all access")
            return False
            
        allowed_list = self.config['allowed_ips']
        try:
            ip_obj = ipaddress.ip_address(ip)
            for net in allowed_list:
                if ip_obj in ipaddress.ip_network(net, strict=False):
                    return True
            return False
        except ValueError:
            return False
    
    def is_keepalive_packet(self, packet_data):
        """
        Determine if this is a keepalive packet based on content or timing
        You can customize this logic based on your specific requirements
        """
        # Check if this is a repeat request from the same source within a short time
        source_ip = packet_data.get('source_ip')
        access_port = packet_data.get('access_port')
        protocol = packet_data.get('protocol')
        
        key = f"{source_ip}:{access_port}:{protocol}"
        current_time = time.time()
        
        if key in self.spa_requests:
            last_request_time = self.spa_requests[key]['timestamp']
            # If same request within 300 seconds, consider it a keepalive
            if current_time - last_request_time < 300:
                return True
        
        return False
    
    def handle_packet(self, data, addr):
        try:
            if self.verbose:
                print(f"\nReceived packet from {addr[0]}:{addr[1]}")
                print(f"Raw data (base64): {base64.b64encode(data).decode()}")
            
            # Decrypt the packet
            decrypted, received_hmac = self.decrypt_packet(data)
            
            if self.verbose:
                print(f"Decrypted data: {decrypted}")
                print(f"HMAC from packet: {received_hmac.hex()}")
            
            # Verify HMAC
            if not self.verify_hmac(decrypted, received_hmac):
                logging.warning(f"Invalid HMAC from {addr[0]}")
                self.reply(addr, False, is_keepalive=False)
                return

            # Parse the packet
            packet_data = json.loads(decrypted)
            
            if self.verbose:
                print("\nPacket contents:")
                pprint.pprint(packet_data)
            
            # Check if source IP is allowed
            source_ip = packet_data.get('source_ip')
            if not source_ip:
                logging.warning(f"No source_ip in packet from {addr[0]}")
                self.reply(addr, False, is_keepalive=False)
                return
                
            if not self.is_ip_allowed(source_ip):
                logging.warning(f"Unauthorized IP {source_ip}")
                self.reply(addr, False, is_keepalive=False)
                return
            
            # Check if protocol is allowed
            if 'allowed_protocols' in self.config:
                protocol = packet_data.get('protocol')
                if protocol not in self.config['allowed_protocols']:
                    logging.warning(f"Unauthorized protocol {protocol}")
                    self.reply(addr, False, is_keepalive=False)
                    return
            
            # Determine if this is a keepalive packet
            is_keepalive = self.is_keepalive_packet(packet_data)

            if is_keepalive:
                logging.info(f"Keepalive from {source_ip}")
                if source_ip in self.active_sessions:
                    self.active_sessions[source_ip]['last_seen'] = time.time()

                self.reply(addr, True, is_keepalive=True)
                return

            
            # Log the access request
            key = f"{source_ip}:{packet_data.get('access_port', '')}:{packet_data.get('protocol', '')}"
            self.spa_requests[key] = {
                'timestamp': time.time(),
                'data': packet_data
            }
            
            if is_keepalive:
                if self.verbose:
                    logging.info(f"Keepalive packet received from {source_ip}")
                # For keepalive packets, just send success response without expecting WireGuard key
                self.reply(addr, True, is_keepalive=True)
            else:
                logging.info(f"Authorized SPA request: {key}")
                # For initial packets, send success response and expect WireGuard key
                # Pass the packet_data to reply so it can be forwarded to receive_key
                self.reply(addr, True, is_keepalive=False, packet_data=packet_data)
            
        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON in packet from {addr[0]}: {e}")
            self.reply(addr, False, is_keepalive=False)
        except Exception as e:
            logging.error(f"Error processing packet from {addr[0]}: {str(e)}")
            self.reply(addr, False, is_keepalive=False)
            if self.verbose:
                import traceback
                traceback.print_exc()

    def receive_key(self, addr, packet_data):
        try:
            # Wait for client's WireGuard public key (max 10s)
            self.socket.settimeout(10)
            data, sender = self.socket.recvfrom(4096)

            # Key must come from same IP
            if sender[0] != addr[0]:
                logging.warning(f"Key received from different IP: expected {addr[0]}, got {sender[0]}")
                return

            try:
                key = data.decode().strip()
            except UnicodeDecodeError:
                logging.warning(f"Invalid key encoding received from {addr[0]}")
                return

            if not key:
                logging.warning(f"Empty WireGuard key received from {addr[0]}")
                error_response = json.dumps({'status': 'error', 'message': 'Empty key received'}).encode()
                self.socket.sendto(error_response, addr)
                return

            # Extract resource info from SPA packet
            resource_ip = packet_data.get('resource_ip')
            access_port = packet_data.get('access_port')

            # Load and resolve gateway
            gateways = ssh_manager.load_gateways()
            gateway = ssh_manager.resolve_gateway(resource_ip, gateways)

            if not gateway:
                logging.error(f"Gateway not found for resource {resource_ip}")
                return

            # Assign VPN IP for client
            vpn_ip = gateway["vpn_ip_pool"][0]

            logging.info(f"WireGuard public key received from {addr[0]}: {key}")

            # Add peer + ACL on gateway
            ssh_manager.add_peer(vpn_ip, key, resource_ip, gateway)
            ssh_manager.set_acl(packet_data, gateway)

            # ✅ Store active session (must include access_port for ACL removal)
            self.active_sessions[addr[0]] = {
                "client_public_key": key,
                "gateway": gateway,
                "last_seen": time.time(),
                "access_port": access_port
            }

            # Prepare gateway config for client response
            gateway_details = {
                'gateway_public_key': gateway['wireguard_public_key'],
                'gateway_endpoint': f"{gateway['gateway_public_ip']}:{gateway['listen_port']}",
                'client_vpn_ip': vpn_ip,
                'vpn_subnet': gateway['vpn_subnet'],
                'gateway_vpn_ip': gateway['gateway_vpn_ip'],
                'status': 'success'
            }

            # Send JSON back to client
            response = json.dumps(gateway_details).encode()
            self.socket.sendto(response, addr)

            logging.info(f"Gateway details sent to {addr[0]}: {gateway_details}")

        except socket.timeout:
            logging.warning(f"No WireGuard key received from {addr[0]} within timeout")

            timeout_response = json.dumps({'status': 'error', 'message': 'Key timeout'}).encode()
            try:
                self.socket.sendto(timeout_response, addr)
            except:
                pass

        except Exception as e:
            logging.error(f"Error receiving WireGuard key from {addr[0]}: {str(e)}")

            error_response = json.dumps({'status': 'error', 'message': str(e)}).encode()
            try:
                self.socket.sendto(error_response, addr)
            except:
                pass

        finally:
            # Reset socket timeout to normal
            self.socket.settimeout(None)


    def reply(self, addr, result, is_keepalive=False, packet_data=None):
        try:
            if result:
                if is_keepalive:
                    # For keepalive packets, just send success response
                    self.socket.sendto('SPA Keepalive acknowledged'.encode(), addr)
                    if self.verbose:
                        print(f"Keepalive acknowledged for {addr[0]}")
                else:
                    # For initial packets, send success response and wait for WireGuard key
                    self.socket.sendto('SPA Verification successful'.encode(), addr)
                    # Pass the packet_data to receive_key so it has access to resource_ip
                    self.receive_key(addr, packet_data)
            else:
                self.socket.sendto('SPA Verification Failed'.encode(), addr)
        except Exception as e:
            logging.error(f"Error sending reply to {addr[0]}: {str(e)}")

    def monitor_sessions(self):
        while self.running:
            try:
                now = time.time()
                expired_clients = []

                for client_ip, session in list(self.active_sessions.items()):
                    last_seen = session["last_seen"]

                    # Timeout check
                    if now - last_seen > self.keepalive_timeout:
                        pubkey = session["client_public_key"]
                        gateway = session["gateway"]
                        access_port = session["access_port"]

                        logging.warning(
                            f"[TIMEOUT] {client_ip} inactive → removing peer {pubkey}"
                        )

                        # Remove WireGuard peer
                        try:
                            ssh_manager.remove_peer(pubkey, gateway)
                        except Exception as e:
                            logging.error(f"Failed to remove peer {pubkey}: {e}")

                        # Remove ACL (now with access_port)
                        try:
                            if hasattr(ssh_manager, "remove_acl"):
                                ssh_manager.remove_acl(access_port, gateway)
                        except Exception as e:
                            logging.error(f"Failed to remove ACL for {client_ip}: {e}")

                        expired_clients.append(client_ip)

                # Remove sessions from table
                for client_ip in expired_clients:
                    del self.active_sessions[client_ip]

            except Exception as e:
                logging.error(f"Session monitor error: {e}")

            time.sleep(30)


        
    def start(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))
            logging.info(f"Server started on port {self.port}")
            logging.info(f"Listening on all interfaces (0.0.0.0)")
            
            # Set up signal handlers for graceful shutdown
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)
            
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(4096)
                    self.handle_packet(data, addr)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:  # Only log if we're still supposed to be running
                        logging.error(f"Error processing packet: {str(e)}")
                    continue
                    
        except KeyboardInterrupt:
            logging.info("Received KeyboardInterrupt, shutting down...")
        except Exception as e:
            logging.error(f"Server error: {str(e)}")
        finally:
            self.cleanup()

    def signal_handler(self, signum, frame):
        if not self.running:  # Prevent multiple shutdown attempts
            return
        logging.info(f"Received signal {signum}, shutting down...")
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass

    def cleanup(self):
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        logging.info("Server shutdown complete")

def main():
    parser = argparse.ArgumentParser(
        description='SPA Server - Single Packet Authorization',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  Start server on default port (62201):
    python3 spa_server.py

  Start server on custom port with verbose output:
    python3 spa_server.py -p 12345 -v

  Start server in daemon mode:
    python3 spa_server.py --daemon

  Use custom config file:
    python3 spa_server.py -c custom_config.json
''')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Show verbose output including packet details')
    parser.add_argument('-c', '--config', default='server_config.json',
                      help='Path to config file (default: server_config.json)')
    parser.add_argument('-p', '--port', type=int, default=62201,
                      help='Port to listen on (default: 62201)')
    parser.add_argument('--daemon', action='store_true',
                      help='Run server in daemon mode')
    args = parser.parse_args()

    if args.daemon:
        # Daemonize the process
        try:
            pid = os.fork()
            if pid > 0:
                # Parent process exits
                sys.exit(0)
        except OSError as e:
            print(f"Fork failed: {e}")
            sys.exit(1)

        # Create new session
        os.setsid()
        os.umask(0)

        # Redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(os.devnull, 'r')
        so = open(os.devnull, 'a+')
        se = open(os.devnull, 'a+')
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

    server = SPAServer(config_file=args.config, verbose=args.verbose, 
                      port=args.port, daemon=args.daemon)
    try:
        server.start()
    except KeyboardInterrupt:
        server.cleanup()

if __name__ == "__main__":
    main()