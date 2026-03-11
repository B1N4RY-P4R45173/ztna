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

import mtls_controller


class VPNIPPool:
    """Manage VPN IP address pool allocation"""

    def __init__(self, ip_pool):
        self.available_ips = set(ip_pool)
        self.allocated_ips = {}     # client_id -> ip
        self.lock = threading.Lock()
        logging.info(f"IP Pool initialized with {len(self.available_ips)} addresses")

    def allocate_ip(self, client_id):
        with self.lock:
            if not self.available_ips:
                logging.error("IP pool exhausted!")
                return None
            ip = self.available_ips.pop()
            self.allocated_ips[client_id] = ip
            logging.info(f"Allocated {ip} to {client_id}")
            return ip

    def release_ip(self, client_id):
        with self.lock:
            if client_id in self.allocated_ips:
                ip = self.allocated_ips.pop(client_id)
                self.available_ips.add(ip)
                logging.info(f"Released {ip} from {client_id}")
                return True
            return False

    def get_allocated_ip(self, client_id):
        return self.allocated_ips.get(client_id)


class SPAServer:
    """SPA Server with mTLS Gateway integration"""

    def __init__(self, config_file='server_config.json', verbose=False,
                 port=62201, daemon=False):
        self.load_config(config_file)

        # Defaults from config, overridden by CLI args
        self.verbose          = self.config.get('verbose', False)
        self.port             = self.config.get('listen_port', 62201)
        self.daemon           = self.config.get('daemon', False)
        self.mtls_port        = self.config.get('mtls_controller_port', 5000)
        self.keepalive_timeout= self.config.get('keepalive_timeout', 300)

        if verbose:        self.verbose = verbose
        if port != 62201:  self.port    = port
        if daemon:         self.daemon  = daemon

        self.active_sessions = {}   # client_id -> session_info
        self.spa_requests    = {}   # key -> {timestamp, data}

        self.load_gateways()
        self.ip_pool = VPNIPPool(self.gateway['vpn_ip_pool'])

        self.setup_logging()
        self.setup_crypto()

        self.socket  = None
        self.running = True

        threading.Thread(target=self.monitor_sessions, daemon=True).start()
        logging.info("SPA Server initialized")

    # ------------------------------------------------------------------ #
    #  Config / setup                                                      #
    # ------------------------------------------------------------------ #
    def load_config(self, config_file):
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except FileNotFoundError:
            print(f"Error: Config file '{config_file}' not found")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in '{config_file}': {e}")
            sys.exit(1)

    def load_gateways(self):
        gateway_file = self.config.get('gateway_config', 'sdp_gateway_details.json')
        try:
            with open(gateway_file, 'r') as f:
                gateways = json.load(f)
            if not gateways:
                logging.error("No gateways configured!")
                sys.exit(1)
            self.gateway = gateways[0]
            logging.info(f"Loaded gateway: {self.gateway['name']} ({self.gateway['gateway_id']})")
        except FileNotFoundError:
            logging.error(f"Gateway config file '{gateway_file}' not found")
            sys.exit(1)
        except Exception as e:
            logging.error(f"Error loading gateway config: {e}")
            sys.exit(1)

    def setup_logging(self):
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        log_level  = logging.DEBUG if self.verbose else logging.INFO
        handlers   = []

        if 'log_file' in self.config:
            try:
                fh = logging.FileHandler(self.config['log_file'])
                fh.setFormatter(logging.Formatter(log_format))
                handlers.append(fh)
            except Exception as e:
                print(f"Failed to set up file logger: {e}")

        if self.verbose or not self.daemon:
            ch = logging.StreamHandler()
            ch.setFormatter(logging.Formatter(log_format))
            handlers.append(ch)

        root = logging.getLogger()
        root.handlers = []
        root.setLevel(log_level)
        for h in handlers:
            root.addHandler(h)

    def setup_crypto(self):
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
        master_key          = kdf.derive(password.encode('utf-8'))
        self.encryption_key = master_key[:32]
        self.hmac_key       = master_key[32:]

    # ------------------------------------------------------------------ #
    #  Crypto helpers                                                      #
    # ------------------------------------------------------------------ #
    def verify_hmac(self, data, received_hmac):
        h = hmac.new(self.hmac_key, data, hashlib.sha256)
        return hmac.compare_digest(h.digest(), received_hmac)

    def decrypt_packet(self, encrypted_data):
        if len(encrypted_data) < 48:
            raise ValueError("Packet too short")
        iv        = encrypted_data[:16]
        encrypted = encrypted_data[16:]
        cipher    = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor  = cipher.decryptor()
        padded     = decryptor.update(encrypted) + decryptor.finalize()
        unpadder   = padding.PKCS7(128).unpadder()
        data       = unpadder.update(padded) + unpadder.finalize()
        json_data  = data[:-32]
        recv_hmac  = data[-32:]
        return json_data, recv_hmac

    # ------------------------------------------------------------------ #
    #  Validation helpers                                                  #
    # ------------------------------------------------------------------ #
    def is_ip_allowed(self, ip):
        if 'allowed_ips' not in self.config:
            logging.warning("No allowed_ips configured — denying all")
            return False
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(
                ip_obj in ipaddress.ip_network(net, strict=False)
                for net in self.config['allowed_ips']
            )
        except ValueError:
            return False

    def is_keepalive_packet(self, packet_data):
        key          = "{source_ip}:{access_port}:{protocol}".format(**packet_data)
        current_time = time.time()
        if key in self.spa_requests:
            if current_time - self.spa_requests[key]['timestamp'] < 300:
                return True
        return False

    def generate_client_id(self, source_ip):
        return f"client-{source_ip}-{int(time.time())}-{str(uuid.uuid4())[:8]}"

    # ------------------------------------------------------------------ #
    #  Packet handling                                                     #
    # ------------------------------------------------------------------ #
    def handle_packet(self, data, addr):
        try:
            if self.verbose:
                logging.debug(f"Received packet from {addr[0]}:{addr[1]}")

            decrypted, received_hmac = self.decrypt_packet(data)

            if not self.verify_hmac(decrypted, received_hmac):
                logging.warning(f"Invalid HMAC from {addr[0]}")
                # Silently drop — do NOT send error response (SPA = no response on failure)
                return

            packet_data = json.loads(decrypted)

            if self.verbose:
                logging.debug("Packet contents:")
                pprint.pprint(packet_data)

            source_ip = packet_data.get('source_ip')
            if not source_ip:
                logging.warning(f"No source_ip in packet from {addr[0]}")
                return  # silent drop

            if not self.is_ip_allowed(source_ip):
                logging.warning(f"Unauthorized IP: {source_ip}")
                return  # silent drop

            protocol = packet_data.get('protocol')
            if 'allowed_protocols' in self.config:
                if protocol not in self.config['allowed_protocols']:
                    logging.warning(f"Unauthorized protocol: {protocol}")
                    return  # silent drop

            if self.is_keepalive_packet(packet_data):
                self.handle_keepalive(source_ip, addr, packet_data)
            else:
                self.handle_new_connection(packet_data, addr)

        except json.JSONDecodeError as e:
            logging.error(f"Invalid JSON from {addr[0]}: {e}")
        except Exception as e:
            logging.error(f"Error processing packet from {addr[0]}: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()

    def handle_keepalive(self, source_ip, addr, packet_data):
        client_id = next(
            (cid for cid, s in self.active_sessions.items()
             if s.get('source_ip') == source_ip),
            None
        )
        if client_id:
            self.active_sessions[client_id]['last_seen'] = time.time()
            key = "{source_ip}:{access_port}:{protocol}".format(**packet_data)
            if key in self.spa_requests:
                self.spa_requests[key]['timestamp'] = time.time()
            logging.info(f"Keepalive from {client_id} ({source_ip})")
            self.send_response(addr, "Keepalive acknowledged")
        else:
            logging.warning(f"Keepalive from unknown client: {source_ip}")

    def handle_new_connection(self, packet_data, addr):
        source_ip   = packet_data.get('source_ip')
        access_port = packet_data.get('access_port')
        protocol    = packet_data.get('protocol')
        # FIX: consistent naming — always use 'resource_ip' key
        resource_ip = packet_data.get('resource_ip')

        key = f"{source_ip}:{access_port}:{protocol}"
        self.spa_requests[key] = {'timestamp': time.time(), 'data': packet_data}

        logging.info(f"New SPA: {source_ip} → {resource_ip}:{access_port}/{protocol}")

        self.send_response(addr, "SPA Verification successful")
        self.receive_wireguard_key(addr, packet_data)

    # ------------------------------------------------------------------ #
    #  WireGuard key exchange                                              #
    # ------------------------------------------------------------------ #
    def receive_wireguard_key(self, addr, packet_data):
        """
        Receive WireGuard public key from client on the SAME server socket (port 62201).
        This avoids ephemeral port issues with Ryu flow rules — port 62201 is already
        allowed in the flow table so the key packet passes through without extra rules.
        """
        try:
            # Tell client to send key back to the same port (62201)
            self.send_response(addr, json.dumps({
                'status': 'send_key',
                'key_port': self.port      # same port — no new flow rules needed
            }))

            # Receive key on the shared server socket
            self.socket.settimeout(10)
            data, sender = self.socket.recvfrom(256)

            if sender[0] != addr[0]:
                logging.warning(f"Key from wrong IP: expected {addr[0]}, got {sender[0]}")
                return

            try:
                public_key = data.decode().strip()
            except UnicodeDecodeError:
                logging.warning(f"Invalid key encoding from {addr[0]}")
                return

            if not public_key:
                logging.warning(f"Empty key from {addr[0]}")
                return

            logging.info(f"WireGuard key from {addr[0]}: {public_key[:20]}...")

            source_ip   = packet_data.get('source_ip')
            access_port = packet_data.get('access_port')
            protocol    = packet_data.get('protocol')
            resource_ip = packet_data.get('resource_ip')

            client_id   = self.generate_client_id(source_ip)
            vpn_ip      = self.ip_pool.allocate_ip(client_id)

            if not vpn_ip:
                logging.error(f"IP pool exhausted for {client_id}")
                self.send_response(addr, json.dumps({'status': 'error', 'message': 'No available IPs'}))
                return

            vpn_ip_cidr = f"{vpn_ip}/32"

            success = self.configure_gateway_with_retry(
                vpn_ip=vpn_ip_cidr,
                public_key=public_key,
                access_port=access_port,
                protocol=protocol,
                resource_ip=resource_ip,
                client_id=client_id
            )

            if not success:
                self.ip_pool.release_ip(client_id)
                logging.error(f"Gateway config failed for {client_id}")
                self.send_response(addr, json.dumps({'status': 'error', 'message': 'Gateway config failed'}))
                return

            self.active_sessions[client_id] = {
                'source_ip':         source_ip,
                'client_public_key': public_key,
                'vpn_ip':            vpn_ip_cidr,
                'access_port':       access_port,
                'protocol':          protocol,
                'resource_ip':       resource_ip,
                'last_seen':         time.time(),
                'created_at':        time.time()
            }

            logging.info(f"Session created: {client_id} → VPN IP: {vpn_ip_cidr}")
            self.send_gateway_details(addr, vpn_ip)

        except socket.timeout:
            logging.warning(f"WireGuard key timeout from {addr[0]}")
        except Exception as e:
            logging.error(f"Error receiving WireGuard key from {addr[0]}: {e}")
        finally:
            self.socket.settimeout(None)

    def configure_gateway_with_retry(self, vpn_ip, public_key, access_port,
                                      protocol, resource_ip, client_id, max_retries=3):
        for attempt in range(1, max_retries + 1):
            logging.info(f"Gateway config attempt {attempt}/{max_retries} for {client_id}")
            success = mtls_controller.send_add_peer_to_gateway(
                vpn_ip=vpn_ip,
                public_key=public_key,
                access_port=access_port,
                protocol=protocol,
                resource_ip=resource_ip,    # FIX: renamed from resource_id
                client_id=client_id
            )
            if success:
                logging.info(f"✓ Gateway configured for {client_id}")
                return True
            if attempt < max_retries:
                logging.warning(f"Attempt {attempt} failed, retrying in 2s...")
                time.sleep(2)
        logging.error(f"✗ All {max_retries} attempts failed for {client_id}")
        return False

    # ------------------------------------------------------------------ #
    #  Response helpers                                                    #
    # ------------------------------------------------------------------ #
    def send_gateway_details(self, addr, vpn_ip):
        details = {
            'status':             'success',
            'gateway_public_key': self.gateway['wireguard_public_key'],
            'gateway_endpoint':   f"{self.gateway['gateway_public_ip']}:{self.gateway['listen_port']}",
            'client_vpn_ip':      vpn_ip,
            'vpn_subnet':         self.gateway['vpn_subnet'],
            'gateway_vpn_ip':     self.gateway['gateway_vpn_ip']
        }
        self.socket.sendto(json.dumps(details).encode(), addr)
        logging.info(f"Gateway details sent to {addr[0]}")

    def send_response(self, addr, message):
        try:
            payload = message if isinstance(message, bytes) else message.encode()
            self.socket.sendto(payload, addr)
        except Exception as e:
            logging.error(f"Error sending response to {addr[0]}: {e}")

    # ------------------------------------------------------------------ #
    #  Session monitor                                                     #
    # ------------------------------------------------------------------ #
    def monitor_sessions(self):
        logging.info("Session monitor started")
        while self.running:
            try:
                now = time.time()
                expired = []

                for client_id, session in list(self.active_sessions.items()):
                    if now - session['last_seen'] > self.keepalive_timeout:
                        logging.warning(
                            f"[TIMEOUT] {client_id} inactive for "
                            f"{int(now - session['last_seen'])}s"
                        )

                        # FIX: pass vpn_ip and use resource_ip (not resource_id)
                        mtls_controller.send_remove_peer_to_gateway(
                            public_key=session['client_public_key'],
                            vpn_ip=session['vpn_ip'],           # FIX: was missing
                            access_port=session['access_port'],
                            protocol=session['protocol'],
                            resource_ip=session['resource_ip'], # FIX: was resource_id
                            client_id=client_id
                        )

                        self.ip_pool.release_ip(client_id)
                        expired.append(client_id)

                for client_id in expired:
                    del self.active_sessions[client_id]
                    logging.info(f"Session expired: {client_id}")

            except Exception as e:
                logging.error(f"Session monitor error: {e}")

            time.sleep(30)

    # ------------------------------------------------------------------ #
    #  Start / stop                                                        #
    # ------------------------------------------------------------------ #
    def start(self):
        try:
            logging.info(f"Initializing mTLS Controller on port {self.mtls_port}...")
            mtls_controller.initialize_mtls_controller(host='0.0.0.0', port=self.mtls_port)
            time.sleep(2)

            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('0.0.0.0', self.port))

            logging.info("=" * 60)
            logging.info(f"SPA Server started on UDP port {self.port}")
            logging.info(f"  mTLS port:         {self.mtls_port}")
            logging.info(f"  Gateway:           {self.gateway['name']}")
            logging.info(f"  Keepalive timeout: {self.keepalive_timeout}s")
            logging.info("=" * 60)

            signal.signal(signal.SIGINT,  self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)

            while self.running:
                try:
                    data, addr = self.socket.recvfrom(4096)
                    self.handle_packet(data, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logging.error(f"Error processing packet: {e}")

        except KeyboardInterrupt:
            logging.info("KeyboardInterrupt — shutting down...")
        except Exception as e:
            logging.error(f"Server error: {e}")
        finally:
            self.cleanup()

    def signal_handler(self, signum, frame):
        if not self.running:
            return
        logging.info(f"Signal {signum} received — shutting down...")
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass

    def cleanup(self):
        logging.info("Cleaning up sessions...")
        for client_id, session in list(self.active_sessions.items()):
            try:
                # FIX: pass vpn_ip and use resource_ip (not resource_id)
                mtls_controller.send_remove_peer_to_gateway(
                    public_key=session['client_public_key'],
                    vpn_ip=session['vpn_ip'],           # FIX: was missing
                    access_port=session['access_port'],
                    protocol=session['protocol'],
                    resource_ip=session['resource_ip'], # FIX: was resource_id
                    client_id=client_id
                )
                self.ip_pool.release_ip(client_id)
            except Exception as e:
                logging.error(f"Cleanup error for {client_id}: {e}")

        if self.socket:
            try:
                self.socket.close()
            except Exception:
                pass

        logging.info("SPA Server shutdown complete")


# ======================================================================== #
#  Entry point                                                              #
# ======================================================================== #
def main():
    parser = argparse.ArgumentParser(
        description='SPA Server with mTLS Gateway Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  python3 spa_server.py
  python3 spa_server.py -v
  python3 spa_server.py -c custom_config.json
  python3 spa_server.py -p 12345
'''
    )
    parser.add_argument('-v', '--verbose',  action='store_true', help='Verbose output')
    parser.add_argument('-c', '--config',   default='server_config.json', help='Config file')
    parser.add_argument('-p', '--port',     type=int, default=62201, help='SPA listen port')
    parser.add_argument('--daemon',         action='store_true', help='Run as daemon')
    args = parser.parse_args()

    if args.daemon:
        try:
            if os.fork() > 0:
                sys.exit(0)
        except OSError as e:
            print(f"Fork failed: {e}")
            sys.exit(1)
        os.setsid()
        os.umask(0)
        for fd, path in [(sys.stdin, 'r'), (sys.stdout, 'a+'), (sys.stderr, 'a+')]:
            try:
                f = open(os.devnull, path if isinstance(path, str) else 'a+')
                os.dup2(f.fileno(), fd.fileno())
            except Exception:
                pass

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


if __name__ == '__main__':
    main()