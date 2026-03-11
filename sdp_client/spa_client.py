#!/usr/bin/env python3
import socket
import json
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import time
import pprint
import hmac
import hashlib
import base64
import threading
import argparse
import wireguard


class SPAClient:
    def __init__(self, config_file='client_config.json', verbose=False,
                 access_port=None, server_port=62201, protocol='tcp',
                 source_ip=None, keepalive_interval=240):

        self.verbose = verbose
        self.load_config(config_file)

        # Config defaults, then CLI overrides
        if not verbose:
            self.verbose = self.config.get('verbose', False)
        self.keepalive_interval = self.config.get('keepalive_interval', 240)

        if access_port:                    self.config['access_port']  = access_port
        if source_ip:                      self.config['source_ip']    = source_ip
        if server_port != 62201:           self.config['server_port']  = server_port
        if protocol != 'tcp':             self.config['protocol']     = protocol
        if keepalive_interval != 240:     self.keepalive_interval     = keepalive_interval

        self.setup_crypto(self.password)
        self.keepalive_timer = None

    # ------------------------------------------------------------------ #
    #  Config / crypto                                                     #
    # ------------------------------------------------------------------ #
    def get_client_ip(self):
        """
        Get local IP via socket trick.
        FIX: falls back to config value if this fails (e.g. inside Mininet
        where there's no route to 8.8.8.8). Always set source_ip in
        client_config.json when running inside Mininet.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            # FIX: in Mininet there's no internet — fall back gracefully
            print("Warning: could not auto-detect IP (no internet route). "
                  "Set 'source_ip' in client_config.json.")
            return None

    def load_config(self, config_file):
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
            if not self.config.get("source_ip"):
                detected = self.get_client_ip()
                if not detected:
                    print("Error: source_ip not set in config and could not be auto-detected.")
                    sys.exit(1)
                self.config['source_ip'] = detected
            self.password = self.config['encryption_key']
        except FileNotFoundError:
            print(f"Error: Config file '{config_file}' not found")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in '{config_file}'")
            sys.exit(1)
        if self.verbose:
            print(f"Source IP: {self.config['source_ip']}")

    def setup_crypto(self, password):
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
    #  Packet creation                                                     #
    # ------------------------------------------------------------------ #
    def create_packet(self):
        iv = os.urandom(16)

        packet_data = {
            'source_ip':   self.config['source_ip'],
            'access_port': self.config['access_port'],
            'protocol':    self.config['protocol'],
            'timestamp':   int(time.time()),
            'message':     'SPA request from SDP Client',
            'resource_ip': self.config['resource_ip']
        }

        if self.verbose:
            print("\nPacket data:")
            pprint.pprint(packet_data)

        json_data    = json.dumps(packet_data).encode()
        h            = hmac.new(self.hmac_key, json_data, hashlib.sha256)
        hmac_digest  = h.digest()
        final_data   = json_data + hmac_digest

        padder      = padding.PKCS7(128).padder()
        padded_data = padder.update(final_data) + padder.finalize()

        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        return iv + encrypted

    # ------------------------------------------------------------------ #
    #  Key exchange                                                        #
    # ------------------------------------------------------------------ #
    def send_wireguard_key(self, sock, key_port):
        """
        Send WireGuard public key to the server's ephemeral key_port.
        FIX: server now sends back the ephemeral port to use — we must
        send to that port, not the original SPA port (62201).
        """
        try:
            public_key = wireguard.get_public_key()

            if self.verbose:
                print(f"Sending WireGuard public key to port {key_port}: {public_key}")

            key_bytes = str(public_key).encode()
            sock.sendto(key_bytes, (self.config['server_ip'], key_port))
            sock.settimeout(10)

            try:
                response, addr = sock.recvfrom(4096)
                if response:
                    # First check if this is another control message
                    try:
                        ctrl = json.loads(response.decode())
                        if ctrl.get('status') == 'error':
                            print(f"Server error: {ctrl.get('message')}")
                            return False
                    except json.JSONDecodeError:
                        pass

                    wireguard.get_wireguard_conf(response)
                    return True

            except socket.timeout:
                print("No response after sending WireGuard key")
                return False

        except Exception as e:
            print(f"Error sending WireGuard key: {e}")
            return False

    # ------------------------------------------------------------------ #
    #  Main send                                                           #
    # ------------------------------------------------------------------ #
    def send_packet(self, is_keepalive=False):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            packet = self.create_packet()
            sock.sendto(packet, (self.config['server_ip'], self.config['server_port']))

            if is_keepalive:
                print("Sent keepalive packet")
                return True

            print(f"SPA packet sent to {self.config['server_ip']}:{self.config['server_port']}")
            if self.verbose:
                print(f"Requesting access to port: {self.config['access_port']}")

            sock.settimeout(5)
            try:
                response, addr = sock.recvfrom(4096)
                if not response:
                    return False

                response_str = response.decode()
                print(response_str)

                # FIX: parse server's response.
                # Server sends two messages:
                #   1. Plain text "SPA Verification successful"
                #   2. JSON {"status": "send_key", "key_port": XXXX}
                # We need to read both before sending the WG key.
                try:
                    ctrl = json.loads(response_str)
                    if ctrl.get('status') == 'send_key':
                        key_port = ctrl['key_port']
                        if self.verbose:
                            print(f"Server ready for WireGuard key on port {key_port}")
                        return self.send_wireguard_key(sock, key_port)
                    elif ctrl.get('status') == 'error':
                        print(f"Server error: {ctrl.get('message')}")
                        return False
                except json.JSONDecodeError:
                    # Plain text response (e.g. "SPA Verification successful")
                    # Read the NEXT message which should be the send_key JSON
                    if self.verbose:
                        print("Plain text ack received — waiting for key_port assignment...")
                    try:
                        sock.settimeout(5)
                        response2, _ = sock.recvfrom(4096)
                        ctrl = json.loads(response2.decode())
                        if ctrl.get('status') == 'send_key':
                            key_port = ctrl['key_port']
                            if self.verbose:
                                print(f"Server ready for WireGuard key on port {key_port}")
                            return self.send_wireguard_key(sock, key_port)
                        elif ctrl.get('status') == 'error':
                            print(f"Server error: {ctrl.get('message')}")
                            return False
                    except (socket.timeout, json.JSONDecodeError, KeyError) as e:
                        if self.verbose:
                            print(f"Could not get key_port from server: {e}")
                        return False

            except socket.timeout:
                print("No response from server")
                return False

        except Exception as e:
            print(f"Error sending packet: {e}")
            return False
        finally:
            sock.close()

    # ------------------------------------------------------------------ #
    #  Keepalive                                                           #
    # ------------------------------------------------------------------ #
    def send_keepalive(self):
        try:
            self.send_packet(is_keepalive=True)
        except Exception as e:
            print(f"Error sending keepalive: {e}")
        finally:
            self.keepalive_timer = threading.Timer(
                self.keepalive_interval, self.send_keepalive)
            self.keepalive_timer.start()

    def start_keepalive(self):
        self.keepalive_timer = threading.Timer(
            self.keepalive_interval, self.send_keepalive)
        self.keepalive_timer.start()
        print(f"Keepalive started (interval: {self.keepalive_interval}s)")

    def stop_keepalive(self):
        if self.keepalive_timer:
            self.keepalive_timer.cancel()
            print("Keepalive stopped")


# ======================================================================== #
#  Entry point                                                              #
# ======================================================================== #
def main():
    parser = argparse.ArgumentParser(
        description='SPA Client - Sends Single Packet Authorization',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  python3 spa_client.py -A 22
  python3 spa_client.py -A 22 -v
  python3 spa_client.py -A 22 -c custom_config.json
'''
    )
    parser.add_argument('-A', '--access',     type=int,
                        help='Port to request access to')
    parser.add_argument('-p', '--port',       type=int, default=62201,
                        help='SPA server port (default: 62201)')
    parser.add_argument('-P', '--protocol',   choices=['tcp', 'udp'], default='tcp',
                        help='Protocol (default: tcp)')
    parser.add_argument('-s', '--source-ip',  type=str,
                        help='Override source IP')
    parser.add_argument('-k', '--keepalive',  type=int, default=240,
                        help='Keepalive interval seconds (default: 240)')
    parser.add_argument('-v', '--verbose',    action='store_true')
    parser.add_argument('-c', '--config',     default='client_config.json')
    args = parser.parse_args()

    client = SPAClient(
        config_file=args.config,
        access_port=args.access,
        server_port=args.port,
        protocol=args.protocol,
        source_ip=args.source_ip,
        keepalive_interval=args.keepalive,
        verbose=args.verbose
    )

    if client.send_packet():
        client.start_keepalive()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            client.stop_keepalive()
            print("\nClient shutting down")
    else:
        print("Failed to connect. Exiting.")
        sys.exit(1)


if __name__ == "__main__":
    main()