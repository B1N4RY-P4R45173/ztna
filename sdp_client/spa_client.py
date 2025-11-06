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
    def __init__(self, config_file='client_config.json', verbose=False, access_port=None, 
             server_port=62201, protocol='tcp', source_ip=None, keepalive_interval=240):
        # Initialize verbose first so it can be used in load_config
        self.verbose = verbose
        
        # Load configuration
        self.load_config(config_file)
        
        # Apply config defaults first, then command line overrides
        if not verbose:  # Only use config verbose if command line wasn't specified
            self.verbose = self.config.get('verbose', False)
        self.keepalive_interval = self.config.get('keepalive_interval', 240)
        
        # Command line arguments override config file settings
        if access_port:
            self.config['access_port'] = access_port
        if source_ip:
            self.config['source_ip'] = source_ip
        if server_port != 62201:  # Only override if non-default port specified
            self.config['server_port'] = server_port
        if protocol != 'tcp':  # Only override if non-default protocol specified
            self.config['protocol'] = protocol
        if keepalive_interval != 240:  # Only override if non-default interval specified
            self.keepalive_interval = keepalive_interval
        
        self.setup_crypto(self.password)
        self.keepalive_timer = None

    def get_client_ip(self): 
        """
        this only gets the private ip and will only work if the client is inside the home 
        network for prod servers please pass the ip in config file or as a command line argument
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip

    def load_config(self, config_file):
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
            if not self.config.get("source_ip"):
                self.config['source_ip'] = self.get_client_ip() # get client ip using sockets
            self.password = self.config['encryption_key'] # get the encryptionkey from config file
        except FileNotFoundError:
            print(f"Error: Configuration file {config_file} not found")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in configuration file {config_file}")
            sys.exit(1)
        if self.verbose:
                print(f"Detected source IP: {self.config['source_ip']}")

    def setup_crypto(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64,  # first32 bytes for AES and next 32 for HMAC
            salt=b'ztna_salt', 
            iterations=100000,
            backend=default_backend()
        )
        master_key = kdf.derive(password.encode('utf-8'))
        self.encryption_key = master_key[:32]
        self.hmac_key = master_key[32:]
    
    def create_packet(self):
        iv = os.urandom(16) # Generate a new IV for each packet

        packet_data = {
            'source_ip': self.config['source_ip'],
            'access_port': self.config['access_port'],
            'protocol': self.config['protocol'],
            'timestamp': int(time.time()),
            'message': 'SPA request from SDP Client',
            'resource_ip':self.config['resource_ip']
        }      
        if self.verbose:
            print("\nPacket data:")
            pprint.pprint(packet_data)

        json_data = json.dumps(packet_data).encode()
        h = hmac.new(self.hmac_key, json_data, hashlib.sha256)
        hmac_digest = h.digest()
        
        if self.verbose:
            print(f"\nHMAC digest (hex):")
            print(hmac_digest.hex())
        
        # Combine data and HMAC
        final_data = json_data + hmac_digest

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(final_data) + padder.finalize()

        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        final_packet = iv + encrypted # the first 16 bits is the iv which will be extracted on server side
        
        if self.verbose:
            print(f"\nEncrypted data (base64):")
            print(base64.b64encode(final_packet).decode())
        
        return final_packet

    def send_keepalive(self):
        try:
            self.send_packet(is_keepalive=True)
            if self.verbose:
                print(f"Keepalive packet sent to {self.config['server_ip']}:{self.config['server_port']}")
        except Exception as e:
            print(f"Error sending keepalive packet: {str(e)}")
        finally:
            # Schedule next keepalive
            self.keepalive_timer = threading.Timer(
                self.keepalive_interval,
                self.send_keepalive
            )
            self.keepalive_timer.start()
    
    def send_wireguard_key(self, sock):
        try: 
            public_key = wireguard.get_public_key()
            
            if self.verbose:
                print(f"WireGuard public key sent to the server: {public_key}")

            key_bytes = str(public_key).encode()
            sock.sendto(key_bytes, (self.config['server_ip'], self.config['server_port']))
            sock.settimeout(5)

            try:
                response, addr = sock.recvfrom(1024)
                if response:
                    wireguard.get_wireguard_conf(response)
                    # print("Server response to key:", response.decode())

            except socket.timeout:
                print("No response received after sending WireGuard key")

        except Exception as e:
            print(f"Error sending WireGuard key: {e}")

    def send_packet(self, is_keepalive=False):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Open a UDP socket
            packet = self.create_packet() # Create the packet

            sock.sendto(packet, (self.config['server_ip'], self.config['server_port']))

            if not is_keepalive:
                print(f"SPA packet sent to {self.config['server_ip']}:{self.config['server_port']}")
            else:
                print(f"sent a Keepalive packet")

            if self.verbose and not is_keepalive:
                print(f"Requesting access to port: {self.config['access_port']}")
            
            # Only wait for response and send WireGuard key for initial packets, not keepalive
            if not is_keepalive:
                sock.settimeout(5)
                try:
                    response, addr = sock.recvfrom(1024)
                    
                    if response:
                        print(response.decode())
                        # Only send WireGuard key for successful initial authentication
                        self.send_wireguard_key(sock)
                        return True  # Success
                            
                except socket.timeout:
                    print("No response received from server")
                    return False  # Failed
            
            return True  # For keepalive packets, assume success

        except Exception as e:
            print(f"Error sending packet: {str(e)}")
            return False  # Failed
        finally:
            sock.close()

    def start_keepalive(self):
        # Start keepalive timer
        self.keepalive_timer = threading.Timer(
            self.keepalive_interval,
            self.send_keepalive
        )
        self.keepalive_timer.start()
        if self.verbose:
            print(f"Keepalive mechanism started (interval: {self.keepalive_interval} seconds)")
        else:
            print("Keepalive mechanism started")

    def stop_keepalive(self):
        if self.keepalive_timer:
            self.keepalive_timer.cancel()
            print("Keepalive mechanism stopped")
def main():
    parser = argparse.ArgumentParser(
        description='SPA Client - Sends Single Packet Authorization',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  Request access to port 80 (TCP):
    python3 spa_client.py -A 80 -p 62201

  Request access to port 53 (UDP):
    python3 spa_client.py -A 53 -P udp -p 62201

  Request access to port 443 with verbose output:
    python3 spa_client.py -A 443 -p 62201 -v

  Specify source IP and keepalive interval:
    python3 spa_client.py -A 80 -s 192.168.1.100 -k 120 (for 2 minutes)

  Use custom config file:
    python3 spa_client.py -A 22 -p 62201 -c custom_config.json
''')
    parser.add_argument('-A', '--access', type=int,
                      help='Target port to request access to (overrides config file)')
    parser.add_argument('-p', '--port', type=int, default=62201,
                      help='Destination port to send SPA packet to (default: 62201)')
    parser.add_argument('-P', '--protocol', choices=['tcp', 'udp'], default='tcp',
                      help='Protocol to request access for (default: tcp)')
    parser.add_argument('-s', '--source-ip', type=str,
                      help='Override source IP address')
    parser.add_argument('-k', '--keepalive', type=int, default=240,
                      help='Keepalive interval in seconds (default: 240)')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Show verbose output including packet details')
    parser.add_argument('-c', '--config', default='client_config.json',
                      help='Path to config file (default: client_config.json)')
    args = parser.parse_args()

    client = SPAClient(config_file=args.config, access_port=args.access, 
                      server_port=args.port, protocol=args.protocol,
                      source_ip=args.source_ip, keepalive_interval=args.keepalive,
                      verbose=args.verbose)
    
    # Send initial packet and check if successful
    if client.send_packet():
        client.start_keepalive()  # Only start keepalive if initial packet was successful
        try:
            # Keep the script running
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            client.stop_keepalive()
            print("\nClient shutting down")
    else:
        print("Failed to connect to server. Exiting.")
        sys.exit(1)

if __name__ == "__main__":
    main()