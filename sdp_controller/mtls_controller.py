#!/usr/bin/env python3
"""
mTLS Controller - Accepts Gateway connections and sends policy commands
Integrates with existing SPA server
"""

import ssl
import socket
import json
import logging
import threading
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


class MTLSController:
    """
    Controller that maintains persistent mTLS connections to Gateways
    and sends policy enforcement commands.
    """

    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.gateway_connections = {}   # gateway_cn -> {connection, address, lock}
        self.running = True

    # ------------------------------------------------------------------ #
    #  SSL                                                                 #
    # ------------------------------------------------------------------ #
    def create_ssl_context(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(
            certfile='./certs/controller_cert.pem',
            keyfile='./certs/controller_key.pem'
        )
        context.load_verify_locations('./certs/ca_cert.pem')
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    # ------------------------------------------------------------------ #
    #  Reliable framed recv — FIX for recv(4096) truncation               #
    # ------------------------------------------------------------------ #
    def recv_message(self, conn):
        """
        Receive a complete newline-terminated JSON message from `conn`.
        Matches the newline-framing used in mtls_gateway.py send path.
        """
        buffer = b''
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                return None
            buffer += chunk
            if b'\n' in buffer:
                line, _ = buffer.split(b'\n', 1)
                return line.decode('utf-8')

    # ------------------------------------------------------------------ #
    #  Gateway connection handler                                          #
    # ------------------------------------------------------------------ #
    def handle_gateway_connection(self, conn, addr):
        """Handle persistent mTLS connection from a Gateway."""
        gateway_cn = None
        try:
            cert = conn.getpeercert()
            gateway_cn = dict(x[0] for x in cert['subject'])['commonName']

            logging.info(f"✓ Gateway connected: {gateway_cn} from {addr[0]}:{addr[1]}")

            self.gateway_connections[gateway_cn] = {
                'connection': conn,
                'address': addr,
                'connected_at': time.time(),
                'lock': threading.Lock()
            }

            # Simply sleep and let send_policy_to_gateway() detect
            # disconnection via send/recv exceptions under the lock.
            # Avoid any concurrent recv() here — it races with the response
            # recv in send_policy_to_gateway() and causes SSL buffer corruption
            # (double free / core dump in libssl).
            while self.running:
                if gateway_cn not in self.gateway_connections:
                    break
                time.sleep(5)

        except Exception as e:
            logging.error(f"Error handling Gateway connection: {e}")
        finally:
            if gateway_cn and gateway_cn in self.gateway_connections:
                del self.gateway_connections[gateway_cn]
            conn.close()
            logging.info(f"Gateway {gateway_cn} disconnected")

    # ------------------------------------------------------------------ #
    #  Send policy command                                                 #
    # ------------------------------------------------------------------ #
    def send_policy_to_gateway(self, gateway_id, policy_command):
        """
        Send a policy command to a connected Gateway and return its response.

        Args:
            gateway_id: Gateway CN (must match the CN in the gateway's cert)
            policy_command: dict with 'action' and required fields

        Returns:
            Response dict from Gateway, or None on failure.
        """
        if gateway_id not in self.gateway_connections:
            logging.error(f"Gateway '{gateway_id}' not connected. "
                          f"Connected gateways: {list(self.gateway_connections.keys())}")
            return None

        gateway_info = self.gateway_connections[gateway_id]
        conn  = gateway_info['connection']
        lock  = gateway_info['lock']

        with lock:
            try:
                # FIX: send newline-terminated JSON to match gateway recv_message()
                message = json.dumps(policy_command) + '\n'
                conn.sendall(message.encode('utf-8'))
                logging.info(f"→ Sent '{policy_command['action']}' to {gateway_id}")

                # FIX: use framed recv instead of raw recv(4096)
                conn.settimeout(15)
                raw = self.recv_message(conn)
                conn.settimeout(None)

                if raw is None:
                    logging.error(f"No response from Gateway {gateway_id}")
                    return None

                response = json.loads(raw)
                logging.info(f"← Gateway response: {response.get('status')}")
                return response

            except socket.timeout:
                logging.error(f"Gateway {gateway_id} response timeout")
                return None
            except Exception as e:
                logging.error(f"Error communicating with Gateway {gateway_id}: {e}")
                return None
            finally:
                try:
                    conn.settimeout(None)
                except Exception:
                    pass

    # ------------------------------------------------------------------ #
    #  Server                                                              #
    # ------------------------------------------------------------------ #
    def start_server(self):
        logging.info("\n" + "=" * 60)
        logging.info(f"Starting mTLS Controller on {self.host}:{self.port}")
        logging.info("=" * 60)

        ssl_context   = self.create_ssl_context()
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        secure_server = ssl_context.wrap_socket(server_socket, server_side=True)

        logging.info("✓ Controller listening (mTLS enabled)")
        logging.info("Waiting for Gateway connections...\n")

        try:
            while self.running:
                try:
                    conn, addr = secure_server.accept()
                    threading.Thread(
                        target=self.handle_gateway_connection,
                        args=(conn, addr),
                        daemon=True
                    ).start()
                except Exception as e:
                    if self.running:
                        logging.error(f"Error accepting connection: {e}")
        except KeyboardInterrupt:
            logging.info("\nShutting down Controller...")
        finally:
            secure_server.close()
            self.running = False


# ======================================================================== #
#  Module-level helpers used by spa_server.py                              #
# ======================================================================== #

mtls_controller_instance = None     # renamed from 'mtls_controller' to avoid
                                     # shadowing the module name on import


def initialize_mtls_controller(host='0.0.0.0', port=5000):
    global mtls_controller_instance
    mtls_controller_instance = MTLSController(host=host, port=port)
    threading.Thread(
        target=mtls_controller_instance.start_server,
        daemon=True
    ).start()
    logging.info("mTLS Controller initialized")
    return mtls_controller_instance


def send_add_peer_to_gateway(vpn_ip, public_key, access_port,
                              protocol, resource_ip, client_id):
    """
    Send add_peer command to Gateway after successful SPA verification.

    Args:
        vpn_ip:      Client VPN IP with /32 (e.g. '10.9.0.2/32')
        public_key:  Client WireGuard public key
        access_port: Port to allow on resource
        protocol:    'tcp' or 'udp'
        resource_ip: Resource host IP (e.g. '10.0.0.4')
        client_id:   Unique client identifier

    Returns:
        True if gateway confirmed success, False otherwise.
    """
    if not mtls_controller_instance:
        logging.error("mTLS Controller not initialized")
        return False

    command = {
        'action':      'add_peer',
        'vpn_ip':      vpn_ip,
        'public_key':  public_key,
        'access_port': access_port,
        'protocol':    protocol,
        'resource_id': resource_ip,   # gateway uses resource_id key internally
        'client_id':   client_id
    }

    # FIX: gateway CN must literally be 'gateway' in the certificate
    # If your cert CN is different, change this value to match
    response = mtls_controller_instance.send_policy_to_gateway('gateway', command)

    if response and response.get('status') == 'success':
        logging.info(f"✓ Peer added for {client_id}")
        return True

    error = response.get('message', 'Unknown error') if response else 'No response'
    logging.error(f"✗ Failed to add peer for {client_id}: {error}")
    return False


def send_remove_peer_to_gateway(public_key, vpn_ip, access_port,
                                 protocol, resource_ip, client_id):
    """
    Send remove_peer command to Gateway (session timeout / cleanup).

    FIX: added vpn_ip parameter — gateway needs it to delete the correct
    iptables rules. Previously missing, causing KeyError on gateway side.

    Returns:
        True if gateway confirmed success, False otherwise.
    """
    if not mtls_controller_instance:
        logging.error("mTLS Controller not initialized")
        return False

    command = {
        'action':      'remove_peer',
        'public_key':  public_key,
        'vpn_ip':      vpn_ip,           # FIX: was missing entirely
        'access_port': access_port,
        'protocol':    protocol,
        'resource_id': resource_ip,
        'client_id':   client_id
    }

    response = mtls_controller_instance.send_policy_to_gateway('gateway', command)

    if response and response.get('status') == 'success':
        logging.info(f"✓ Peer removed for {client_id}")
        return True

    error = response.get('message', 'Unknown error') if response else 'No response'
    logging.error(f"✗ Failed to remove peer for {client_id}: {error}")
    return False


def main():
    controller = MTLSController(host='0.0.0.0', port=5000)
    controller.start_server()


if __name__ == '__main__':
    main()