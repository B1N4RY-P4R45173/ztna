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
    and sends policy enforcement commands
    """
    
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.gateway_connections = {}  # gateway_id -> connection
        self.running = True
        
    def create_ssl_context(self):
        """Create SSL context for mTLS server"""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        # Load Controller's certificate and key
        context.load_cert_chain(
            certfile='certs/controller_cert.pem',
            keyfile='certs/controller_key.pem'
        )
        
        # Load CA to verify Gateway
        context.load_verify_locations('certs/ca_cert.pem')
        
        # REQUIRE Gateway certificate
        context.verify_mode = ssl.CERT_REQUIRED
        
        return context
    
    def handle_gateway_connection(self, conn, addr):
        """Handle persistent connection from a Gateway"""
        try:
            # Get Gateway's certificate
            cert = conn.getpeercert()
            gateway_cn = dict(x[0] for x in cert['subject'])['commonName']
            
            logging.info(f"✓ Gateway connected: {gateway_cn} from {addr[0]}:{addr[1]}")
            
            # Store connection (using gateway_cn as identifier)
            # In future, you'll use gateway_id from your gateway table
            self.gateway_connections[gateway_cn] = {
                'connection': conn,
                'address': addr,
                'connected_at': time.time()
            }
            
            # Keep connection alive - just wait
            # Commands will be sent via send_policy_to_gateway()
            while self.running:
                # Check if connection is still alive
                try:
                    # Set short timeout to check periodically
                    conn.settimeout(30)
                    data = conn.recv(1)  # Minimal recv to detect disconnect
                    
                    if not data:
                        logging.warning(f"Gateway {gateway_cn} disconnected")
                        break
                        
                except socket.timeout:
                    # Normal - no data received, connection still alive
                    continue
                except Exception as e:
                    logging.error(f"Error with Gateway {gateway_cn}: {e}")
                    break
            
        except Exception as e:
            logging.error(f"Error handling Gateway connection: {e}")
        finally:
            # Clean up connection
            if gateway_cn in self.gateway_connections:
                del self.gateway_connections[gateway_cn]
            conn.close()
            logging.info(f"Gateway {gateway_cn} connection closed")
    
    def send_policy_to_gateway(self, gateway_id, policy_command):
        """
        Send policy command to specific Gateway and wait for response
        
        Args:
            gateway_id: Gateway identifier (currently using CN, later will be gateway_id)
            policy_command: Dictionary with action and parameters
            
        Returns:
            Response from Gateway or None if failed
        """
        # For now, use 'sdp-gateway' as default
        # In future, you'll look up which gateway based on resource_id
        if gateway_id not in self.gateway_connections:
            logging.error(f"Gateway {gateway_id} not connected")
            return None
        
        try:
            conn = self.gateway_connections[gateway_id]['connection']
            
            # Send command
            logging.info(f"Sending to {gateway_id}: {policy_command['action']}")
            conn.sendall(json.dumps(policy_command).encode('utf-8'))
            
            # Wait for response (with timeout)
            conn.settimeout(10)
            response_data = conn.recv(4096)
            
            if not response_data:
                logging.error(f"No response from Gateway {gateway_id}")
                return None
            
            response = json.loads(response_data.decode('utf-8'))
            logging.info(f"Gateway response: {response['status']}")
            
            return response
            
        except socket.timeout:
            logging.error(f"Gateway {gateway_id} response timeout")
            return None
        except Exception as e:
            logging.error(f"Error sending to Gateway {gateway_id}: {e}")
            return None
        finally:
            # Reset timeout
            try:
                conn.settimeout(None)
            except:
                pass
    
    def start_server(self):
        """Start mTLS server to accept Gateway connections"""
        logging.info("\n" + "="*60)
        logging.info(f"Starting mTLS Controller on {self.host}:{self.port}")
        logging.info("="*60)
        
        ssl_context = self.create_ssl_context()
        
        # Create server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        # Wrap with TLS
        secure_server = ssl_context.wrap_socket(server_socket, server_side=True)
        
        logging.info(f"✓ Controller listening (mTLS enabled)")
        logging.info("Waiting for Gateway connections...\n")
        
        try:
            while self.running:
                try:
                    conn, addr = secure_server.accept()
                    
                    # Handle each Gateway in separate thread
                    handler = threading.Thread(
                        target=self.handle_gateway_connection,
                        args=(conn, addr),
                        daemon=True
                    )
                    handler.start()
                    
                except Exception as e:
                    if self.running:
                        logging.error(f"Error accepting connection: {e}")
                        
        except KeyboardInterrupt:
            logging.info("\nShutting down Controller...")
        finally:
            secure_server.close()
            self.running = False


# Global instance for integration with SPA server
mtls_controller = None


def initialize_mtls_controller(host='0.0.0.0', port=5000):
    """
    Initialize mTLS Controller in a background thread
    Call this from your SPA server initialization
    """
    global mtls_controller
    
    mtls_controller = MTLSController(host=host, port=port)
    
    # Start server in background thread
    server_thread = threading.Thread(
        target=mtls_controller.start_server,
        daemon=True
    )
    server_thread.start()
    
    logging.info("mTLS Controller initialized")
    
    return mtls_controller


def send_add_peer_to_gateway(vpn_ip, public_key, access_port, protocol, resource_id, client_id):
    """
    Send add_peer command to Gateway
    Call this from your SPA server after successful SPA verification
    
    Returns:
        True if successful, False otherwise
    """
    global mtls_controller
    
    if not mtls_controller:
        logging.error("mTLS Controller not initialized")
        return False
    
    # Build command
    command = {
        'action': 'add_peer',
        'vpn_ip': vpn_ip,
        'public_key': public_key,
        'access_port': access_port,
        'protocol': protocol,
        'resource_id': resource_id,
        'client_id': client_id
    }
    
    # For now, hardcode gateway_id as 'sdp-gateway'
    # In future, you'll look up gateway based on resource_id
    gateway_id = 'sdp-gateway'
    
    # Send to Gateway and wait for response
    response = mtls_controller.send_policy_to_gateway(gateway_id, command)
    
    if response and response.get('status') == 'success':
        logging.info(f"✓ Peer added successfully for {client_id}")
        return True
    else:
        error_msg = response.get('message', 'Unknown error') if response else 'No response'
        logging.error(f"✗ Failed to add peer: {error_msg}")
        return False


def send_remove_peer_to_gateway(public_key, access_port, protocol, resource_id, client_id):
    """
    Send remove_peer command to Gateway
    Call this from your session timeout handler
    
    Returns:
        True if successful, False otherwise
    """
    global mtls_controller
    
    if not mtls_controller:
        logging.error("mTLS Controller not initialized")
        return False
    
    # Build command (same info as add_peer so Gateway knows what to remove)
    command = {
        'action': 'remove_peer',
        'public_key': public_key,
        'access_port': access_port,
        'protocol': protocol,
        'resource_id': resource_id,
        'client_id': client_id
    }
    
    # For now, hardcode gateway_id as 'sdp-gateway'
    gateway_id = 'sdp-gateway'
    
    # Send to Gateway and wait for response
    response = mtls_controller.send_policy_to_gateway(gateway_id, command)
    
    if response and response.get('status') == 'success':
        logging.info(f"✓ Peer removed successfully for {client_id}")
        return True
    else:
        error_msg = response.get('message', 'Unknown error') if response else 'No response'
        logging.error(f"✗ Failed to remove peer: {error_msg}")
        return False


# Standalone mode for testing
def main():
    """Run Controller in standalone mode for testing"""
    controller = MTLSController(host='0.0.0.0', port=5000)
    controller.start_server()


if __name__ == '__main__':
    main()