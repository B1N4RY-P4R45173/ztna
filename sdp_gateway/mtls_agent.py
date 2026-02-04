import socket
import ssl

SERVER_HOST = "127.0.0.1"   # Change to Device A IP if remote
SERVER_PORT = 8489

# Paths
CA_CERT = "../../certs/ca.crt"
CLIENT_CERT = "./certs/gtwy.crt"
CLIENT_KEY = "./certs/gtwy.key"


def main():
    # Create SSL context for client
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)

    # Load CA (verify server)
    context.load_verify_locations(CA_CERT)

    # Load client cert + key
    context.load_cert_chain(
        certfile=CLIENT_CERT,
        keyfile=CLIENT_KEY
    )

    # Enforce hostname check
    context.check_hostname = False  # Disable if not using proper DNS
    context.verify_mode = ssl.CERT_REQUIRED

    # Create TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Wrap socket with TLS
    tls_sock = context.wrap_socket(
        sock,
        server_hostname=SERVER_HOST
    )

    print("[+] Connecting...")

    tls_sock.connect((SERVER_HOST, SERVER_PORT))

    print("[+] Secure connection established")

    message = "Hello from Device B"
    tls_sock.send(message.encode())

    reply = tls_sock.recv(1024)
    print("[+] Server replied:", reply.decode())

    tls_sock.close()


if __name__ == "__main__":
    main()
