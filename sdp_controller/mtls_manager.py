import socket
import ssl

HOST = "0.0.0.0"
PORT = 8489

# Paths
CA_CERT = "../../certs/ca.crt"
SERVER_CERT = "./certs/ctrl.crt"
SERVER_KEY = "./certs/ctrl.key"


def main():
    # Create SSL context for server
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    # Require client certificate (this enables mTLS)
    context.verify_mode = ssl.CERT_REQUIRED

    # Load CA (to verify client cert)
    context.load_verify_locations(CA_CERT)

    # Load server cert + key
    context.load_cert_chain(
        certfile=SERVER_CERT,
        keyfile=SERVER_KEY
    )

    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(5)

    print(f"[+] mTLS Server listening on {PORT}")

    while True:
        client_sock, addr = sock.accept()
        print(f"[+] Connection from {addr}")

        try:
            # Wrap socket with TLS
            tls_conn = context.wrap_socket(
                client_sock,
                server_side=True
            )

            # Get client cert info
            cert = tls_conn.getpeercert()
            print("[+] Client certificate:", cert["subject"])

            data = tls_conn.recv(1024)
            print("[+] Received:", data.decode())

            reply = "Hello from Device A (secure)"
            tls_conn.send(reply.encode())

            tls_conn.close()

        except ssl.SSLError as e:
            print("[-] TLS Error:", e)


if __name__ == "__main__":
    main()
