import subprocess
import sys
import json

def load_gateways(json_path="sdp_gateway_details.json"):
    try:
        with open(json_path, "r") as file:
            return json.load(file)
    except Exception as e:
        print(f"Failed to load gateways: {e}")
        sys.exit(1)

def resolve_gateway(resource_ip, gateways):
    resource_to_gateway_id = {
        "resource-1": "gw-01",
        "resource-2": "gw-02"
    }

    gateway_id = resource_to_gateway_id.get(resource_ip)
    if not gateway_id:
        print(f"Invalid resource identifier: {resource_ip}")
        return

    for gw in gateways:
        if gw["gateway_id"] == gateway_id:
            return gw

    print(f"Gateway with ID '{gateway_id}' not found.")
    return None

def add_peer(client_vpn_ip, client_pub_key, resource_id, gateway):

    ssh_user = gateway["ssh_user"]
    ssh_host = gateway["ssh_host"]
    ssh_port = gateway["ssh_port"]
    ssh_key_path = gateway["ssh_key_path"]
    wg_interface = gateway["wireguard_interface"]  # e.g., 'wg0'


    wg_cmd = f" wg set {wg_interface} peer {client_pub_key} allowed-ips {client_vpn_ip}/32"
    ssh_command = [
        "ssh",
        "-i", ssh_key_path,
        "-p", str(ssh_port),
        f"{ssh_user}@{ssh_host}",
        wg_cmd
    ]
    print(f"\n [+] Connecting to {gateway['name']} ({ssh_host}) using key {ssh_key_path}...\n")

    
    try:
        result = subprocess.run(ssh_command, capture_output=True, text=True, check=True)
        print("[+] Peer successfully added to live WireGuard interface.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to run wg command:\n{e.stderr}")
    except Exception as ex:
        print(f"[!] Unexpected error: {ex}")

def set_acl(packet_data, gateway):
    access_port = packet_data["access_port"]
    ssh_user = gateway["ssh_user"]
    ssh_host = gateway["ssh_host"]
    ssh_port = gateway["ssh_port"]
    ssh_key_path = gateway["ssh_key_path"]
    

    cmd = (
        f"sudo iptables -F FORWARD && "
        f"sudo iptables -A FORWARD -i wg0 -o ens38 -s 10.9.0.0/24 -d 10.10.2.0/24 -p tcp --dport {access_port} -j ACCEPT && "
        f"sudo iptables -A FORWARD -i wg0 -o ens38 -j DROP"
    )

    ssh_command = [
        "ssh",
        "-i", ssh_key_path,
        "-p", str(ssh_port),
        f"{ssh_user}@{ssh_host}",
        cmd
    ]

    print(f"\n [+] Connecting to {gateway['name']} ({ssh_host}) using key {ssh_key_path}...\n")
    
    try:
        result = subprocess.run(ssh_command, capture_output=True, text=True, check=True)
        print("[+] ACL list successfully updated")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to add ACL lists:\n{e.stderr}")
    except Exception as ex:
        print(f"[!] Unexpected error: {ex}")
    
def remove_peer(client_pub_key, gateway):
    """
    Remove a WireGuard peer from a gateway using its public key.
    Uses SSH and subprocess.run (same style as add_peer).
    """

    ssh_user = gateway["ssh_user"]
    ssh_host = gateway["ssh_host"]
    ssh_port = gateway["ssh_port"]
    ssh_key_path = gateway["ssh_key_path"]
    wg_interface = gateway["wireguard_interface"]  # e.g. "wg0"

    print(f"\n [-] Removing WireGuard peer {client_pub_key[:16]}... from {gateway['name']} ({ssh_host})")

    # WireGuard removal command
    wg_remove_cmd = f"sudo wg set {wg_interface} peer {client_pub_key} remove"

    ssh_command = [
        "ssh",
        "-i", ssh_key_path,
        "-p", str(ssh_port),
        f"{ssh_user}@{ssh_host}",
        wg_remove_cmd
    ]

    try:
        result = subprocess.run(ssh_command, capture_output=True, text=True, check=True)
        print("[+] Peer successfully removed from WireGuard interface.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to remove peer:\n{e.stderr}")
    except Exception as ex:
        print(f"[!] Unexpected error: {ex}")

    # Optional routing cleanup
    cleanup_cmd = "sudo ip route flush cache"
    ssh_cleanup = [
        "ssh",
        "-i", ssh_key_path,
        "-p", str(ssh_port),
        f"{ssh_user}@{ssh_host}",
        cleanup_cmd
    ]

    try:
        subprocess.run(ssh_cleanup, capture_output=True, text=True)
        print("[+] Flushed routing cache.")
    except Exception as e:
        print(f"[!] Route cache cleanup failed: {e}")

def remove_acl(access_port, gateway):
    ssh_user = gateway["ssh_user"]
    ssh_host = gateway["ssh_host"]
    ssh_port = gateway["ssh_port"]
    ssh_key_path = gateway["ssh_key_path"]

    delete_acl_cmd = (
        f"sudo iptables -D FORWARD -i wg0 -o ens38 -s 10.9.0.0/24 -d 10.10.2.0/24 "
        f"-p tcp --dport {access_port} -j ACCEPT ; "
        f"sudo iptables -D FORWARD -i wg0 -o ens38 -j DROP"
    )

    ssh_command = [
        "ssh",
        "-i", ssh_key_path,
        "-p", str(ssh_port),
        f"{ssh_user}@{ssh_host}",
        delete_acl_cmd
    ]

    try:
        subprocess.run(ssh_command, capture_output=True, text=True)
        print("[+] ACL rules successfully removed.")
    except Exception as e:
        print(f"[!] Failed to remove ACL rules: {e}")
