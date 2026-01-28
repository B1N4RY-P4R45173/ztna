from  wireguard_tools import *
import os
import json
import subprocess
import os
import getpass

private_key = WireguardKey.generate()
public_key = private_key.public_key()

def get_public_key():
    return public_key

def get_wireguard_conf(response):
    decoded = response.decode()
    json_data = json.loads(decoded)

    gateway_public_key = json_data.get("gateway_public_key")
    gateway_endpoint = json_data.get("gateway_endpoint")
    client_vpn_ip = json_data.get("client_vpn_ip")
    vpn_subnet = json_data.get("vpn_subnet")
    gateway_vpn_ip = json_data.get("gateway_vpn_ip")
    status = json_data.get("status")

    print("Received gateway wireguard data")
    write_wireguard_conf(private_key, gateway_public_key, gateway_endpoint, client_vpn_ip, vpn_subnet, gateway_vpn_ip)
    

def write_wireguard_conf(
    private_key,
    gateway_public_key,
    gateway_endpoint,
    client_vpn_ip,
    vpn_subnet,
    gateway_vpn_ip,
    output_file="./wg0_conn.conf"
):
    """
    Creates a proper WireGuard config on Linux-B using received tunnel parameters.
    """
    print("writing to conf file")
    config_content = f"""
[Interface]
PrivateKey = {private_key}
Address = {client_vpn_ip}/24
ListenPort = 51820

[Peer]
PublicKey = {gateway_public_key}
AllowedIPs = {vpn_subnet}
Endpoint = {gateway_endpoint}
PersistentKeepalive = 25
"""

    try:
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        with open(output_file, "w") as conf:
            conf.write(config_content)

        # Secure file permissions — critical for WireGuard private key
        os.chmod(output_file, 0o600)

        print(f"✅ WireGuard configuration saved to: {output_file}")
        load_wireguard_conf()

    except PermissionError:
        print("❌ Permission denied! Run with sudo.")
    except Exception as e:
        print(f"⚠️ Failed to write WireGuard config: {e}")

def load_wireguard_conf(conf_path="./wg0_conn.conf"):
    """
    Starts WireGuard using the generated configuration.
    Prompts for sudo password if not executed as root.
    """

    print("🔄 Starting WireGuard tunnel...")

    if not os.path.exists(conf_path):
        print(f"❌ Config file does not exist: {conf_path}")
        return

    # Check if root already
    if os.geteuid() == 0:
        cmd = ["wg-quick", "up", conf_path]
        result = subprocess.run(cmd, text=True, capture_output=True)
        print(result.stdout or result.stderr)

        if result.returncode == 0:
            print("✅ WireGuard tunnel is active.")
        else:
            print(f"⚠️ wg-quick returned code {result.returncode}")
        return

    # Not root → ask for password and run with sudo
    sudo_pass = getpass.getpass("Enter sudo password to activate WireGuard: ")

    cmd = ["sudo", "-S", "wg-quick", "up", conf_path]

    result = subprocess.run(
        cmd,
        input=sudo_pass + "\n",
        text=True,
        capture_output=True
    )

    # Clear password from memory
    sudo_pass = " " * len(sudo_pass)

    print(result.stdout or result.stderr)

    if result.returncode == 0:
        print("✅ WireGuard tunnel is active.")
    else:
        print(f"⚠️ wg-quick returned code {result.returncode}")
