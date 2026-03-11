from wireguard_tools import WireguardKey
import os
import json
import subprocess
import getpass

# FIX: generate keys once at module load — wrapped in a class so they
# survive reimports without regenerating (module-level singleton pattern)
class _KeyStore:
    def __init__(self):
        self._private = WireguardKey.generate()
        self._public  = self._private.public_key()

    @property
    def private_key(self):
        return self._private

    @property
    def public_key(self):
        return self._public

_keys = _KeyStore()


def get_public_key():
    return _keys.public_key


def get_wireguard_conf(response):
    decoded   = response.decode()
    json_data = json.loads(decoded)

    gateway_public_key = json_data.get("gateway_public_key")
    gateway_endpoint   = json_data.get("gateway_endpoint")
    client_vpn_ip      = json_data.get("client_vpn_ip")
    vpn_subnet         = json_data.get("vpn_subnet")
    gateway_vpn_ip     = json_data.get("gateway_vpn_ip")
    status             = json_data.get("status")

    if status != "success":
        print(f"⚠️  Gateway returned non-success status: {status}")
        return

    print("Received gateway WireGuard data")
    write_wireguard_conf(
        _keys.private_key,
        gateway_public_key,
        gateway_endpoint,
        client_vpn_ip,
        vpn_subnet,
        gateway_vpn_ip
    )


def write_wireguard_conf(
    private_key,
    gateway_public_key,
    gateway_endpoint,
    client_vpn_ip,
    vpn_subnet,
    gateway_vpn_ip,
    output_file="/etc/wireguard/wg0_conn.conf"   # FIX: absolute path for wg-quick
):
    """Write WireGuard config and bring up the tunnel."""
    print("Writing WireGuard config...")

    config_content = f"""[Interface]
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
        # FIX: ensure the directory exists, not the file path itself
        dir_path = os.path.dirname(output_file)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)

        with open(output_file, "w") as conf:
            conf.write(config_content)

        # Secure permissions — WireGuard requires this
        os.chmod(output_file, 0o600)
        print(f"✅ WireGuard config saved to: {output_file}")

        load_wireguard_conf(output_file)

    except PermissionError:
        print("❌ Permission denied! Run with sudo.")
    except Exception as e:
        print(f"⚠️  Failed to write WireGuard config: {e}")


def load_wireguard_conf(conf_path="/etc/wireguard/wg0_conn.conf"):
    """Bring up WireGuard tunnel using wg-quick."""
    print("🔄 Starting WireGuard tunnel...")

    if not os.path.exists(conf_path):
        print(f"❌ Config file not found: {conf_path}")
        return

    # FIX: wg-quick needs absolute path or interface name — use absolute path
    conf_path = os.path.abspath(conf_path)

    if os.geteuid() == 0:
        _run_wg_quick(conf_path)
        return

    # Not root — prompt for sudo password
    sudo_pass = getpass.getpass("Enter sudo password to activate WireGuard: ")
    cmd    = ["sudo", "-S", "wg-quick", "up", conf_path]
    result = subprocess.run(
        cmd,
        input=sudo_pass + "\n",
        text=True,
        capture_output=True
    )
    sudo_pass = " " * len(sudo_pass)   # clear from memory

    print(result.stdout or result.stderr)
    if result.returncode == 0:
        print("✅ WireGuard tunnel is active.")
    else:
        print(f"⚠️  wg-quick returned code {result.returncode}")


def _run_wg_quick(conf_path):
    """Run wg-quick as root."""
    result = subprocess.run(
        ["wg-quick", "up", conf_path],
        text=True,
        capture_output=True
    )
    print(result.stdout or result.stderr)
    if result.returncode == 0:
        print("✅ WireGuard tunnel is active.")
    else:
        print(f"⚠️  wg-quick returned code {result.returncode}")