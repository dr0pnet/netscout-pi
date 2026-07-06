# scanner/device_scan.py
import subprocess
import re
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from manuf import manuf

parser = manuf.MacParser()

# -------------------------
# Helper: ping a single host
# -------------------------
def ping_host(ip):
    try:
        subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except:
        pass

# -----------------------------------
# Wake LAN neighbors (parallel ping)
# -----------------------------------
def wake_lan_neighbors(network_cidr="192.168.68.0/24", exclude_ip=None):
    network = ipaddress.ip_network(network_cidr, strict=False)
    ips = [str(host) for host in network.hosts()]
    if exclude_ip:
        ips = [ip for ip in ips if ip != exclude_ip]

    with ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(ping_host, ips)

# -------------------------
# Main scan function
# -------------------------
def scan_devices():
    # Step 1: ping LAN to populate neighbor table
    wake_lan_neighbors(network_cidr="192.168.68.0/24", exclude_ip="192.168.68.13")

    devices = []

    # Step 2: read neighbor table
    try:
        output = subprocess.check_output(
            ["ip", "neigh"],
            text=True,
            stderr=subprocess.DEVNULL
        )
    except Exception as e:
        return [{"error": str(e)}]

    for line in output.splitlines():
        ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac_match = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", line)
        state = line.split()[-1] if line.split() else "unknown"

        if ip_match:
            ip = ip_match.group(1)
            mac = mac_match.group(1) if mac_match else None

            # MAC vendor lookup safely
            if mac:
                try:
                    vendor = parser.get_manuf(mac) or "Unknown / Private MAC"
                except:
                    vendor = "Unknown / Private MAC"
            else:
                vendor = "Unknown / Private MAC"
                mac = "Unknown"

            # Try to resolve hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = ""

            # Map neighbor state to Up/Down
            if state.lower() in ["reachable", "stale", "delay", "probe"]:
                state_display = "Up"
            else:
                state_display = "Down"

            devices.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "hostname": hostname,
                "state": state_display
            })

    return devices
