import re
import socket
import subprocess
from manuf import manuf

mac_parser = manuf.MacParser()

def discover_hosts():
    output = run_cmd([
        "nmap",
        "-sn",
        "192.168.68.0/24"
    ], timeout=60)

    devices = []

    current = {}

    for line in output.splitlines():

        if line.startswith("Nmap scan report for"):
            if current:
                devices.append(current)

            current = {
                "ip": line.split()[-1]
            }

        elif "MAC Address:" in line:
            m = re.search(
                r"MAC Address: ([0-9A-F:]+) \((.*?)\)",
                line
            )

            if m:
                current["mac"] = m.group(1)
                current["vendor"] = m.group(2)

    if current:
        devices.append(current)

    return devices

def run_cmd(cmd, timeout=4):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip()
    except Exception:
        return ""


def get_neighbors():
    output = run_cmd(["ip", "neigh"])
    devices = []

    for line in output.splitlines():
        parts = line.split()

        if len(parts) < 5:
            continue

        ip = parts[0]
        mac = None
        state = parts[-1]

        if "lladdr" in parts:
            mac = parts[parts.index("lladdr") + 1]

        if not mac:
            continue

        devices.append({
            "ip": ip,
            "mac": mac,
            "state": state
        })

    return devices


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def get_vendor(mac):
    if not mac or mac == "Unknown":
        return "Unknown"

    try:
        vendor = mac_parser.get_manuf(mac)
        return vendor if vendor else "Unknown"
    except Exception:
        return "Unknown"


def quick_ports(ip):
    ports = {
        22: "SSH",
        53: "DNS",
        80: "Web Interface",
        443: "Secure Web Interface",
        445: "Windows File Sharing",
        515: "Printer LPD",
        631: "IPP Printer",
        9100: "JetDirect Printer",
        62078: "Apple iOS Sync",
        7000: "AirPlay",
        8008: "Google Cast",
        8009: "Google Cast",
        8080: "Web Interface"
    }

    found = []

    for port, service in ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.25)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0 and service not in found:
                found.append(service)
        except Exception:
            pass

    return found


def classify_device(vendor, hostname, services):
    text = f"{vendor} {hostname} {' '.join(services)}".lower()

    if "apple" in text or "iphone" in text or "ipad" in text:
        return "Mobile Device", "iOS / Apple Device"

    if "samsung" in text or "android" in text:
        return "Mobile Device", "Android Device"

    if "hp" in text or "canon" in text or "epson" in text or "brother" in text:
        return "Printer", "Embedded Printer OS"

    if "jetdirect" in text or "ipp printer" in text or "printer" in text:
        return "Printer", "Embedded Printer OS"

    if "microsoft" in text or "windows" in text or "desktop" in text or "445" in text:
        return "Windows PC", "Windows"

    if "raspberry" in text or "linux" in text:
        return "Linux Device", "Linux"

    if "roku" in text:
        return "Streaming Device", "Roku OS"

    if "amazon" in text or "echo" in text:
        return "Smart Device", "Amazon Device"

    if "google" in text or "cast" in text or "chromecast" in text:
        return "Streaming Device", "Google Cast Device"

    if "router" in text or "gateway" in text:
        return "Router", "Network Gateway"

    return "Unknown Device", "Unknown"


def confidence_score(name, vendor, services, device_type):
    score = 20

    if name != "Unknown":
        score += 25

    if vendor != "Unknown":
        score += 25

    if services:
        score += 20

    if device_type != "Unknown Device":
        score += 10

    if score >= 80:
        return "High"
    if score >= 50:
        return "Medium"
    return "Low"


def get_identity_devices():
    raw_devices = discover_hosts()
    enriched = []

    for device in raw_devices:
        ip = device["ip"]
        mac = device.get("mac", "Unknown")

        hostname = get_hostname(ip)
        vendor = device.get("vendor") or get_vendor(mac)
        services = quick_ports(ip)

        device_type, os_guess = classify_device(vendor, hostname, services)
        confidence = confidence_score(hostname, vendor, services, device_type)

        name = hostname if hostname != "Unknown" else vendor
        if name == "Unknown":
            name = ip

        enriched.append({
            "name": name,
            "type": device_type,
            "vendor": vendor,
            "ip": ip,
            "mac": mac,
            "os": os_guess,
            "services": services,
            "state": device.get("state", "Online"),
            "confidence": confidence
        })

    return enriched
