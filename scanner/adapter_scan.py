import subprocess
import os

LAST_ADAPTERS = set()
PRIMARY_INTERFACE = "wlan0"


def run_cmd(cmd):
    return subprocess.check_output(
        cmd,
        text=True,
        stderr=subprocess.DEVNULL
    ).strip()


def get_mac(interface):
    try:
        with open(f"/sys/class/net/{interface}/address", "r") as f:
            return f.read().strip()
    except Exception:
        return "unknown"


def get_state(interface):
    try:
        with open(f"/sys/class/net/{interface}/operstate", "r") as f:
            return f.read().strip()
    except Exception:
        return "unknown"


def scan_adapters():
    try:
        output = run_cmd(["iw", "dev"])
    except Exception as e:
        return [{"error": str(e), "hint": "Make sure iw is installed."}]

    adapters = []
    current = None

    for line in output.splitlines():
        line = line.strip()

        if line.startswith("Interface"):
            if current:
                adapters.append(current)

            iface = line.split()[1]

            current = {
                "interface": iface,
                "mode": "unknown",
                "mac": get_mac(iface),
                "state": get_state(iface),
                "primary": iface == PRIMARY_INTERFACE
            }

        elif line.startswith("type") and current:
            mode = line.split()[1]

            if mode == "P2P-device":
                continue

            current["mode"] = mode

    if current:
        adapters.append(current)

    return adapters

def detect_adapter_changes():
    global LAST_ADAPTERS

    adapters = scan_adapters()
    current_adapters = set()

    for adapter in adapters:
        if "interface" in adapter:
            current_adapters.add(adapter["interface"])

    added = current_adapters - LAST_ADAPTERS
    removed = LAST_ADAPTERS - current_adapters

    LAST_ADAPTERS = current_adapters

    return {
        "added": list(added),
        "removed": list(removed),
        "current": list(current_adapters)
    }


def set_adapter_mode(interface, mode):
    if interface == PRIMARY_INTERFACE:
        return {
            "ok": False,
            "error": f"{PRIMARY_INTERFACE} is the primary interface and cannot be changed."
        }

    if mode not in ["managed", "monitor"]:
        return {"ok": False, "error": "Invalid mode"}

    interfaces = [a.get("interface") for a in scan_adapters()]

    if interface not in interfaces:
        return {"ok": False, "error": "Interface not found"}

    try:
        subprocess.check_call(["sudo", "ip", "link", "set", interface, "down"])
        subprocess.check_call(["sudo", "iw", "dev", interface, "set", "type", mode])
        subprocess.check_call(["sudo", "ip", "link", "set", interface, "up"])

        return {
            "ok": True,
            "interface": interface,
            "mode": mode
        }

    except Exception as e:
        return {
            "ok": False,
            "error": str(e),
            "interface": interface,
            "mode": mode
        }
