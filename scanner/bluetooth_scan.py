import subprocess
import re

BLUETOOTH_SCAN_ENABLED = False
BLUETOOTH_CACHE = []
BLUETOOTH_ADAPTER = "00:C0:CA:B5:5B:FA"


def start_bluetooth_scan():
    global BLUETOOTH_SCAN_ENABLED

    BLUETOOTH_SCAN_ENABLED = True
    return {"ok": True, "scanning": True}


def stop_bluetooth_scan():
    global BLUETOOTH_SCAN_ENABLED

    try:
        subprocess.run(
            ["bluetoothctl", "scan", "off"],
            timeout=5,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
    except Exception:
        pass

    BLUETOOTH_SCAN_ENABLED = False
    return {"ok": True, "scanning": False}


def bluetooth_status():
    return {
        "scanning": BLUETOOTH_SCAN_ENABLED,
        "adapter": BLUETOOTH_ADAPTER,
        "cached_devices": len(BLUETOOTH_CACHE)
    }


def scan_bluetooth():
    global BLUETOOTH_CACHE

    if not BLUETOOTH_SCAN_ENABLED:
        return BLUETOOTH_CACHE

    try:
        cmd = f"""
        (
          echo "select {BLUETOOTH_ADAPTER}"
          echo "power on"
          echo "scan on"
          sleep 12
          echo "devices"
          echo "scan off"
          echo "quit"
        ) | bluetoothctl
        """

        output = subprocess.check_output(
            ["bash", "-c", cmd],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=20
        )

    except Exception as e:
        return [{"error": str(e), "hint": "Bluetooth scan failed."}]

    devices = {}

    for line in output.splitlines():
        match = re.search(r"(?:\[NEW\]\s+)?Device\s+([0-9A-F:]{17})\s+(.+)", line)

        if match:
            mac = match.group(1)
            name = match.group(2).strip()

            devices[mac] = {
                "mac": mac,
                "name": name,
                "rssi": "Unknown"
            }

    BLUETOOTH_CACHE = list(devices.values())
    return BLUETOOTH_CACHE
