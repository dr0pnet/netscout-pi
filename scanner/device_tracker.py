import json
from pathlib import Path
from scanner.device_scan import scan_devices

STATE_FILE = Path("state/devices.json")

def load_previous_devices():
    if not STATE_FILE.exists():
        return {}

    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_current_devices(devices):
    STATE_FILE.parent.mkdir(exist_ok=True)

    data = {
        device["ip"]: device
        for device in devices
        if device.get("ip")
    }

    with open(STATE_FILE, "w") as f:
        json.dump(data, f, indent=2)

def check_device_changes():
    previous = load_previous_devices()
    current_devices = scan_devices()

    current = {
        device["ip"]: device
        for device in current_devices
        if device.get("ip")
    }


    for ip, device in current.items():
        if ip not in previous:
                "type": "Device Joined",
                "message": f"New device detected: {ip} ({device.get('vendor', 'Unknown')})",
                "severity": "medium"
            })

    for ip, device in previous.items():
        if ip not in current:
                "type": "Device Left",
                "message": f"Device disappeared: {ip} ({device.get('vendor', 'Unknown')})",
                "severity": "low"
            })

    save_current_devices(current_devices)

