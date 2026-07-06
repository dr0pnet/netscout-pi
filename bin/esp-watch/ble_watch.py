#!/usr/bin/env python3
"""NetSc0ut ESP Watch BLE sidecar.
Passive BLE/name watcher using bluetoothctl. It prints ESP/Marauder-like BLE names,
and in aggressive mode prints any named BLE device once/repeated by cooldown.
"""
import argparse
import re
import subprocess
import sys
import time

ESP_WORDS = [
    "esp", "esp32", "esp8266", "espressif", "marauder", "wled", "tasmota",
    "esphome", "nodemcu", "lolin", "cyd", "evil", "portal"
]

def ts():
    return time.strftime("%H:%M:%S")

def looks_esp(text: str) -> bool:
    t = text.lower()
    return any(w in t for w in ESP_WORDS)

def emit(label, msg):
    print(f"[{ts()}] [{label}] {msg}", flush=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("iface", nargs="?", default="hci0")
    ap.add_argument("--all", action="store_true", help="print all named BLE devices, not only ESP-like names")
    ap.add_argument("--dedupe", type=int, default=3)
    args = ap.parse_args()

    emit("BLE WATCH", f"Starting BLE sidecar on {args.iface}. all={args.all} dedupe={args.dedupe}s")

    # Best effort power-on. Do not fail the whole tool if Bluetooth is not available.
    subprocess.run(["bluetoothctl", "power", "on"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        proc = subprocess.Popen(
            ["bluetoothctl", "scan", "on"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        emit("BLE ERROR", "bluetoothctl not found; install bluez")
        return 0
    except Exception as e:
        emit("BLE ERROR", f"failed to start bluetoothctl: {e}")
        return 0

    last = {}
    device_re = re.compile(r"Device\s+([0-9A-Fa-f:]{17})(?:\s+(.+))?")
    name_re = re.compile(r"Name:\s*(.+)$")
    rssi_re = re.compile(r"RSSI:\s*(-?\d+)")

    last_mac = None
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue

        mac = None
        name = None
        rssi = None

        m = device_re.search(line)
        if m:
            mac = m.group(1).upper()
            last_mac = mac
            possible_name = (m.group(2) or "").strip()
            if possible_name and not possible_name.startswith("("):
                name = possible_name

        nm = name_re.search(line)
        if nm and last_mac:
            mac = last_mac
            name = nm.group(1).strip()

        rm = rssi_re.search(line)
        if rm and last_mac:
            mac = last_mac
            rssi = rm.group(1)

        if not mac:
            continue

        text = f"{name or ''} {line}"
        esp_like = looks_esp(text)
        if not esp_like and not args.all:
            continue

        key = f"{mac}:{name or ''}:{'esp' if esp_like else 'all'}"
        now = time.time()
        if key in last and now - last[key] < args.dedupe:
            continue
        last[key] = now

        if esp_like:
            emit("BLE ESP-LIKE", f"mac={mac} name=\"{name or '-'}\" rssi={rssi or '?'} confidence=High reason=\"BLE name/event looks ESP/Marauder-related\"")
        else:
            emit("BLE PASSIVE", f"mac={mac} name=\"{name or '-'}\" rssi={rssi or '?'} reason=\"named BLE device seen\"")

    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        pass
