import subprocess
import re


def split_nmcli_line(line):
    return re.split(r'(?<!\\):', line)


def clean_field(value):
    return value.replace("\\:", ":").strip()


def signal_value_from_text(signal):
    signal = str(signal)
    signal = "".join(ch for ch in signal if ch.isdigit())
    return int(signal) if signal else 0


def get_band(freq):
    freq = str(freq)
    freq = "".join(ch for ch in freq if ch.isdigit())

    try:
        freq = int(freq)
    except:
        return "Unknown"

    if 2400 <= freq <= 2500:
        return "2.4 GHz"
    elif 5000 <= freq <= 5900:
        return "5 GHz"
    elif 5900 <= freq <= 7100:
        return "6 GHz"
    return "Unknown"

def signal_quality(signal):
    value = signal_value_from_text(signal)

    if value >= 80:
        return "Excellent"
    elif value >= 60:
        return "Good"
    elif value >= 40:
        return "Fair"
    else:
        return "Weak"


def get_connected_wifi():
    try:
        output = subprocess.check_output(
            ["nmcli", "-t", "-f", "ACTIVE,SSID,DEVICE,SIGNAL", "dev", "wifi"],
            text=True,
            stderr=subprocess.DEVNULL
        )

        for line in output.splitlines():
            parts = split_nmcli_line(line)

            if len(parts) >= 4 and parts[0] == "yes":
                ssid = clean_field(parts[1])
                iface = clean_field(parts[2])
                signal = clean_field(parts[3])

                return {
                    "ssid": ssid or "Unknown",
                    "interface": iface or "Unknown",
                    "signal": signal,
                    "quality": signal_quality(signal),
                    "state": "Connected"
                }

    except Exception as e:
        return {
            "ssid": "Unknown",
            "interface": "Unknown",
            "signal": "Unknown",
            "quality": "Unknown",
            "state": f"Error: {e}"
        }

    return {
        "ssid": "Not connected",
        "interface": "Unknown",
        "signal": "Unknown",
        "quality": "Unknown",
        "state": "Disconnected"
    }


def scan_wifi():
    try:
        cmd = [
            "nmcli",
            "-t",
            "-f",
            "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY",
            "dev",
            "wifi",
            "list",
            "ifname",
            "wlan1"
        ]

        output = subprocess.check_output(
            cmd,
            text=True,
            stderr=subprocess.DEVNULL
        )

    except Exception as e:
        return [{
            "error": str(e),
            "hint": "Make sure NetworkManager/nmcli is installed and wlan1 exists."
        }]

    grouped = {}

    for line in output.splitlines():
        parts = split_nmcli_line(line)

        if len(parts) >= 6:
            ssid = clean_field(parts[0]) or "<hidden>"
            bssid = clean_field(parts[1])
            channel = clean_field(parts[2])
            freq = clean_field(parts[3])
            signal = clean_field(parts[4])
            security = clean_field(":".join(parts[5:])) or "open"

            if ssid not in grouped:
                grouped[ssid] = {
                    "ssid": ssid,
                    "best_signal": signal,
                    "quality": signal_quality(signal),
                    "security": security,
                    "channels": set(),
                    "frequencies": set(),
                    "bands": set(),
                    "bssid_count": 0
                }

            grouped[ssid]["bssid_count"] += 1

            if channel:
                grouped[ssid]["channels"].add(channel)

            if freq:
                clean_freq = freq.replace("MHz", "").strip()
                grouped[ssid]["frequencies"].add(f"{clean_freq} MHz")
                grouped[ssid]["bands"].add(get_band(clean_freq))

            if signal_value_from_text(signal) > signal_value_from_text(grouped[ssid]["best_signal"]):
                grouped[ssid]["best_signal"] = signal
                grouped[ssid]["quality"] = signal_quality(signal)
                grouped[ssid]["security"] = security

    networks = []

    for item in grouped.values():
        item["channels"] = ", ".join(sorted(item["channels"]))
        item["frequency"] = ", ".join(sorted(item["frequencies"]))
        item["band"] = ", ".join(sorted(item["bands"]))

        del item["frequencies"]
        del item["bands"]

        networks.append(item)

    networks.sort(
        key=lambda n: signal_value_from_text(n.get("best_signal", "0")),
        reverse=True
    )

    return networks
