import subprocess
import os
import signal
import json
import re
import threading
import time
from collections import deque
from pathlib import Path
from datetime import datetime

from flask import Flask, jsonify, send_from_directory, request

from scanner.wifi_scan import scan_wifi, get_connected_wifi
from scanner.device_scan import scan_devices
from scanner.bluetooth_scan import (
    scan_bluetooth,
    start_bluetooth_scan,
    stop_bluetooth_scan,
    bluetooth_status
)
from scanner.db import init_db, log_event, get_recent_events
from scanner.system_stats import get_system_stats
from scanner.adapter_scan import scan_adapters, detect_adapter_changes, set_adapter_mode
from scanner.storage import get_external_storage, get_storage_path
from scanner.device_identity import get_identity_devices

BASE_DIR = Path(__file__).resolve().parent
TOOLS_DIR = BASE_DIR / "bin"
LOGS_DIR = BASE_DIR / "logs"

LAST_SCANS = {
    "devices": None,
    "wifi": None,
    "bluetooth": None
}

DEVICE_SCAN_ENABLED = False
DEVICE_CACHE = []

CONSOLE_BUFFER = deque(maxlen=500)
CONSOLE_LOCK = threading.Lock()

CURRENT_TOOL = {
    "id": None,
    "name": None,
    "command": None,
    "process": None,
    "started": None,
    "status": "idle",
    "exit_code": None,
    "logfile": None
}

app = Flask(__name__, template_folder="web", static_folder="web")


# ----------------------------
# Helpers
# ----------------------------

def load_tools():
    tools = {}

    if not TOOLS_DIR.exists():
        return tools

    for manifest_path in TOOLS_DIR.glob("*/tool.json"):
        tool_dir = manifest_path.parent

        try:
            with open(manifest_path, "r") as f:
                tool = json.load(f)

            tool_id = tool.get("id")

            if not tool_id:
                continue

            tool["tool_dir"] = str(tool_dir)
            tools[tool_id] = tool

        except Exception as e:
            print(f"Failed loading tool {manifest_path}: {e}")

    return tools


def tool_log_path(tool_id):
    LOGS_DIR.mkdir(exist_ok=True)
    return LOGS_DIR / f"{tool_id}.log"


def run_cmd(cmd, timeout=15):
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        return (
            result.stdout.strip(),
            result.stderr.strip(),
            result.returncode
        )

    except Exception as e:
        return "", str(e), 1


def console_log(line):
    line = str(line).rstrip()
    if not line:
        return

    ts = time.strftime("%H:%M:%S")
    formatted = f"[{ts}] {line}"

    with CONSOLE_LOCK:
        CONSOLE_BUFFER.append(formatted)

    logfile = CURRENT_TOOL.get("logfile")
    if logfile:
        try:
            with open(logfile, "a", errors="ignore") as f:
                f.write(formatted + "\n")
        except Exception:
            pass


def current_process_running():
    proc = CURRENT_TOOL.get("process")
    return proc is not None and proc.poll() is None


def reset_current_tool():
    CURRENT_TOOL.update({
        "id": None,
        "name": None,
        "command": None,
        "process": None,
        "started": None,
        "status": "idle",
        "exit_code": None,
        "logfile": None
    })


def stop_current_process(force=False):
    proc = CURRENT_TOOL.get("process")

    if not proc or proc.poll() is not None:
        return True, "No running tool"

    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGTERM)
        console_log("Stop requested.")

        if force:
            time.sleep(1)
            if proc.poll() is None:
                os.killpg(pgid, signal.SIGKILL)
                console_log("Force kill sent.")

        CURRENT_TOOL["status"] = "stopping"
        return True, "Stop requested"

    except Exception as e:
        return False, str(e)


def stream_tool_output(proc, tool_id, tool_name):
    try:
        if proc.stdout:
            for line in proc.stdout:
                line = line.rstrip()
                if not line:
                    continue

                print(f"[{tool_name}] {line}")
                console_log(line)

                try:
                    log_event(tool_id, line)
                except Exception:
                    pass

        exit_code = proc.wait()

    except Exception as e:
        exit_code = proc.poll()
        console_log(f"Console stream error: {e}")

    CURRENT_TOOL["exit_code"] = exit_code
    CURRENT_TOOL["status"] = "stopped"

    console_log(f"Process ended with code: {exit_code}")


def build_kill_patterns(tool_id, tool):
    command = tool.get("command", "")
    tool_name = tool.get("name", tool_id)

    patterns = [tool_id, tool_name]

    if "pwnagotchi_core" in command:
        patterns.append("pwnagotchi_core")

    if "sniffer" in command:
        patterns.append("sniffer")

    return list(dict.fromkeys([p for p in patterns if p]))


# ----------------------------
# Static pages
# ----------------------------

@app.route("/")
def index():
    return send_from_directory("web", "index.html")


@app.route("/style.css")
def style():
    return send_from_directory("web", "style.css")


# ----------------------------
# Core APIs
# ----------------------------

@app.route("/api/status")
def status():
    return jsonify({
        "name": "NetScout Pi",
        "version": "0.1.0",
        "status": "running"
    })


@app.route("/api/system")
def system():
    return jsonify(get_system_stats())


@app.route("/api/summary")
def summary():
    wifi_count = len(scan_wifi())
    device_count = len(scan_devices())
    bluetooth_count = len(scan_bluetooth())

    now = datetime.now()

    LAST_SCANS["wifi"] = now
    LAST_SCANS["devices"] = now
    LAST_SCANS["bluetooth"] = now

    return jsonify({
        "devices": device_count,
        "wifi": wifi_count,
        "bluetooth": bluetooth_count,
    })


# ----------------------------
# VPN APIs
# ----------------------------

@app.route("/api/vpn/status")
def vpn_status():
    out, err, code = run_cmd(["sudo", "wg", "show", "wg0"])

    ip_out, _, _ = run_cmd(["ip", "-4", "addr", "show", "wg0"])

    public_ip = None
    try:
        public_ip = subprocess.check_output(
            ["curl", "-s", "https://api.ipify.org"],
            text=True,
            timeout=5
        ).strip()
    except Exception:
        public_ip = None

    vpn_ip = None
    ip_match = re.search(r"inet\s+([0-9.]+/\d+)", ip_out)
    if ip_match:
        vpn_ip = ip_match.group(1)

    connected = "latest handshake:" in out

    endpoint = "-"
    endpoint_match = re.search(r"endpoint:\s+(.+)", out)
    if endpoint_match:
        endpoint = endpoint_match.group(1).strip()

    handshake = "-"
    handshake_match = re.search(r"latest handshake:\s+(.+)", out)
    if handshake_match:
        handshake = handshake_match.group(1).strip()

    return jsonify({
        "ok": code == 0,
        "connected": connected,
        "interface": "wg0",
        "vpn_ip": vpn_ip,
        "public_ip": public_ip,
        "endpoint": endpoint,
        "handshake": handshake
    })


@app.route("/api/vpn/connect", methods=["POST"])
def vpn_connect():
    out, err, code = run_cmd(["sudo", "wg-quick", "up", "wg0"])
    return jsonify({
        "ok": code == 0 or "already exists" in err,
        "output": out,
        "error": err
    })


@app.route("/api/vpn/disconnect", methods=["POST"])
def vpn_disconnect():
    out, err, code = run_cmd(["sudo", "wg-quick", "down", "wg0"])
    return jsonify({
        "ok": code == 0,
        "output": out,
        "error": err
    })


@app.route("/api/vpn/restart", methods=["POST"])
def vpn_restart():
    down_out, down_err, _ = run_cmd(["sudo", "wg-quick", "down", "wg0"])
    up_out, up_err, up_code = run_cmd(["sudo", "wg-quick", "up", "wg0"])

    return jsonify({
        "ok": up_code == 0,
        "output": down_out + "\n" + up_out,
        "error": down_err + "\n" + up_err
    })


# ----------------------------
# Wi-Fi APIs
# ----------------------------

@app.route("/api/wifi/connected")
def wifi_connected():
    return jsonify(get_connected_wifi())


@app.route("/api/wifi")
def wifi():
    results = scan_wifi()
    LAST_SCANS["wifi"] = datetime.now()

    log_event("wifi_scan", f"Found {len(results)} Wi-Fi networks")
    return jsonify(results)


@app.route("/api/speedtest")
def speedtest():
    try:
        output = subprocess.check_output(
            ["speedtest-cli", "--simple"],
            text=True,
            timeout=90
        )

        ping = ""
        download = ""
        upload = ""

        for line in output.splitlines():
            if line.startswith("Ping"):
                ping = line.split(":")[1].strip()

            elif line.startswith("Download"):
                download = line.split(":")[1].strip()

            elif line.startswith("Upload"):
                upload = line.split(":")[1].strip()

        return jsonify({
            "ok": True,
            "ping": ping,
            "download": download,
            "upload": upload
        })

    except Exception as e:
        return jsonify({
            "ok": False,
            "error": str(e)
        })


@app.route("/api/channel_usage")
def channel_usage():
    networks = scan_wifi()

    channels_24 = {}
    channels_5 = {}

    for net in networks:
        channel_text = str(net.get("channels", ""))

        for ch in channel_text.split(","):
            ch = ch.strip()

            if not ch:
                continue

            try:
                channel_num = int(ch)
            except Exception:
                continue

            count = int(net.get("bssid_count", 1))

            if 1 <= channel_num <= 14:
                channels_24[ch] = channels_24.get(ch, 0) + count
            else:
                channels_5[ch] = channels_5.get(ch, 0) + count

    recommended_24 = None
    recommended_5 = None

    if channels_24:
        recommended_24 = min(channels_24, key=channels_24.get)

    if channels_5:
        recommended_5 = min(channels_5, key=channels_5.get)

    return jsonify({
        "channels_24": channels_24,
        "channels_5": channels_5,
        "recommended_24": recommended_24,
        "recommended_5": recommended_5
    })


# ----------------------------
# Device APIs
# ----------------------------

@app.route("/api/devices")
def devices():
    global DEVICE_CACHE

    if DEVICE_SCAN_ENABLED:
        DEVICE_CACHE = get_identity_devices()
        LAST_SCANS["devices"] = datetime.now()
        log_event("device_scan", f"Found {len(DEVICE_CACHE)} local devices")

    return jsonify(DEVICE_CACHE)


@app.route("/api/devices/start", methods=["POST"])
def start_device_scan():
    global DEVICE_SCAN_ENABLED

    DEVICE_SCAN_ENABLED = True
    log_event("device_scan", "Device scanning started")

    return jsonify({"ok": True, "scanning": True})


@app.route("/api/devices/stop", methods=["POST"])
def stop_device_scan():
    global DEVICE_SCAN_ENABLED

    DEVICE_SCAN_ENABLED = False
    log_event("device_scan", "Device scanning stopped")

    return jsonify({"ok": True, "scanning": False})


@app.route("/api/devices/scan_status")
def device_scan_status():
    return jsonify({
        "scanning": DEVICE_SCAN_ENABLED,
        "cached_devices": len(DEVICE_CACHE)
    })


# ----------------------------
# Bluetooth APIs
# ----------------------------

@app.route("/api/bluetooth")
def bluetooth():
    results = scan_bluetooth()
    LAST_SCANS["bluetooth"] = datetime.now()

    log_event("bluetooth_scan", f"Found {len(results)} Bluetooth devices")

    return jsonify(results)


@app.route("/api/bluetooth/start", methods=["POST"])
def bluetooth_start():
    result = start_bluetooth_scan()
    log_event("bluetooth_scan", "Bluetooth scanning started")

    return jsonify(result)


@app.route("/api/bluetooth/stop", methods=["POST"])
def bluetooth_stop():
    result = stop_bluetooth_scan()
    log_event("bluetooth_scan", "Bluetooth scanning stopped")

    return jsonify(result)


@app.route("/api/bluetooth/status")
def bluetooth_scan_status():
    return jsonify(bluetooth_status())


# ----------------------------
# Events / adapters / storage
# ----------------------------

@app.route("/api/events")
def events():
    return jsonify(get_recent_events())


@app.route("/api/scan_status")
def scan_status():
    def age(scan_time):
        if not scan_time:
            return "Never"

        seconds = int((datetime.now() - scan_time).total_seconds())
        return f"{seconds}s ago"

    return jsonify({
        "devices": age(LAST_SCANS["devices"]),
        "wifi": age(LAST_SCANS["wifi"]),
        "bluetooth": age(LAST_SCANS["bluetooth"])
    })


@app.route("/api/adapters")
def adapters():
    return jsonify(scan_adapters())


@app.route("/api/adapter_changes")
def adapter_changes():
    changes = detect_adapter_changes()

    for iface in changes["added"]:
        log_event("adapter_connected", f"Wireless adapter connected: {iface}")

    for iface in changes["removed"]:
        log_event("adapter_disconnected", f"Wireless adapter disconnected: {iface}")

    return jsonify(changes)


@app.route("/api/adapters/sdr")
def adapters_sdr():
    try:
        proc = subprocess.run(
            ["rtl_test", "-t"],
            capture_output=True,
            text=True,
            timeout=8
        )

        output = (proc.stdout or "") + "\n" + (proc.stderr or "")

    except FileNotFoundError:
        return jsonify({
            "available": False,
            "status": "tools_missing",
            "message": "rtl-sdr tools are not installed.",
            "devices": []
        })

    except subprocess.TimeoutExpired as e:
        output = ""

        if e.stdout:
            output += e.stdout if isinstance(e.stdout, str) else e.stdout.decode(errors="ignore")

        if e.stderr:
            output += e.stderr if isinstance(e.stderr, str) else e.stderr.decode(errors="ignore")

    except Exception as e:
        return jsonify({
            "available": False,
            "status": "error",
            "message": str(e),
            "devices": []
        })

    if "No supported devices found" in output:
        return jsonify({
            "available": False,
            "status": "not_found",
            "message": "No RTL-SDR device detected.",
            "devices": []
        })

    devices = []

    pattern = re.compile(
        r"^\s*(\d+):\s*([^,\n]+),\s*([^,\n]+),\s*SN:\s*([^\s]+)",
        re.MULTILINE
    )

    for match in pattern.finditer(output):
        devices.append({
            "index": match.group(1).strip(),
            "vendor": match.group(2).strip(),
            "model": match.group(3).strip(),
            "serial": match.group(4).strip(),
            "type": "RTL-SDR",
            "status": "ready"
        })

    tuner = "Unknown"

    tuner_match = re.search(r"Found\s+(.+?)\s+tuner", output)
    if tuner_match:
        tuner = tuner_match.group(1).strip()

    if not devices and "Found" in output and "device" in output:
        devices.append({
            "index": "0",
            "vendor": "Realtek",
            "model": "RTL2832U / RTL2838",
            "serial": "unknown",
            "type": "RTL-SDR",
            "status": "ready"
        })

    found_device = len(devices) > 0

    return jsonify({
        "available": found_device,
        "status": "ready" if found_device else "unknown",
        "message": "RTL-SDR detected and ready." if found_device else "SDR check completed, but no device was parsed.",
        "tuner": tuner,
        "devices": devices
    })


@app.route("/api/adapters/mode", methods=["POST"])
def adapter_mode():
    data = request.get_json() or {}

    interface = data.get("interface")
    mode = data.get("mode")

    result = set_adapter_mode(interface, mode)

    if result.get("ok"):
        log_event("adapter_mode_changed", f"{interface} set to {mode}")

    return jsonify(result)


@app.route("/api/storage")
def storage_status():
    drives = get_external_storage()
    active_path = get_storage_path()

    return jsonify({
        "external_drives": drives,
        "active_storage_path": active_path
    })


# ----------------------------
# Shared Tool Console APIs
# ----------------------------

@app.route("/api/tools")
def list_tools():
    result = []
    tools = load_tools()

    for tool_id, tool in tools.items():
        running = current_process_running() and CURRENT_TOOL.get("id") == tool_id

        item = dict(tool)
        item["id"] = tool_id
        item["name"] = tool.get("name", tool_id)
        item["icon"] = tool.get("icon", "")
        item["type"] = tool.get("type", "console")
        item["running"] = running
        item["requires_interface"] = tool.get("requires_interface", "")
        item["requires_monitor"] = tool.get("requires_monitor", False)
        item["auto_start"] = tool.get("auto_start", False)

        result.append(item)

    return jsonify(result)


@app.route("/api/console")
def api_console():
    running = current_process_running()

    if not running and CURRENT_TOOL.get("process") is not None and CURRENT_TOOL.get("status") == "running":
        CURRENT_TOOL["status"] = "stopped"

    with CONSOLE_LOCK:
        lines = list(CONSOLE_BUFFER)

    return jsonify({
        "ok": True,
        "tool_id": CURRENT_TOOL.get("id"),
        "tool_name": CURRENT_TOOL.get("name"),
        "command": CURRENT_TOOL.get("command"),
        "status": "running" if running else CURRENT_TOOL.get("status", "idle"),
        "started": CURRENT_TOOL.get("started"),
        "exit_code": CURRENT_TOOL.get("exit_code"),
        "lines": lines
    })


@app.route("/api/console/clear", methods=["POST"])
def api_console_clear():
    with CONSOLE_LOCK:
        CONSOLE_BUFFER.clear()

    console_log("Console cleared.")
    return jsonify({"ok": True})


@app.route("/api/tools/<tool_id>/start", methods=["POST"])
def start_tool(tool_id):
    tools = load_tools()
    tool = tools.get(tool_id)

    if not tool:
        return jsonify({
            "ok": False,
            "status": "error",
            "message": "Unknown tool",
            "error": "Unknown tool"
        }), 404

    command = tool.get("command")

    if not command:
        return jsonify({
            "ok": False,
            "status": "error",
            "message": "No command defined in tool.json",
            "error": "No command defined in tool.json"
        }), 400

    # Fresh start: stop any currently running tool first.
    if current_process_running():
        old_name = CURRENT_TOOL.get("name") or "previous tool"
        ok, msg = stop_current_process(force=True)
        if not ok:
            return jsonify({
                "ok": False,
                "status": "error",
                "message": msg,
                "error": msg
            }), 500

        console_log(f"Stopped {old_name}.")
        time.sleep(0.5)

    logfile = tool_log_path(tool_id)

    with CONSOLE_LOCK:
        CONSOLE_BUFFER.clear()

    try:
        with open(logfile, "w", errors="ignore") as f:
            f.write(f"[NetScout] Starting {tool.get('name', tool_id)}...\n")
            f.write(f"[NetScout] Command: {command}\n\n")
    except Exception:
        pass

    tool_name = tool.get("name", tool_id)

    CURRENT_TOOL.update({
        "id": tool_id,
        "name": tool_name,
        "command": command,
        "process": None,
        "started": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status": "starting",
        "exit_code": None,
        "logfile": str(logfile)
    })

    console_log(f"Starting {tool_name}...")
    console_log(f"Command: {command}")

    try:
        proc = subprocess.Popen(
            f"script -q -f -c {json.dumps(command)} /dev/null",
            cwd=str(BASE_DIR),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            universal_newlines=True,
            preexec_fn=os.setsid
    )

        CURRENT_TOOL["process"] = proc
        CURRENT_TOOL["status"] = "running"

        threading.Thread(
            target=stream_tool_output,
            args=(proc, tool_id, tool_name),
            daemon=True
        ).start()

        log_event(tool_id, f"{tool_name} started")

        return jsonify({
            "ok": True,
            "status": "ok",
            "message": f"{tool_name} started",
            "redirect": "/console.html"
        })

    except Exception as e:
        CURRENT_TOOL["status"] = "error"
        console_log(f"Failed to start tool: {e}")

        return jsonify({
            "ok": False,
            "status": "error",
            "message": str(e),
            "error": str(e)
        }), 500


@app.route("/api/tools/stop", methods=["POST"])
def stop_active_tool():
    tool_id = CURRENT_TOOL.get("id")
    tool_name = CURRENT_TOOL.get("name") or "tool"

    ok, msg = stop_current_process(force=False)

    if ok:
        try:
            if tool_id:
                log_event(tool_id, f"{tool_name} stop requested")
        except Exception:
            pass

        return jsonify({
            "ok": True,
            "status": "ok",
            "message": msg
        })

    return jsonify({
        "ok": False,
        "status": "error",
        "message": msg,
        "error": msg
    }), 500


@app.route("/api/tools/<tool_id>/stop", methods=["POST"])
def stop_tool(tool_id):
    tools = load_tools()
    tool = tools.get(tool_id)

    if not tool:
        return jsonify({
            "ok": False,
            "status": "error",
            "message": "Unknown tool",
            "error": "Unknown tool"
        }), 404

    if CURRENT_TOOL.get("id") != tool_id:
        return jsonify({
            "ok": True,
            "status": "ok",
            "message": "Tool is not the active console process"
        })

    tool_name = tool.get("name", tool_id)

    ok, msg = stop_current_process(force=True)

    # Extra cleanup for stubborn child processes from compiled tools.
    for pattern in build_kill_patterns(tool_id, tool):
        subprocess.run(
            ["sudo", "pkill", "-TERM", "-f", pattern],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    time.sleep(0.5)

    for pattern in build_kill_patterns(tool_id, tool):
        subprocess.run(
            ["sudo", "pkill", "-9", "-f", pattern],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    CURRENT_TOOL["status"] = "stopped"
    console_log(f"{tool_name} stopped.")

    try:
        log_event(tool_id, f"{tool_name} stopped")
    except Exception:
        pass

    return jsonify({
        "ok": ok,
        "status": "ok" if ok else "error",
        "message": f"{tool_name} stopped" if ok else msg
    })


@app.route("/api/tool_log/<tool_id>")
def tool_log(tool_id):
    logfile = tool_log_path(tool_id)

    if not logfile.exists():
        return ""

    with open(logfile, "r", errors="ignore") as f:
        lines = f.readlines()

    return "".join(lines[-500:])


# ----------------------------
# Terminal keyboard API
# ----------------------------

@app.post("/api/terminal/key")
def terminal_key():
    data = request.get_json(force=True)
    key = data.get("key", "")

    allowed_special = {
        "Enter": "Enter",
        "Backspace": "BSpace",
        "Space": "Space",
        "Tab": "Tab",
        "CtrlC": "C-c",
        "Up": "Up",
        "Down": "Down",
        "Left": "Left",
        "Right": "Right",
    }

    if key in allowed_special:
        tmux_key = allowed_special[key]
        subprocess.run(["tmux", "send-keys", "-t", "netscout-term", tmux_key])
        return jsonify({"ok": True})

    if len(key) == 1:
        subprocess.run(["tmux", "send-keys", "-t", "netscout-term", key])
        return jsonify({"ok": True})

    return jsonify({"error": "invalid key"}), 400


# ----------------------------
# Power / service controls
# ----------------------------

@app.route("/api/restart_netscout", methods=["POST"])
def restart_netscout():
    try:
        subprocess.Popen(["sudo", "systemctl", "restart", "netscout"])

        return jsonify({
            "ok": True,
            "message": "NetScout restarting..."
        })

    except Exception as e:
        return jsonify({
            "ok": False,
            "message": str(e)
        }), 500


@app.route("/api/reboot", methods=["POST"])
def reboot_pi():
    try:
        subprocess.Popen(["sudo", "reboot"])

        return jsonify({
            "ok": True,
            "message": "Rebooting device..."
        })

    except Exception as e:
        return jsonify({
            "ok": False,
            "message": str(e)
        }), 500


@app.route("/api/shutdown", methods=["POST"])
def shutdown_pi():
    try:
        subprocess.Popen(["sudo", "shutdown", "-h", "now"])

        return jsonify({
            "ok": True,
            "message": "Shutting down device..."
        })

    except Exception as e:
        return jsonify({
            "ok": False,
            "message": str(e)
        }), 500


@app.route("/<path:filename>")
def static_pages(filename):
    return send_from_directory("web", filename)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5055)
