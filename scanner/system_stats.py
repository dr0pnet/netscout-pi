import socket
import shutil
import psutil
import time
import subprocess

def get_lan_ip():
    for iface in ["wlan0", "eth0"]:
        try:
            out = subprocess.check_output(
                ["ip", "-4", "addr", "show", iface],
                text=True
            )
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    return line.split()[1].split("/")[0]
        except:
            pass

    return "Unknown"

def get_system_stats():
    vm = psutil.virtual_memory()
    disk = shutil.disk_usage("/")

    ip = get_lan_ip()

    uptime_seconds = int(time.time() - psutil.boot_time())

    return {
        "cpu_percent": psutil.cpu_percent(interval=1),
        "ram_percent": vm.percent,
        "ram_used_gb": round(vm.used / (1024**3), 2),
        "ram_total_gb": round(vm.total / (1024**3), 2),
        "disk_percent": round((disk.used / disk.total) * 100, 2),
        "disk_used_gb": round(disk.used / (1024**3), 2),
        "disk_total_gb": round(disk.total / (1024**3), 2),
        "hostname": socket.gethostname(),
        "ip_address": ip,
        "uptime_seconds": uptime_seconds
    }
