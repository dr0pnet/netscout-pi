#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

g++ -std=c++17 -O2 -Wall -Wextra esp_watch_wifi.cpp -lpcap -o esp_watch_wifi
chmod +x esp_watch_wifi
chmod +x run_console.sh ble_watch.py 2>/dev/null || true

echo "Built esp_watch_wifi"
