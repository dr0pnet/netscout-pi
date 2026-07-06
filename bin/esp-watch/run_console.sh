#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
WIFI_IFACE="${1:-wlan1}"
BLE_IFACE="${2:-hci0}"
CHANNELS="${3:-1,2,3,4,5,6,7,8,9,10,11,12,13}"
HOP_MS="${4:-350}"
DEDUPE_SEC="${5:-1}"

WIFI_BIN="$DIR/esp_watch_wifi"
BLE_BIN="$DIR/ble_watch.py"

if [[ ! -x "$WIFI_BIN" ]]; then
  echo "ERROR: esp_watch_wifi is missing or not executable at: $WIFI_BIN"
  echo "Run: cd $DIR && ./build.sh"
  exit 1
fi

cleanup() {
  [[ -n "${WIFI_PID:-}" ]] && kill "$WIFI_PID" 2>/dev/null || true
  [[ -n "${BLE_PID:-}" ]] && kill "$BLE_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "NetSc0ut ESP Watch v2 / Marauder Watch console"
echo "Passive-only detection. No packets are transmitted by this tool."
echo "Wi-Fi iface: $WIFI_IFACE"
echo "BLE iface: $BLE_IFACE"
echo "Channels: $CHANNELS | Hop: ${HOP_MS}ms | Dedupe: ${DEDUPE_SEC}s"
echo "Aggressive triggers enabled: passive AP/probe/action, ESP-like identity, probe floods, beacon spam, deauth/disassoc bursts."
echo

# Best-effort monitor mode. If NetworkManager is fighting it, tcpdump/iw tests will show that separately.
sudo ip link set "$WIFI_IFACE" down 2>/dev/null || true
sudo iw dev "$WIFI_IFACE" set type monitor 2>/dev/null || true
sudo ip link set "$WIFI_IFACE" up 2>/dev/null || true
FIRST_CH="${CHANNELS%%,*}"
sudo iw dev "$WIFI_IFACE" set channel "$FIRST_CH" HT20 2>/dev/null || true

"$WIFI_BIN" "$WIFI_IFACE" "$CHANNELS" "$HOP_MS" "$DEDUPE_SEC" \
  --window-sec 5 \
  --probe-src-threshold 3 \
  --probe-total-threshold 8 \
  --deauth-threshold 2 \
  --beacon-spam-threshold 4 &
WIFI_PID=$!

if [[ "$BLE_IFACE" != "none" && -x "$BLE_BIN" ]]; then
  python3 "$BLE_BIN" "$BLE_IFACE" --all --dedupe 3 &
  BLE_PID=$!
fi

wait "$WIFI_PID"
