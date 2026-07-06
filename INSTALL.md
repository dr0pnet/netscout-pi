# Installation

## Supported Hardware

- Raspberry Pi 5
- Raspberry Pi OS Lite (64-bit)
- USB Wi-Fi adapter (monitor mode capable)
- Bluetooth adapter (optional)
- ESP32
- GPS module
- Raspberry Pi Touch Display

## System Packages

```bash
sudo apt update
sudo apt install -y \
python3 python3-pip python3-venv \
build-essential cmake git jq \
aircrack-ng iw wireless-tools \
bluez libbluetooth-dev \
libpcap-dev nmap
```

## Python

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Enable Interfaces

```bash
sudo raspi-config
```

Enable:
- I2C (if required)
- Serial UART (GPS if used)
- Bluetooth

## Services

```bash
sudo systemctl enable netscout
sudo systemctl enable netscout-terminal
sudo systemctl enable netscout-kiosk
```
