#!/bin/sh

echo "=== [ pfBlockerNG Installer ] ==="

# Ensure we're running as root
if [ "$(id -u)" -ne 0 ]; then
  echo "[!] This script must be run as root."
  exit 1
fi

# Check if pfSense is online
echo "[*] Checking internet connectivity..."
ping -c 1 1.1.1.1 >/dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "[!] No internet connection. Exiting."
  exit 1
fi

# Update pkg repo
echo "[*] Updating pfSense package repository..."
pkg update

# Check if pfBlockerNG is already installed
echo "[*] Checking for existing pfBlockerNG installation..."
pkg info | grep -i pfblockerng >/dev/null 2>&1
if [ $? -eq 0 ]; then
  echo "[!] pfBlockerNG is already installed."
  exit 0
fi

# Install pfBlockerNG
echo "[*] Installing pfBlockerNG..."
pkg install -y pfSense-pkg-pfBlockerNG

if [ $? -eq 0 ]; then
  echo "[+] pfBlockerNG installed successfully."
  echo "[*] Visit the web GUI to complete setup: Firewall > pfBlockerNG"
else
  echo "[!] Failed to install pfBlockerNG."
  exit 1
fi
