#!/bin/sh

echo "=== [ pfSense Binary Recovery Script - No Reboot ] ==="

# Step 0: Remount root filesystem as read-write
echo "[*] Remounting root as read-write..."
mount -u -w / || echo "[!] Could not remount rootfs, continuing anyway..."

# Step 1: Get pfSense version
PFSENSE_VER=$(cat /etc/version 2>/dev/null)
PFSENSE_MAJOR=$(echo "$PFSENSE_VER" | cut -d'-' -f1)

echo "[*] Detected pfSense version: $PFSENSE_VER"

# Step 2: Setup base URL and tools
BASE_URL="https://files.pfsense.org/mirror/downloads"
BINARIES="pkg git fetch tar sh ls mount cp mv cat"
WORKDIR="/root/.recovery"
mkdir -p "$WORKDIR"

# Step 3: Binary recovery loop
for BIN in $BINARIES; do
  BIN_PATH="/usr/bin/$BIN"
  ALT_PATH="/usr/local/bin/$BIN"

  if [ ! -x "$BIN_PATH" ] && [ ! -x "$ALT_PATH" ]; then
    echo "[!] $BIN missing or not executable. Downloading from pfSense..."

    fetch -o "$WORKDIR/$BIN" "$BASE_URL/tools/$BIN" 2>/dev/null || \
    curl -o "$WORKDIR/$BIN" "$BASE_URL/tools/$BIN" 2>/dev/null || \
    echo "[!] Could not download $BIN."

    if [ -f "$WORKDIR/$BIN" ]; then
      chmod +x "$WORKDIR/$BIN"
      cp "$WORKDIR/$BIN" "/usr/local/bin/$BIN"
      echo "[+] $BIN restored to /usr/local/bin/"
    else
      echo "[!] Failed to recover $BIN. Manual fix may be required."
    fi
  else
    echo "[+] $BIN OK. Skipping."
  fi
done

# Step 4: Refresh shell environment
echo "[*] Refreshing shell environment..."
export PATH="/usr/local/bin:/usr/local/sbin:/bin:/sbin:/usr/bin:/usr/sbin"
hash -r 2>/dev/null

# Step 5: Try to use pkg to restore packages
if command -v pkg >/dev/null 2>&1; then
  echo "[*] pkg is now available. Updating packages..."
  pkg update -f && pkg upgrade -f -y
else
  echo "[!] pkg still not found. Skipping package recovery."
fi

# Step 6: Restart key services instead of rebooting
echo "[*] Restarting key services to apply changes..."
/etc/rc.reload_all
/etc/rc.restart_all

# Optional: Refresh the web UI (if desired)
if [ -x /etc/rc.php_ini_setup ]; then
  /etc/rc.php_ini_setup
fi

echo "[*] Recovery complete. System should be functional without reboot."
