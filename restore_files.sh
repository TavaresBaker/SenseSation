#!/bin/sh

# pfSense Full Web Interface + Init Restore Script
# Safely restores GUI, init system, and other essential files

# Detect pfSense version
VERSION_RAW=$(cat /etc/version | cut -d'-' -f1)
BRANCH="RELENG_$(echo "$VERSION_RAW" | tr '.' '_')"

# Fallback options if main branch fails
BRANCHES="$BRANCH master main"

echo "[*] Detected pfSense version: $VERSION_RAW"
echo "[*] Trying branches: $BRANCHES"

GITHUB_PFSENSE="https://raw.githubusercontent.com/pfsense/pfsense"
GITHUB_FREEBSD="https://raw.githubusercontent.com/freebsd/freebsd-src/releng/14.0"

FAILED_FILES=""

# Backup and Quarantine
cd /root || exit 1

# Assume the master script has already created the SenseSation_Backups directory
BACKUP_DIR="/root/SenseSation_Backups"

# Check if the backup folder exists, if not exit
if [ ! -d "$BACKUP_DIR" ]; then
    echo "[!] Backup directory does not exist. Please ensure the master script has created it."
    exit 1
fi

echo "[*] Moving original files to backup and quarantine..."

# Create a temporary quarantine directory for the current script run
QUARANTINE_DIR="/root/SenseSation_Quarantine"
mkdir -p "$QUARANTINE_DIR"

# Copy for backup
cp -a /usr/local/www "$BACKUP_DIR/"
cp -a /usr/local/etc/rc.d "$BACKUP_DIR/rc.d/"

# Copy for quarantine
cp -a /usr/local/www "$QUARANTINE_DIR/"
cp -a /usr/local/etc/rc.d "$QUARANTINE_DIR/rc.d/"

echo "[+] Files moved to backup directory: $BACKUP_DIR"
echo "[+] Files quarantined in directory: $QUARANTINE_DIR"

# Zip both folders
zip -r "${BACKUP_DIR}/SenseSation_Backups_$(date +%Y%m%d_%H%M%S).zip" "$BACKUP_DIR" > /dev/null
zip -r "${QUARANTINE_DIR}/SenseSation_Quarantine_$(date +%Y%m%d_%H%M%S).zip" "$QUARANTINE_DIR" > /dev/null

echo "[+] Archives created: SenseSation_Backups_$(date +%Y%m%d_%H%M%S).zip and SenseSation_Quarantine_$(date +%Y%m%d_%H%M%S).zip"

# Replace web interface
cd /usr/local || exit 1
fetch "https://codeload.github.com/pfsense/pfsense/zip/refs/heads/${BRANCH}" -o pfsense.zip || exit 1
unzip -oq pfsense.zip
rm -rf www
cp -a "pfsense-${BRANCH}/src/usr/local/www" .
rm -rf pfsense.zip "pfsense-${BRANCH}"
echo "[✔] /usr/local/www replaced."

# Function to download a file with fallback branches
restore_file() {
  LOCAL_PATH="$1"
  RELATIVE_URL="$2"

  for BR in $BRANCHES; do
    URL="${GITHUB_PFSENSE}/${BR}/src${RELATIVE_URL}"
    TMP_FILE="/tmp/$(basename "$LOCAL_PATH")"

    echo "[~] Trying to restore $LOCAL_PATH from $URL"
    curl -fsSL "$URL" -o "$TMP_FILE" && {
      cp "$TMP_FILE" "$LOCAL_PATH"
      echo "[✔] Restored $LOCAL_PATH"
      return 0
    }
  done

  echo "[!] Failed to restore $LOCAL_PATH"
  FAILED_FILES="${FAILED_FILES}\n$LOCAL_PATH"
  return 1
}

# Restore critical system files
restore_file "/etc/rc.initial" "/etc/rc.initial"
restore_file "/etc/inc/config.inc" "/etc/inc/config.inc"
restore_file "/etc/inc/auth.inc" "/etc/inc/auth.inc"

chmod +x /etc/rc.initial 2>/dev/null

# Restore rc.d scripts
echo "[*] Restoring /usr/local/etc/rc.d/* scripts..."
fetch https://codeload.github.com/pfsense/FreeBSD-ports/zip/refs/heads/devel -o ports.zip
unzip -oq ports.zip

if [ -d "FreeBSD-ports-devel" ]; then
  rm -rf /usr/local/etc/rc.d/*
  find FreeBSD-ports-devel -type f -name "*.in" -exec cp {} /usr/local/etc/rc.d/ \;
  echo "[✔] rc.d scripts restored from FreeBSD-ports."
else
  echo "[!] Failed to restore rc.d scripts"
  FAILED_FILES="${FAILED_FILES}\n/usr/local/etc/rc.d/*"
fi

rm -rf ports.zip FreeBSD-ports-devel

# Optional cleanups (does not reset config)
echo "[*] Cleaning up temp PHP sessions..."
rm -rf /var/tmp/php* /tmp/php*

# Restart web GUI and services
echo "[*] Restarting GUI and services..."
pfSsh.php playback svc restart webgui
pfSsh.php playback svc restart all

# Final report
clear
echo "----------------------------------------"
echo "[✔] Restore Completed."
echo "----------------------------------------"
echo "The following files were successfully restored:"
echo "/etc/rc.initial"
echo "/etc/inc/config.inc"
echo "/etc/inc/auth.inc"
echo "/usr/local/www (Web GUI)"
echo "/usr/local/etc/rc.d (Startup Scripts)"
echo "----------------------------------------"

# Display failed files if any
if [ -n "$FAILED_FILES" ]; then
  echo "The following files failed to restore:"
  echo -e "$FAILED_FILES"
else
  echo "[✔] No files failed to restore."
fi
