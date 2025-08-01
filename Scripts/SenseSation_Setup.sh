#!/bin/sh

# region (Directories)

# Inform of directory creation
create_directories() {
    echo "[*] Creating directories..."
    dirs="/root/SenseSation/Scripts /root/SenseSation/Backups /root/SenseSation/Quarantine /root/SenseSation/Supporting_Files"
    for d in $dirs; do
        mkdir -p "$d" || failed_items="${failed_items}DIR:$d\n"
    done
}
# Create the directories
mkdir -p /root/SenseSation/Scripts /root/SenseSation/Backups /root/SenseSation/Quarantine /root/SenseSation/Supporting_Files

# endregion

# region (Backups)

# Backup original supporting files
if [ -f /etc/rc.initial ]; then
    mv /etc/rc.initial /root/SenseSation/Backups/
fi

if [ -f /etc/rc.banner ]; then
    mv /etc/rc.banner /root/SenseSation/Backups/
fi
# endregion

# region (rc.initial and rc.banner)
setup_supporting_files() {
    echo "[*] Handling supporting files..."

    # Backup originals if they exist
    [ -f /etc/rc.initial ] && mv /etc/rc.initial /root/SenseSation/Backups/ || true
    [ -f /etc/rc.banner ] && mv /etc/rc.banner /root/SenseSation/Backups/ || true

    # Make them executable
    for file in /root/SenseSation/Supporting_Files/rc.initial /root/SenseSation/Supporting_Files/rc.banner; do
        chmod +x "$file" 2>/dev/null || failed_items="${failed_items}SUPPORT_CHMOD:$file\n"
    done

    # Copy to /etc
    cp /root/SenseSation/Supporting_Files/rc.initial /etc/ 2>/dev/null || failed_items="${failed_items}SUPPORT_COPY:/etc/rc.initial\n"
    cp /root/SenseSation/Supporting_Files/rc.banner /etc/ 2>/dev/null || failed_items="${failed_items}SUPPORT_COPY:/etc/rc.banner\n"
}

#region

# Deploy rc.initial
cat << 'EOF' > /root/SenseSation/Supporting_Files/rc.initial
#!/bin/sh

# SenseSation rc.initial


while : ; do

if [ -f /tmp/ttybug ]; then
	/bin/rm /tmp/ttybug
	exit && exit && logout
fi

/etc/rc.banner

# Read product_name from $g, defaults to pfSense
if [ -f /etc/product_name ]; then
	product_name=$(/bin/cat /etc/product_name)
else
	product_name=$(/usr/local/sbin/read_global_var product_name pfSense)
fi

# Read product_label from $g, defaults to pfSense
if [ -f /etc/product_label ]; then
	product_label=$(/bin/cat /etc/product_label)
else
	product_label=$(/usr/local/sbin/read_global_var product_label pfSense)
fi

# Check to see if SSH is running.
if /bin/pgrep -qaF /var/run/sshd.pid sshd 2>/dev/null; then
	sshd_option='Disable'
else
	sshd_option='Enable'
fi

echo ""
echo ""

# ASCII Art
echo -e "\033[1;34m     _____                      \033[1;31m_____       __  _           "
echo -e "\033[1;34m    / ___/___  ____  ________  \033[1;31m/ ___/____ _/ /_(_)___  ____ "
echo -e "\033[1;34m    \\__ \\/ _ \\/ __ \\/ ___/ _ \\ \033[1;31m\\__ \\/ __ \`/ __/ / __ \\/ __ \\"
echo -e "\033[1;34m   ___/ /  __/ / / (__  /  __ \033[1;31m___/ / /_/ / /_/ / /_/ / / / /"
echo -e "\033[1;34m  /____/\\___/_/ /_/____/\\___/\033[1;31m/_____/\__,/\\__/_/\\____/_/ /_/"
echo -e "\033[0m"

echo ""
echo ""
echo " 0) Exit                                1) Shell"
echo " 2) Restore Binaries                    3) Restore Files"
echo " 4) Find Added Users                    5) Find Points of Entry"
echo " 6) Find Webhooks                       7) Nuke SSH"
echo " 8) Find Suspicious Processes           9) Deploy PFBlocker"
echo ""
echo ""

read -p "Enter a number: " opmode
echo

case ${opmode} in
  '')
    if [ -n "$SSH_CONNECTION" ]; then
        exit
    else
        /bin/kill $PPID ; exit
    fi
    ;;

  0)
    echo "Exiting to shell..."
    /root/SenseSation/Scripts/stop_script.sh
    ;;

  1)
    exec /bin/tcsh -l
    ;;

  2)
    /root/SenseSation/Scripts/restore_binaries.sh
    echo "Press ENTER to return to the menu..."
    read dummy
    ;;

  3)
    /root/SenseSation/Scripts/restore_files.sh
    echo "Press ENTER to return to the menu..."
    read dummy
    ;;

  4)
    echo "Launching interactive shell to find added users..."
    /root/SenseSation/Scripts/delete_users.sh
    ;;

  5)
    /root/SenseSation/Scripts/shell_hunter.sh
    ;;

  6)
    /root/SenseSation/Scripts/find_webhooks.sh
    ;;

  7)
    echo "Launching shell to nuke SSH..."
    /root/SenseSation/Scripts/nuke_ssh.sh
    ;;

  8)
    echo "Launching shell to investigate processes..."
    /root/SenseSation/Scripts/find_suspecious_processes.sh
    ;;

  9)
    /root/SenseSation/Scripts/deploy_pfblocker.sh
    echo "Press ENTER to return to the menu..."
    read dummy
    ;;

  100)
    protocol=$(/usr/local/sbin/read_xml_tag.sh string system/webgui/protocol)
    port=$(/usr/local/sbin/read_xml_tag.sh string system/webgui/port)
    [ -z "$protocol" ] && protocol='http'
    [ -z "$port" ] && case $protocol in https) port=443;; *) port=80;; esac
    links "${protocol}://localhost:${port}"
    ;;

  *)
    echo "Invalid option."
    echo "Press ENTER to continue..."
    read dummy
    ;;
esac

done

EOF

#endregion

#region

# Deploy rc.banner
cat << 'EOF' > /root/SenseSation/Supporting_Files/rc.banner
#!/usr/local/bin/php-cgi -f
<?php
/*
 * rc.banner - Sensation Edition
 * Custom system banner for the Sensation cleanup script
 * (c) 2025 John Doe / Apogee Networks
 */

require_once("config.inc");
require_once("gwlb.inc");
require_once("interfaces.inc");

$hostname = config_get_path('system/hostname');
$machine = trim(`uname -m`);
$platform = system_identify_specific_platform();

$sensation_version_file = "/etc/sensation_version";
$sensation_version = "v1.0.0";
if (file_exists($sensation_version_file)) {
	$sensation_version = trim(file_get_contents($sensation_version_file));
}

// Print Sensation welcome banner
printf("\n*** Welcome to Sensation %s (%s) on %s ***\n", $sensation_version, $machine, $hostname);
if (isset($platform['descr'])) {
	printf("Platform: %s\n", $platform['descr']);
}
printf("\n");

// Get interfaces
$iflist = get_configured_interface_with_descr(true);

// Calculate widths for alignment
$realif_width = 1;
$tobanner_width = 1;
foreach ($iflist as $ifname => $friendly) {
	$realif = get_real_interface($ifname);
	$realif_length = strlen($realif);
	if ($realif_length > $realif_width) {
		$realif_width = $realif_length;
	}
	$tobanner = "{$friendly} ({$ifname})";
	$tobanner_length = strlen($tobanner);
	if ($tobanner_length > $tobanner_width) {
		$tobanner_width = $tobanner_length;
	}
}
$v6line_width = $realif_width + $tobanner_width + 9;

// Print interface summaries
foreach ($iflist as $ifname => $friendly) {
	$ifconf = config_get_path("interfaces/{$ifname}");

	$class = match($ifconf['ipaddr'] ?? '') {
		'dhcp' => '/DHCP4',
		'pppoe' => '/PPPoE',
		'pptp' => '/PPTP',
		'l2tp' => '/L2TP',
		default => '',
	};

	$class6 = match($ifconf['ipaddrv6'] ?? '') {
		'dhcp6' => '/DHCP6',
		'slaac' => '/SLAAC',
		'6rd' => '/6RD',
		'6to4' => '/6to4',
		'track6' => '/t6',
		default => '',
	};

	$ipaddr = get_interface_ip($ifname);
	$subnet = get_interface_subnet($ifname);
	$ipaddr6 = get_interface_ipv6($ifname);
	$subnet6 = get_interface_subnetv6($ifname);
	$realif = get_real_interface($ifname);
	$tobanner = "{$friendly} ({$ifname})";

	printf(" %-{$tobanner_width}s -> \%-{$realif_width}s\ -> ",
		$tobanner,
		$realif
	);
	$v6first = false;
	if (!empty($ipaddr) && !empty($subnet)) {
		printf("v4%s: %s/%s", $class, $ipaddr, $subnet);
	} else {
		$v6first = true;
	}
	if (!empty($ipaddr6) && !empty($subnet6)) {
		if (!$v6first) {
			printf("\n%s", str_repeat(" ", $v6line_width));
		}
		printf("v6%s: %s/%s\033[0m", $class6, $ipaddr6, $subnet6);
	}
	printf("\n");
}
printf("\n");
?>

EOF

#endregion

# endregion

# region (Scripts)
# region (Script to stop SenseSation)
cat << 'EOF' > /root/SenseSation/Scripts/stop_script.sh
#!/bin/sh

# Script to restore the original rc.initial and rc.banner files

echo "Restoring original files..."

# Check if backup files exist before restoring
if [ -f /root/SenseSation/Backups/rc.initial ]; then
    echo "Restoring rc.initial..."
    cp /root/SenseSation/Backups/rc.initial /etc/rc.initial
else
    echo "Backup for rc.initial not found!"
fi

if [ -f /root/SenseSation/Backups/rc.banner ]; then
    echo "Restoring rc.banner..."
    cp /root/SenseSation/Backups/rc.banner /etc/rc.banner
else
    echo "Backup for rc.banner not found!"
fi

echo "Restoration complete."

EOF

# endregion

# region (Script to restore Bianries)
cat << 'EOF' > /root/SenseSation/Scripts/restore_binaries.sh
#!/bin/sh

echo "=== [ Binary Recovery ] ==="

# Define directories
BASE_DIR="/SenseSation"
QUARANTINE_DIR="$BASE_DIR/Quarantine"
mkdir -p "$QUARANTINE_DIR"

# Remount root as read-write
echo "[*] Remounting root filesystem as read-write..."
mount -u -w / || echo "[!] Warning: Could not remount rootfs writable, continuing..."

# Get pfSense version
PFSENSE_VER=$(cat /etc/version 2>/dev/null)
echo "[*] Detected pfSense version: $PFSENSE_VER"

# Setup
BASE_URL="https://files.pfsense.org/mirror/downloads"
BINARIES="pkg git fetch tar sh ls mount cp mv cat"
WORKDIR="/root/.recovery"
mkdir -p "$WORKDIR"
NOW=$(date +%Y%m%d_%H%M%S)

failed_bins=""

for BIN in $BINARIES; do
  BIN_PATH="/usr/bin/$BIN"
  ALT_PATH="/usr/local/bin/$BIN"

  if [ -x "$BIN_PATH" ]; then
    continue
  elif [ -x "$ALT_PATH" ]; then
    continue
  fi

  echo "[!] $BIN missing. Attempting download..."

  fetch -o "$WORKDIR/$BIN" "$BASE_URL/tools/$BIN" 2>/dev/null || \
  curl -o "$WORKDIR/$BIN" "$BASE_URL/tools/$BIN" 2>/dev/null

  if [ ! -f "$WORKDIR/$BIN" ]; then
    echo "[!] Failed to download $BIN."
    failed_bins="$failed_bins $BIN"
    continue
  fi

  chmod +x "$WORKDIR/$BIN"
  RESTORE_PATH="/usr/local/bin/$BIN"

  if [ -f "$RESTORE_PATH" ]; then
    QUAR_NAME="quarantine_${BIN}_usr_local_bin_${NOW}.tar.gz"
    tar -czf "$QUARANTINE_DIR/$QUAR_NAME" -C /usr/local/bin "$BIN"
    echo "[*] Quarantined existing $BIN"
  fi

  cp "$WORKDIR/$BIN" "$RESTORE_PATH" || {
    echo "[!] Failed to restore $BIN."
    failed_bins="$failed_bins $BIN"
  }

  echo "[+] Restored $BIN"
done

# Refresh shell environment
export PATH="/usr/local/bin:/usr/local/sbin:/bin:/sbin:/usr/bin:/usr/sbin"
hash -r 2>/dev/null

# Attempt pkg update/upgrade if available
if command -v pkg >/dev/null 2>&1; then
  echo "[*] Updating packages with pkg..."
  pkg update -f && pkg upgrade -f -y
else
  echo "[!] pkg not found. Skipping package update."
fi

# Restart key services without reboot
/etc/rc.reload_all
/etc/rc.restart_all

# Refresh web UI if needed
if [ -x /etc/rc.php_ini_setup ]; then
  /etc/rc.php_ini_setup
fi

if [ -z "$failed_bins" ]; then
  echo "[*] Recovery complete, all binaries restored."
else
  echo "[!] Recovery complete, but failed on:$failed_bins"
fi


EOF

# endregion

# region (Script to restore Web GUI and startup scripts)
cat << 'EOF' > /root/SenseSation/Scripts/restore_files.sh
#!/bin/sh

# pfSense Full Web Interface + Init Restore Script
# Safely restores GUI, init system, and other essential files

# Detect pfSense version
VERSION_RAW=$(cut -d'-' -f1 /etc/version)
BRANCH="RELENG_$(echo "$VERSION_RAW" | tr '.' '_')"
BRANCHES="$BRANCH master main"

echo "[*] Detected pfSense version: $VERSION_RAW"
echo "[*] Trying branches: $BRANCHES"

GITHUB_PFSENSE="https://raw.githubusercontent.com/pfsense/pfsense"
GITHUB_FREEBSD="https://raw.githubusercontent.com/freebsd/freebsd-src/releng/14.0"
FAILED_FILES=""

# Paths
BACKUP_DIR="/root/SenseSation/Backups"
QUARANTINE_DIR="/root/SenseSation/Quarantine"
NOW=$(date +%Y%m%d_%H%M%S)

# Ensure backup directory exists
[ ! -d "$BACKUP_DIR" ] && {
  echo "[!] Backup directory does not exist. Please ensure it's in place."
  exit 1
}

echo "[*] Backing up and quarantining files..."

# Backup
cp -a /usr/local/www "$BACKUP_DIR/www_$NOW"
cp -a /usr/local/etc/rc.d "$BACKUP_DIR/rc.d_$NOW"

# Quarantine
cp -a /usr/local/www "$QUARANTINE_DIR/www_$NOW"
cp -a /usr/local/etc/rc.d "$QUARANTINE_DIR/rc.d_$NOW"

# Archive
cd "$BACKUP_DIR" && zip -r "Backups_$NOW.zip" "www_$NOW" "rc.d_$NOW" > /dev/null
cd "$QUARANTINE_DIR" && zip -r "Quarantine_$NOW.zip" "www_$NOW" "rc.d_$NOW" > /dev/null

echo "[+] Backup and quarantine complete."

# Replace web interface
cd /usr/local || exit 1
fetch "https://codeload.github.com/pfsense/pfsense/zip/refs/heads/${BRANCH}" -o pfsense.zip || exit 1
unzip -oq pfsense.zip
rm -rf www
cp -a "pfsense-${BRANCH}/src/usr/local/www" .
rm -rf pfsense.zip "pfsense-${BRANCH}"
echo "[✔] /usr/local/www replaced."

# Restore system files
restore_file() {
  LOCAL_PATH="$1"
  RELATIVE_URL="$2"

  for BR in $BRANCHES; do
    URL="${GITHUB_PFSENSE}/${BR}/src${RELATIVE_URL}"
    TMP="/tmp/$(basename "$LOCAL_PATH")"
    echo "[~] Trying: $URL"
    curl -fsSL "$URL" -o "$TMP" && {
      cp "$TMP" "$LOCAL_PATH"
      echo "[✔] Restored $LOCAL_PATH"
      return 0
    }
  done

  echo "[!] Failed to restore $LOCAL_PATH"
  FAILED_FILES="${FAILED_FILES}\n$LOCAL_PATH"
  return 1
}

restore_file "/etc/rc.initial" "/etc/rc.initial"
restore_file "/etc/inc/config.inc" "/etc/inc/config.inc"
restore_file "/etc/inc/auth.inc" "/etc/inc/auth.inc"
chmod +x /etc/rc.initial 2>/dev/null

# Restore rc.d scripts
echo "[*] Restoring /usr/local/etc/rc.d scripts..."
fetch https://codeload.github.com/pfsense/FreeBSD-ports/zip/refs/heads/devel -o ports.zip
unzip -oq ports.zip

if [ -d "FreeBSD-ports-devel" ]; then
  rm -rf /usr/local/etc/rc.d/*
  find FreeBSD-ports-devel -type f -name "*.in" -exec cp {} /usr/local/etc/rc.d/ \;
  echo "[✔] rc.d scripts restored."
else
  echo "[!] Failed to restore rc.d scripts"
  FAILED_FILES="${FAILED_FILES}\n/usr/local/etc/rc.d/*"
fi

rm -rf ports.zip FreeBSD-ports-devel

# Cleanup
echo "[*] Cleaning PHP session files..."
rm -rf /var/tmp/php* /tmp/php*

# Restart services
echo "[*] Restarting services..."
pfSsh.php playback svc restart webgui
pfSsh.php playback svc restart all

# Report
clear
echo""
echo""
echo""
echo""
echo "_______________________"
echo "|Restore Completed    |"
echo "|---------------------|"
echo "|Files Restored:      |"
echo "|/etc/rc.initial      |"
echo "|/etc/inc/config.inc  |"
echo "|/etc/inc/auth.inc    |"
echo "|/usr/local/www       |"
echo "|/usr/local/etc/rc.d  |"
echo "|_____________________|"

if [ -n "$FAILED_FILES" ]; then
  echo "Some files failed to restore:"
  echo -e "$FAILED_FILES"
else
  echo "files restored successfully."
fi

EOF

# endregion

# region (Script to find and delete malicious users on the pfsense)
cat << 'EOF' > /root/SenseSation/Scripts/delete_users.sh
#!/bin/sh

# pfSense - Safe Non-Native User Deletion Script

BASE_DIR="/SenseSation"
BACKUP_DIR="$BASE_DIR/Backups"
QUARANTINE_DIR="$BASE_DIR/Quarantine"
SCRIPT_DIR="$BASE_DIR/Scripts"
SUPPORT_DIR="$BASE_DIR/Supporting_Files"

DEFAULT_USERS="admin"
USER_XML="/conf/config.xml"
BACKUP_XML="$BACKUP_DIR/config.xml.bak"
USER_DIRS="/home /usr/local/etc"  # Directories to check and delete user directories from

NOW=$(date +%Y%m%d_%H%M%S)

# Ensure required directories exist
mkdir -p "$BACKUP_DIR" "$QUARANTINE_DIR" "$SCRIPT_DIR" "$SUPPORT_DIR"

echo "===[ pfSense Non-Native Users Report ]==="
echo ""

# Extract all users
ALL_USERS=$(xmllint --xpath '//user/name/text()' "$USER_XML" 2>/dev/null)

USER_LIST=""
INDEX=1

echo "Found users:"
for USER in $ALL_USERS; do
    if echo "$DEFAULT_USERS" | grep -qw "$USER"; then
        continue
    fi

    echo "$INDEX) Username: $USER"

    GROUPS=$(xmllint --xpath "string(//user[name='$USER']/groups/item)" "$USER_XML" 2>/dev/null)
    [ -z "$GROUPS" ] && GROUPS="(none)"

    DESC=$(xmllint --xpath "string(//user[name='$USER']/descr)" "$USER_XML" 2>/dev/null)
    [ -z "$DESC" ] && DESC="(no description)"

    echo "   Groups: $GROUPS"
    echo "   Description: $DESC"
    echo ""

    USER_LIST="$USER_LIST$USER\n"
    INDEX=$((INDEX + 1))
done

echo "Enter the number of the user you want to delete (press Enter for none): "
read -r USER_NUMBER

if [ -n "$USER_NUMBER" ] && echo "$USER_NUMBER" | grep -qE '^[0-9]+$'; then
    DELETE_USER=$(echo -e "$USER_LIST" | sed -n "${USER_NUMBER}p" | xargs)

    if [ -z "$DELETE_USER" ]; then
        echo "Invalid selection."
        exit 1
    fi

    echo "Selected user for deletion: $DELETE_USER"

    echo "Backing up current config to $BACKUP_XML..."
    cp "$USER_XML" "$BACKUP_XML"

    echo "Removing user '$DELETE_USER'..."

    # Escape special regex characters in username
    ESCAPED_USER=$(printf '%s\n' "$DELETE_USER" | sed 's/[][\.*^$(){}?+|/]/\\&/g')

    # Delete the <user> block with <name> matching the selected username
    awk -v user="$ESCAPED_USER" '
    BEGIN { in_block = 0; block = "" }
    /<user>/ { in_block = 1; block = $0 ORS; next }
    /<\/user>/ {
        block = block $0 ORS;
        if (block ~ "<name>" user "</name>") {
            in_block = 0;
            block = "";
            next;
        } else {
            printf "%s", block;
            in_block = 0;
            block = "";
            next;
        }
    }
    {
        if (in_block) {
            block = block $0 ORS;
        } else {
            print;
        }
    }
    ' "$BACKUP_XML" > "$USER_XML"

    # Archive and remove the user's directories
    echo "Archiving and removing directories associated with '$DELETE_USER'..."

    for DIR in $USER_DIRS; do
        USER_DIR_PATH="$DIR/$DELETE_USER"

        if [ -d "$USER_DIR_PATH" ]; then
            ARCHIVE_NAME="user_backup_${DELETE_USER}_$(echo "$DIR" | tr '/' '_')_${NOW}.tar.gz"
            ARCHIVE_PATH="$QUARANTINE_DIR/$ARCHIVE_NAME"

            echo "Archiving $USER_DIR_PATH to $ARCHIVE_PATH..."
            tar -czf "$ARCHIVE_PATH" -C "$(dirname "$USER_DIR_PATH")" "$(basename "$USER_DIR_PATH")"

            if [ -f "$ARCHIVE_PATH" ]; then
                echo "Archive successful. Removing original: $USER_DIR_PATH"
                rm -rf "$USER_DIR_PATH"
            else
                echo "ERROR: Failed to archive $USER_DIR_PATH. Skipping deletion."
            fi
        else
            echo "No directory found for user in $DIR"
        fi
    done

    echo "Reloading pfSense config..."
    /etc/rc.reload_all

    echo "User '$DELETE_USER' and associated directories successfully removed, archived, and config reloaded."
else
    echo "No user deleted."
fi

echo "=== End of Report ==="


EOF

# endregion

# region (Script to find webshells, rogue bash sessions, reverse shells, etc)
cat << 'EOF' > /root/SenseSation/Scripts/shell_hunter.sh
#!/bin/sh
# Clean ShellHunter v2 - Reverse/Webshell/Rogue Shell Detection (No Colors)

echo "[*] Starting scan for suspicious shell activity..."
echo "====================================================="

### 1. Suspicious processes
echo "[1/4] Checking for suspicious processes..."
ps aux | grep -E 'nc|netcat|bash|sh|python|perl|php|ruby|socat' | grep -v grep | while read -r line; do
    pid=$(echo "$line" | awk '{print $2}')
    exe_path=$(readlink "/proc/$pid/exe" 2>/dev/null)
    [ -n "$exe_path" ] && echo "[Weird Process] PID: $pid - $exe_path"
done
echo ""

### 2. Suspicious listening ports
echo "[2/4] Checking for suspicious listening ports..."
netstat -tunlp 2>/dev/null | grep -E '(:4444|:1337|:1234|:9001|:2222|:8080)' | while read -r line; do
    port=$(echo "$line" | awk '{print $4}')
    proc=$(echo "$line" | awk '{print $7}')
    echo "[Reverse Shell Port] $port - $proc"
done
echo ""

### 3. Suspicious script contents
echo "[3/4] Checking for suspicious script contents..."
for dir in /home /tmp /var/tmp; do
    [ -d "$dir" ] || continue
    grep -r --include="*.sh" -E 'bash -i|nc -e|python.*socket|socat|/dev/tcp|exec [0-9]' "$dir" 2>/dev/null | while read -r match; do
        filepath=$(echo "$match" | cut -d: -f1)
        echo "[Suspicious Script] $filepath"
    done
done
echo ""

### 4. Suspicious startup entries
echo "[4/4] Checking for suspicious startup entries..."
startup_dirs="/etc/rc.d /usr/local/etc/rc.d $HOME/.config/autostart"
for path in $startup_dirs; do
    find $path -type f 2>/dev/null | while read -r startup; do
        if grep -qEi '\b(nc|python|perl|php|ruby|socat)\b' "$startup"; then
            echo "[Startup File] $startup"
        fi
    done
done
echo ""

echo "[✓] Scan complete."

EOF

# endregion

# region (script to find webhooks)

cat << 'EOF' > /root/SenseSation/Scripts/find_webhooks.sh
#!/bin/sh

# Output file for results
OUTPUT="/root/discord_webhooks_found.txt"
> "$OUTPUT"

echo "Scanning system for Discord webhooks..."
echo "Results will be saved to: $OUTPUT"
echo "----------" > "$OUTPUT"

# Define the pattern for a Discord webhook URL
WEBHOOK_PATTERN="discord\.com/api/webhooks"

# Search key directories
for DIR in /etc /root /usr /var /tmp /home /conf; do
    echo "Scanning $DIR..."
    find "$DIR" -type f 2>/dev/null | while read FILE; do
        if grep -qE "$WEBHOOK_PATTERN" "$FILE" 2>/dev/null; then
            echo "Found potential webhook in: $FILE" | tee -a "$OUTPUT"
            grep -E "$WEBHOOK_PATTERN" "$FILE" | tee -a "$OUTPUT"
            echo "-----------------------------" >> "$OUTPUT"
        fi
    done
done

echo "Scan complete."
echo "Review the file at $OUTPUT"

EOF

# endregion

# region (Script to disable SSH)
cat << 'EOF' > /root/SenseSation/Scripts/nuke_ssh.sh
#!/bin/sh

echo "Choose an option:"
echo "1) Turn off SSH (stop the service)"
echo "2) Destroy SSH completely (remove files, configs, XML entries)"
read -r choice

case "$choice" in
    1)
        echo "[INFO] Stopping SSH service..."
        /etc/rc.d/sshd stop
        echo "[INFO] SSH service stopped."
        ;;
    2)
        echo "[WARNING] This will PERMANENTLY delete SSH from this system and its config."
        echo "Are you absolutely sure? (yes/NO)"
        read -r confirm
        if [ "$confirm" = "yes" ]; then
            echo "[INFO] Stopping SSH service..."
            /etc/rc.d/sshd stop

            echo "[INFO] Removing SSH from rc.conf and rc.conf.local..."
            sed -i '' '/sshd_enable/d' /etc/rc.conf
            sed -i '' '/sshd_enable/d' /etc/rc.conf.local

            echo "[INFO] Removing SSH binaries and configs..."
            rm -f /usr/sbin/sshd
            rm -f /usr/bin/ssh*
            rm -f /usr/libexec/sftp-server
            rm -f /usr/libexec/ssh-keysign
            rm -rf /etc/ssh
            rm -f /etc/rc.d/sshd

            echo "[INFO] Removing SSH settings from pfSense config.xml..."
            cp /cf/conf/config.xml /cf/conf/config.xml.bak
            sed -i '' '/<ssh.*>/d' /cf/conf/config.xml
            sed -i '' '/<enablessh.*>/d' /cf/conf/config.xml

            echo "[INFO] Reconfiguring system to apply changes..."
            /etc/rc.reload_all

            echo "[SUCCESS] SSH has been turned into goo."
        else
            echo "[INFO] Destruction cancelled."
        fi
        ;;
    *)
        echo "[ERROR] Invalid option. Exiting."
        ;;
esac

EOF

# endregion

# region (Script to nuke the Web GUI)
cat << 'EOF' > /root/SenseSation/Scripts/nuke_gui.sh
pfSsh.php playback svc stop lighttpd

EOF

# endregion
# endregion

# region (Make files executable)
make_scripts_executable() {
    echo "[*] Setting script permissions..."
    scripts="
        /root/SenseSation/Scripts/nuke_gui.sh
        /root/SenseSation/Scripts/find_webhooks.sh
        /root/SenseSation/Scripts/shell_hunter.sh
        /root/SenseSation/Scripts/delete_users.sh
        /root/SenseSation/Scripts/restore_files.sh
        /root/SenseSation/Scripts/restore_binaries.sh
        /root/SenseSation/Scripts/nuke_ssh.sh
        /root/SenseSation/Scripts/stop_script.sh
    "
    for script in $scripts; do
        chmod +x "$script" 2>/dev/null || failed_items="${failed_items}SCRIPT:$script\n"
    done
}
# Make the files executable 
chmod +x /root/SenseSation/Scripts/nuke_gui.sh
chmod +x /root/SenseSation/Scripts/find_webhooks.sh
chmod +x /root/SenseSation/Scripts/shell_hunter.sh
chmod +x /root/SenseSation/Scripts/delete_users.sh
chmod +x /root/SenseSation/Scripts/restore_files.sh
chmod +x /root/SenseSation/Scripts/restore_binaries.sh
chmod +x /root/SenseSation/Scripts/nuke_ssh.sh
chmod +x /root/SenseSation/Scripts/stop_script.sh
chmod +x /root/SenseSation/Supporting_Files/rc.initial
chmod +x /root/SenseSation/Supporting_Files/rc.banner

# endregion

# region (Move files appropriately)
# Move new files to the expected location
cp /root/SenseSation/Supporting_Files/rc.initial /etc/
cp /root/SenseSation/Supporting_Files/rc.banner /etc/
# endregion

# region (Check for failures)
failed_items=""

# === Summary Report ===
report_results() {
    echo ""
    echo "===== Setup Summary ====="
    if echo "$failed_items" | grep -q "^DIR:"; then
        echo "[!] Directory creation: FAIL"
        echo "$failed_items" | grep "^DIR:"
    else
        echo "[+] Directory creation: OK"
    fi

    if echo "$failed_items" | grep -q "^SCRIPT:"; then
        echo "[!] Script permissions: FAIL"
        echo "$failed_items" | grep "^SCRIPT:"
    else
        echo "[+] Script permissions: OK"
    fi

    if echo "$failed_items" | grep -q "^SUPPORT_"; then
        echo "[!] Supporting files: FAIL"
        echo "$failed_items" | grep "^SUPPORT_"
    else
        echo "[+] Supporting files: OK"
    fi

    if [ -z "$failed_items" ]; then
        echo "All setup steps completed successfully."
    else
        echo "Some steps failed. Review output above."
    fi
}

# === Run Everything ===
create_directories
make_scripts_executable
setup_supporting_files
report_results

# endregion