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
