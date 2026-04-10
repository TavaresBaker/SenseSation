#!/bin/sh
# =============================================================================
# hunt_shells.sh - pfSense Threat Hunter: Shell Hunter Module
# Finds web shells, reverse shells, rogue sessions, and exfil channels
# Run standalone: sh hunt_shells.sh
# =============================================================================
SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "$0")" && pwd)}"
. "$SCRIPT_DIR/lib_shared.sh"
_PHP_PAT='eval\(base64_decode|passthru\s*\(|shell_exec\s*\(|system\s*\(|popen\s*\(|\$_GET\s*\[|\$_POST\s*\[|\$_REQUEST\s*\[|base64_decode\s*\(\s*\$|str_rot13|gzinflate|assert\s*\(\s*\$|preg_replace.*\/e|create_function|move_uploaded_file'
_SH_PAT='bash\s+-i|/dev/tcp/|/dev/udp/|nc\s+-[el]|ncat\s+-[el]|python.*socket|perl.*socket|mkfifo.*nc|0<&.*>&'
_WH_PAT='(curl|wget).*(discord\.com/api/webhooks|hooks\.slack|webhook|ngrok|serveo|localhost\.run)'

mod_shells() {
    while true; do
        draw_screen
        printf "\n"
        printf "  ${B}Shell Hunter${N}\n"
        divider
        printf "  ${B}1)${N}  Scan for PHP web shells\n"
        printf "  ${B}2)${N}  Scan for reverse shells in scripts\n"
        printf "  ${B}3)${N}  Scan for rogue shell sessions\n"
        printf "  ${B}4)${N}  Scan for webhooks / exfil channels\n"
        printf "  ${B}5)${N}  Kill a session by PID\n"
        printf "  ${B}6)${N}  Full scan (all above)\n"
        printf "  ${B}0)${N}  Back\n"
        printf "\n"
        printf "  Enter an option: "
        read _c
        case "$_c" in
            1) _sh_php ;;
            2) _sh_rev ;;
            3) _sh_sess ;;
            4) _sh_webhook ;;
            5) _sh_kill ;;
            6) _sh_php; _sh_rev; _sh_sess; _sh_webhook ;;
            0) return ;;
        esac
    done
}

_sh_php() {
    _rpt="$LOG_DIR/shell_hunt_$(date +%Y%m%d_%H%M%S).txt"
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  PHP Web Shell Scan${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n\n"
    _found=0
    for _dir in /usr/local/www /var/www /tmp /var/tmp; do
        [ -d "$_dir" ] || continue
        msg_in "Scanning: $_dir"
        find "$_dir" -type f \( -name "*.php" -o -name "*.php5" -o -name "*.phtml" \) 2>/dev/null | \
        while read _f; do
            if grep -qEi "$_PHP_PAT" "$_f" 2>/dev/null; then
                printf "\n"
                printf "  ${R}  [SHELL CANDIDATE]${N}\n"
                printf "  File    : ${W}%s${N}\n" "$_f"
                printf "  Size    : %s\n" "$(wc -c < "$_f" 2>/dev/null | tr -d ' ') bytes"
                printf "  Modified: %s\n" "$(ls -la "$_f" 2>/dev/null | awk '{print $6,$7,$8}')"
                printf "  Matches :\n"
                grep -nEi "$_PHP_PAT" "$_f" 2>/dev/null | head -5 | \
                    while read _ml; do printf "    ${Y}%s${N}\n" "$_ml"; done
                printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
                printf "%s\n" "$_f" >> "$_rpt"
                grep -nEi "$_PHP_PAT" "$_f" 2>/dev/null | head -5 >> "$_rpt"
                log "PHPSHELL: $_f"
                _found=1
            fi
        done
    done
    printf "\n"
    msg_in "Checking /tmp and /var/tmp for any files..."
    find /tmp /var/tmp -type f 2>/dev/null | while read _f; do
        printf "  ${Y}  [TEMP FILE]${N}  %s\n" "$_f"
        log "TEMPFILE: $_f"
    done
    printf "\n"
    msg_ok "PHP scan complete. Full report: $LOG_DIR"
    press_enter
}

_sh_rev() {
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  Reverse Shell Pattern Scan${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n\n"
    msg_in "Scanning .sh .bash .py .pl files for reverse shell patterns..."
    _found=0
    find / -type f \( -name "*.sh" -o -name "*.bash" -o -name "*.py" -o -name "*.pl" \) \
        -not -path "/proc/*" -not -path "$SCRIPT_DIR/*" 2>/dev/null | \
    while read _f; do
        if grep -qEi "$_SH_PAT" "$_f" 2>/dev/null; then
            printf "\n"
            printf "  ${R}  [REVERSE SHELL CANDIDATE]${N}\n"
            printf "  File    : ${W}%s${N}\n" "$_f"
            printf "  Modified: %s\n" "$(ls -la "$_f" 2>/dev/null | awk '{print $6,$7,$8}')"
            printf "  Matches :\n"
            grep -nEi "$_SH_PAT" "$_f" 2>/dev/null | head -3 | \
                while read _ml; do printf "    ${Y}%s${N}\n" "$_ml"; done
            printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
            log "REVSHELL: $_f"
            _found=1
        fi
    done

    printf "\n"
    msg_in "Checking for executables in /tmp and /var/tmp..."
    find /tmp /var/tmp -type f -perm /111 2>/dev/null | while read _f; do
        printf "  ${R}  [TEMP EXECUTABLE]${N}  %s\n" "$_f"
        printf "  Type: %s\n" "$(file "$_f" 2>/dev/null | cut -d: -f2-)"
        log "TMPEXEC: $_f"
    done

    printf "\n"
    msg_ok "Reverse shell scan complete."
    press_enter
}

_sh_sess() {
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  Active Shell Sessions and Network Activity${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n\n"

    msg_in "Logged-in users:"
    printf "\n"
    who 2>/dev/null | while read _line; do
        printf "  ${W}%s${N}\n" "$_line"
    done || printf "  None\n"

    printf "\n"
    msg_in "Shell-like processes (bash, sh, python, nc, etc.):"
    printf "\n"
    printf "  ${B}  %-8s %-12s %-6s %s${N}\n" "PID" "USER" "CPU%" "COMMAND"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    ps aux 2>/dev/null | grep -E " (bash|sh |ksh|csh|zsh|python|perl|nc |ncat) " | \
        grep -v grep | grep -v "rc.hunter" | \
    while read _u _pid _cpu _mem _vsz _rss _tt _stat _start _time _cmd; do
        # Flag truly suspicious ones in red, others in normal
        _color="$N"
        echo "$_cmd" | grep -qEi "(bash -i|nc -[el]|ncat|/dev/tcp|mkfifo)" && _color="$R"
        printf "  ${_color}  %-8s %-12s %-6s %s${N}\n" "$_pid" "$_u" "$_cpu" "$_cmd"
    done

    printf "\n"
    msg_in "Suspicious process indicators (netcat, reverse shells):"
    printf "\n"
    _susp_count=0
    ps aux 2>/dev/null | grep -Ev "grep|rc.hunter" | \
    while read _u _pid _cpu _mem _vsz _rss _tt _stat _start _time _cmd; do
        if echo "$_cmd" | grep -qEi "(nc -[el]|ncat|bash -i|/dev/tcp|mkfifo)"; then
            printf "  ${R}  [!!] PID %-6s USER %-10s CMD: %s${N}\n" "$_pid" "$_u" "$_cmd"
            log "SUSPPROC: PID=$_pid USER=$_u CMD=$_cmd"
            _susp_count=1
        fi
    done
    [ "$_susp_count" -eq 0 ] && msg_ok "No obvious reverse shell processes detected"

    printf "\n"
    msg_in "Network connections (excluding loopback and known services):"
    printf "\n"
    printf "  ${B}  %-8s %-22s %-22s %s${N}\n" "PROTO" "LOCAL" "REMOTE" "STATE"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    sockstat 2>/dev/null | grep -vE "(sshd|nginx|php|lighttpd|127\.|::1|USER)" | head -20 | \
    while read _line; do
        printf "  %s\n" "$_line"
    done

    printf "\n"
    msg_in "Recent login history (last 15):"
    printf "\n"
    last 2>/dev/null | head -15 | while read _line; do
        printf "  %s\n" "$_line"
    done

    press_enter
}

_sh_webhook() {
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  Webhook and Exfiltration Channel Scan${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n\n"

    msg_in "Scanning scripts and configs for outbound webhook patterns..."
    _found=0
    find / -type f \( -name "*.sh" -o -name "*.php" -o -name "*.conf" -o -name "*.py" \) \
        -not -path "/proc/*" -not -path "$SCRIPT_DIR/*" 2>/dev/null | \
    while read _f; do
        if grep -qEi "$_WH_PAT" "$_f" 2>/dev/null; then
            printf "\n"
            printf "  ${R}  [WEBHOOK PATTERN]${N}\n"
            printf "  File    : ${W}%s${N}\n" "$_f"
            printf "  Matches :\n"
            grep -nEi "$_WH_PAT" "$_f" 2>/dev/null | head -3 | \
                while read _ml; do printf "    ${Y}%s${N}\n" "$_ml"; done
            printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
            log "WEBHOOK: $_f"
            _found=1
        fi
    done
    [ "$_found" -eq 0 ] && msg_ok "No webhook patterns found in scripts"

    printf "\n"
    msg_in "Established outbound connections:"
    printf "\n"
    printf "  ${B}  %-10s %-24s %-24s %s${N}\n" "PROTO" "LOCAL" "REMOTE" "STATE"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    netstat -an 2>/dev/null | grep ESTABLISHED | \
    while read _line; do
        printf "  %s\n" "$_line"
    done | head -20

    printf "\n"
    msg_ok "Webhook scan complete."
    press_enter
}

_sh_kill() {
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  Kill Session by PID${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n\n"

    printf "  ${B}  %-8s %-12s %-6s %s${N}\n" "PID" "USER" "CPU%" "COMMAND"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    ps aux 2>/dev/null | grep -E " (bash|sh |nc |ncat|python|perl) " | \
        grep -v grep | grep -v "rc.hunter" | \
    while read _u _pid _cpu _mem _vsz _rss _tt _stat _start _time _cmd; do
        printf "  %-8s %-12s %-6s %s\n" "$_pid" "$_u" "$_cpu" "$_cmd"
    done

    printf "\n  Enter PID(s) to kill (space-separated, ENTER to cancel): "
    read _pids; [ -z "$_pids" ] && return
    for _pid in $_pids; do
        echo "$_pid" | grep -qE '^[0-9]+$' || { msg_wn "Invalid PID: $_pid"; continue; }
        _cmd="$(ps -p "$_pid" -o args= 2>/dev/null)"
        confirm "Kill PID $_pid ($_cmd)?" && kill -9 "$_pid" 2>/dev/null && \
            msg_ok "Killed PID $_pid" || msg_wn "Failed to kill $_pid"
        log "KILLED PID: $_pid"
    done
    press_enter
}


mod_shells
