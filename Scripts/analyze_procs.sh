#!/bin/sh
# =============================================================================
# analyze_procs.sh - pfSense Threat Hunter: Process Analyzer Module
# Detects suspicious processes, crypto miners, and web-spawned shells
# Run standalone: sh analyze_procs.sh
# =============================================================================
SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "$0")" && pwd)}"
. "$SCRIPT_DIR/lib_shared.sh"
_PROC_PAT='(nc -[el]|ncat|bash -i|bash -c /|/dev/tcp|/dev/udp|python.*-c|perl.*-e|mkfifo|socat.*exec|xmrig|minerd|ccminer|cgminer)'
_MINER_PAT='xmrig|minerd|cgminer|bfgminer|cpuminer|ethminer|t-rex|nbminer|lolminer'

mod_procs() {
    while true; do
        draw_screen
        printf "\n"
        printf "  ${B}Process Analyzer${N}\n"
        divider
        printf "  ${B}1)${N}  Show all processes (sorted by CPU)\n"
        printf "  ${B}2)${N}  Scan for suspicious processes\n"
        printf "  ${B}3)${N}  Real-time monitor (Ctrl+C to stop)\n"
        printf "  ${B}4)${N}  Kill process by PID\n"
        printf "  ${B}5)${N}  Check for crypto miners\n"
        printf "  ${B}0)${N}  Back\n"
        printf "\n"
        printf "  Enter an option: "
        read _c
        case "$_c" in
            1) _pr_list ;;
            2) _pr_scan ;;
            3) _pr_monitor ;;
            4) _pr_kill ;;
            5) _pr_miners ;;
            0) return ;;
        esac
    done
}

_pr_list() {
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  All Processes — Sorted by CPU Usage${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n\n"
    printf "  ${B}  %-8s %-12s %-6s %-6s %s${N}\n" "PID" "USER" "CPU%" "MEM%" "COMMAND"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    ps aux 2>/dev/null | sort -k3 -rn | tail -n +2 | head -30 | \
    while read _u _pid _cpu _mem _vsz _rss _tt _stat _start _time _cmd; do
        # Highlight high CPU in yellow
        _color="$N"
        [ "$(echo "$_cpu > 20" | awk '{print ($1>20)}')" = "1" ] 2>/dev/null && _color="$Y"
        echo "$_cmd" | grep -qEi "$_PROC_PAT" && _color="$R"
        printf "  ${_color}%-8s %-12s %-6s %-6s %s${N}\n" \
            "$_pid" "$_u" "$_cpu" "$_mem" "$_cmd"
    done
    press_enter
}

_pr_scan() {
    _rpt="$LOG_DIR/proc_scan_$(date +%Y%m%d_%H%M%S).txt"
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  Suspicious Process Scan${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n\n"

    _total_flags=0

    msg_in "Checking for suspicious command patterns..."
    ps aux 2>/dev/null | grep -Ev "grep|rc.hunter" | \
    while read _u _pid _cpu _mem _vsz _rss _tt _stat _start _time _cmd; do
        if echo "$_cmd" | grep -qEi "$_PROC_PAT"; then
            printf "\n"
            printf "  ${R}  [SUSPICIOUS PROCESS]${N}\n"
            printf "  PID     : ${W}%s${N}\n" "$_pid"
            printf "  User    : %s\n" "$_u"
            printf "  CPU%%    : %s\n" "$_cpu"
            printf "  Command : ${R}%s${N}\n" "$_cmd"
            printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
            printf "PID=%s USER=%s CMD=%s\n" "$_pid" "$_u" "$_cmd" >> "$_rpt"
            log "SUSPPROC: PID=$_pid USER=$_u CMD=$_cmd"
            _total_flags=1
        fi
    done

    printf "\n"
    msg_in "Checking for processes running from /tmp or /var/tmp..."
    ps aux 2>/dev/null | grep -Ev "grep|rc.hunter" | \
    while read _u _pid _cpu _mem _vsz _rss _tt _stat _start _time _cmd; do
        if echo "$_cmd" | grep -qE "(/tmp/|/var/tmp/)"; then
            printf "  ${Y}  [TEMP PATH]${N}  PID ${W}%-6s${N}  USER %-10s  %s\n" "$_pid" "$_u" "$_cmd"
            log "TMPPROC: PID=$_pid USER=$_u CMD=$_cmd"
        fi
    done

    printf "\n"
    msg_in "Checking for high CPU usage (>80%)..."
    ps aux 2>/dev/null | tail -n +2 | \
    while read _u _pid _cpu _mem _vsz _rss _tt _stat _start _time _cmd; do
        if awk "BEGIN{exit !($_cpu+0 > 80)}" 2>/dev/null; then
            printf "  ${Y}  [HIGH CPU]${N}  PID ${W}%-6s${N}  CPU ${Y}%s%%${N}  USER %-10s  %s\n" \
                "$_pid" "$_cpu" "$_u" "$_cmd"
            log "HIGHCPU: PID=$_pid CPU=$_cpu USER=$_u CMD=$_cmd"
        fi
    done

    printf "\n"
    msg_in "Checking for shells spawned by web server processes..."
    for _wpid in $(pgrep -f "nginx|lighttpd|php-fpm" 2>/dev/null); do
        for _cpid in $(pgrep -P "$_wpid" 2>/dev/null); do
            _cmd="$(ps -p "$_cpid" -o comm= 2>/dev/null)"
            if echo "$_cmd" | grep -qE "(sh|bash|ksh|python|perl)"; then
                printf "  ${R}  [WEB->SHELL]${N}  Web server PID ${W}%s${N} spawned: PID ${W}%s${N} (%s)\n" \
                    "$_wpid" "$_cpid" "$_cmd"
                log "WEBSHELL PROC: webpid=$_wpid childpid=$_cpid cmd=$_cmd"
            fi
        done
    done

    printf "\n"
    msg_ok "Process scan complete. Report: $LOG_DIR"
    press_enter
}

_pr_monitor() {
    clear
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  Real-Time Process Monitor — Ctrl+C to stop${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n\n"
    printf "  Watching for: nc, ncat, bash -i, /dev/tcp, miners, mkfifo...\n\n"

    while true; do
        ps aux 2>/dev/null | grep -Ev "grep|rc.hunter" | \
        while read _u _pid _cpu _mem _vsz _rss _tt _stat _start _time _cmd; do
            if echo "$_cmd" | grep -qEi "$_PROC_PAT"; then
                printf "  ${R}[%s ALERT]${N}  PID ${W}%-6s${N}  USER %-10s  %s\n" \
                    "$(date '+%H:%M:%S')" "$_pid" "$_u" "$_cmd"
                log "MONITOR ALERT: PID=$_pid USER=$_u CMD=$_cmd"
            fi
        done
        sleep 3
    done
}

_pr_kill() {
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  Kill Process by PID${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n\n"

    printf "  ${B}  %-8s %-12s %-6s %s${N}\n" "PID" "USER" "CPU%" "COMMAND"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    ps aux 2>/dev/null | grep -Ev "grep|rc.hunter" | grep -Ei "$_PROC_PAT" | head -15 | \
    while read _u _pid _cpu _mem _vsz _rss _tt _stat _start _time _cmd; do
        printf "  ${R}%-8s${N} %-12s %-6s %s\n" "$_pid" "$_u" "$_cpu" "$_cmd"
    done

    printf "\n  If none listed above, enter any PID from the process list.\n"
    printf "\n  Enter PID(s) to kill (space-separated, ENTER to cancel): "
    read _pids; [ -z "$_pids" ] && return

    for _pid in $_pids; do
        echo "$_pid" | grep -qE '^[0-9]+$' || { msg_wn "Invalid PID: $_pid"; continue; }
        _cmd="$(ps -p "$_pid" -o args= 2>/dev/null)"
        _user="$(ps -p "$_pid" -o user= 2>/dev/null)"
        printf "\n"
        printf "  PID     : %s\n" "$_pid"
        printf "  User    : %s\n" "$_user"
        printf "  Command : %s\n" "$_cmd"
        confirm "Kill PID $_pid?" && kill -9 "$_pid" 2>/dev/null && \
            msg_ok "Killed PID $_pid" || msg_wn "Failed to kill $_pid"
        log "KILLED PID $_pid: $_cmd"
    done
    press_enter
}

_pr_miners() {
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  Crypto Miner Detection${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n\n"

    msg_in "Scanning process list for known miner signatures..."
    _found=0
    ps aux 2>/dev/null | grep -iE "$_MINER_PAT" | grep -v grep | \
    while read _u _pid _cpu _mem _vsz _rss _tt _stat _start _time _cmd; do
        printf "\n"
        printf "  ${R}  [MINER DETECTED]${N}\n"
        printf "  PID     : ${W}%s${N}\n" "$_pid"
        printf "  User    : %s\n" "$_u"
        printf "  CPU%%    : ${R}%s${N}\n" "$_cpu"
        printf "  Command : ${R}%s${N}\n" "$_cmd"
        printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
        log "MINER PROC: PID=$_pid CMD=$_cmd"
        _found=1
    done
    [ "$_found" -eq 0 ] && msg_ok "No miner processes found in process list"

    printf "\n"
    msg_in "Scanning filesystem for miner binaries..."
    find / -type f \( -name "xmrig" -o -name "minerd" -o -name "cpuminer" \) \
        -not -path "/proc/*" 2>/dev/null | while read _f; do
        printf "\n"
        printf "  ${R}  [MINER BINARY]${N}  %s\n" "$_f"
        printf "  Size : %s\n" "$(ls -lh "$_f" 2>/dev/null | awk '{print $5}')"
        log "MINER BIN: $_f"
        confirm "Delete $_f?" && rm -f "$_f" && msg_ok "Deleted: $_f" || true
    done

    printf "\n"
    msg_in "Checking for active mining pool connections..."
    _found=0
    netstat -an 2>/dev/null | grep -E ":(3333|4444|5555|7777|8888|14444|45700)" | \
    while read _line; do
        printf "  ${R}  [MINING CONNECTION]${N}  %s\n" "$_line"
        log "MININGCONN: $_line"
        _found=1
    done
    [ "$_found" -eq 0 ] && msg_ok "No mining pool connections found"

    printf "\n"
    msg_ok "Miner check complete."
    press_enter
}


mod_procs
