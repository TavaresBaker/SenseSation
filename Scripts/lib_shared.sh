#!/bin/sh
# =============================================================================
# lib_shared.sh - pfSense Threat Hunter: Shared Utilities
# Sourced by all module scripts. Do not run directly.
# =============================================================================

# Resolve paths — works in both layouts:
#   Repo:      Scripts/lib_shared.sh  → logs/ and backups/ are at ../logs ../backups
#   Installed: /opt/pf_hunter/Scripts/ → same relative layout
SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "$0")" && pwd)}"
_BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
LOG_DIR="$_BASE_DIR/logs"
BACKUP_DIR="$_BASE_DIR/backups"
mkdir -p "$LOG_DIR" "$BACKUP_DIR"
LOG_FILE="$LOG_DIR/hunter_$(date +%Y%m%d).log"

# Colors — use printf to generate real ESC characters so they work
# on pfSense's /bin/sh which doesn't expand \033 in double-quoted strings
ESC="$(printf '\033')"
R="${ESC}[0;31m"
G="${ESC}[0;32m"
Y="${ESC}[1;33m"
C="${ESC}[0;36m"
W="${ESC}[1;37m"
B="${ESC}[1m"
N="${ESC}[0m"

# Logging and messaging
log()    { printf "[%s] %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG_FILE"; }
msg_ok() { printf "${G}  [OK]${N}  %s\n" "$1"; log "OK: $1"; }
msg_fl() { printf "${R}  [!!]${N}  %s\n" "$1"; log "FAIL: $1"; }
msg_wn() { printf "${Y}  [**]${N}  %s\n" "$1"; log "WARN: $1"; }
msg_in() { printf "${C}  [--]${N}  %s\n" "$1"; log "INFO: $1"; }

press_enter() {
    printf "\n  Press ENTER to return to menu..."
    read _junk
}

confirm() {
    printf "${Y}  %s [y/N]: ${N}" "$1"
    read _ans
    case "$_ans" in [Yy]*) return 0;; *) return 1;; esac
}

divider() {
    printf "${C}  ---------------------------------------------------------------------------${N}\n"
}

draw_screen() {
    clear
    _host="$(hostname 2>/dev/null || echo unknown)"
    _kern="$(uname -r 2>/dev/null || echo unknown)"
    _ip="$(ifconfig 2>/dev/null | awk '/inet /{print $2}' | grep -v 127 | head -1)"
    _ip="${_ip:-unavailable}"

    # ASCII banner
    printf "${C}"
    printf "  ██████╗ ███████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ \n"
    printf "  ██╔══██╗██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗\n"
    printf "  ██████╔╝█████╗      ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝\n"
    printf "  ██╔═══╝ ██╔══╝      ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗\n"
    printf "  ██║     ██║         ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║\n"
    printf "  ╚═╝     ╚═╝         ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝\n"
    printf "${N}\n"

    printf "${C}  pfSense Threat Hunter v1.0 | $(date '+%Y-%m-%d %H:%M:%S')${N}\n"
    printf "${W}  Hostname: $_host | $_kern${N}\n"
    printf "\n"

    _ssh_stat="${G}STOPPED${N}"
    pgrep sshd >/dev/null 2>&1 && _ssh_stat="${R}RUNNING${N}"

    _susp="${G}None detected${N}"
    ps aux 2>/dev/null | grep -qEi "(nc -[el]|ncat|bash -i|/dev/tcp|xmrig|minerd)" \
        && _susp="${R}! SUSPICIOUS PROCESSES DETECTED !${N}"

    printf "  ${B}System Status:${N}\n"
    printf "  SSH Daemon: ${_ssh_stat}  |  ${_susp}\n"
    printf "\n"
    divider
    printf "\n"
}

draw_menu() {
    draw_screen
    printf "  ${B}THREAT HUNTING MODULES${N}\n\n"
    printf "  ${B}1)${N}  ${Y}User Hunter${N}              - Find & delete malicious/hidden users\n"
    printf "  ${B}2)${N}  ${Y}Binary & File Restore${N}    - Restore binaries, break web shells & persistence\n"
    printf "  ${B}3)${N}  ${Y}Shell Hunter${N}             - Find web shells, reverse shells, rogue sessions\n"
    printf "  ${B}4)${N}  ${Y}SSH Manager${N}              - Disable/enable/nuke SSH, kill sessions\n"
    printf "  ${B}5)${N}  ${Y}Process Analyzer${N}         - Analyze & kill suspicious processes\n"
    printf "  ${B}6)${N}  ${Y}View Logs${N}                - Review hunt logs\n"
    printf "  ${B}7)${N}  ${Y}Full Sweep${N}               - Run all modules non-interactively\n"
    printf "  ${B}8)${N}  ${Y}Config Restore${N}           - Apply known-good config.xml\n"
    printf "\n"
    divider
    printf "\n  ${B}0)${N}  Exit to shell\n"
    printf "\n"
    printf "  Enter choice: "
}
