#!/bin/sh
# =============================================================================
# full_sweep.sh - pfSense Threat Hunter: Full Automated Sweep
# Runs all scan modules non-interactively and logs everything
# Run standalone: sh full_sweep.sh
# =============================================================================
SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "$0")" && pwd)}"
. "$SCRIPT_DIR/lib_shared.sh"
# Pull in patterns from other modules
_PROC_PAT='(nc -[el]|ncat|bash -i|bash -c /|/dev/tcp|/dev/udp|python.*-c|perl.*-e|mkfifo|socat.*exec|xmrig|minerd|ccminer|cgminer)'
_MINER_PAT='xmrig|minerd|cgminer|bfgminer|cpuminer|ethminer|t-rex|nbminer|lolminer'
mod_sweep() {
    draw_screen
    printf "\n  ${B}Full Sweep${N}\n"
    divider
    printf "\n"
    msg_wn "Full sweep runs all scan modules automatically and logs everything."
    confirm "Proceed?" || return

    _slog="$LOG_DIR/full_sweep_$(date +%Y%m%d_%H%M%S).log"
    printf "Full sweep started: %s\n" "$(date)" | tee "$_slog"
    printf "==========================================================\n" >> "$_slog"

    printf "\n=== USER AUDIT ===\n" | tee -a "$_slog"
    awk -F: '($3==0 && $1!="root" && $1!="toor"){print "UID-0: "$1}' /etc/passwd | tee -a "$_slog"
    find / -name "authorized_keys" -not -path "/proc/*" 2>/dev/null | \
        while read _f; do printf "AUTHKEYS: %s\n" "$_f"; done | tee -a "$_slog"
    grep "^wheel:" /etc/group 2>/dev/null | tee -a "$_slog"

    printf "\n=== REPO CONFIG INTEGRITY ===\n" | tee -a "$_slog"
    _sw_rv="$(cat /etc/version 2>/dev/null | sed 's/-.*//' | tr -d '[:space:]')"
    _sw_native_ver="$(grep 'url:' /usr/local/share/pfSense/pkg/repos/pfSense-repo.conf \
        2>/dev/null | head -1 | grep -oE 'v[0-9_]+' | head -1 | tr '_' '.' | sed 's/^v//')"
    printf "Installed version : %s\n" "$_sw_rv" | tee -a "$_slog"
    printf "Repo config says  : %s\n" "${_sw_native_ver:-(unreadable)}" | tee -a "$_slog"
    if [ -n "$_sw_native_ver" ] && [ "$_sw_native_ver" != "$_sw_rv" ]; then
        printf "ALERT: REPO VERSION MISMATCH — repo points to %s but system is %s\n" \
            "$_sw_native_ver" "$_sw_rv" | tee -a "$_slog"
        printf "This may be attacker tampering to block security updates.\n" | tee -a "$_slog"
    else
        printf "Repo version matches installed version: OK\n" | tee -a "$_slog"
    fi
    printf "Native repo config:\n" | tee -a "$_slog"
    grep 'url:' /usr/local/share/pfSense/pkg/repos/pfSense-repo.conf 2>/dev/null | \
        tee -a "$_slog"
    printf "Current DNS servers (from resolv.conf):\n" | tee -a "$_slog"
    grep "^nameserver" /etc/resolv.conf 2>/dev/null | tee -a "$_slog"
    printf "pfSense configured DNS (from config.xml):\n" | tee -a "$_slog"
    grep -A1 "dnsserver\|dns_server" /cf/conf/config.xml 2>/dev/null | \
        grep -v "^--$" | head -10 | tee -a "$_slog"
    printf "SRV resolution test for pkg.pfsense.org:\n" | tee -a "$_slog"
    host -t srv _https._tcp.pkg.pfsense.org 2>/dev/null | tee -a "$_slog" || \
        printf "FAILED - DNS cannot resolve SRV records\n" | tee -a "$_slog"
    # Check untrusted cert count and timestamps
    _uc_total="$(find /etc/ssl/untrusted -type l -o -type f 2>/dev/null | wc -l | tr -d ' ')"
    printf "Untrusted certs in /etc/ssl/untrusted: %s\n" "$_uc_total" | tee -a "$_slog"
    printf "Source dir mtime (should match OS install date):\n" | tee -a "$_slog"
    ls -ld /usr/share/certs/untrusted/ 2>/dev/null | tee -a "$_slog"
    # Note: pkg+https with SSL_NO_VERIFY_PEER=1 required on 2.8.1 due to
    # Mozilla distrust list conflict with Netgate's update server CA
    printf "NOTE: pfSense 2.8.1 known issue — Mozilla distrust list blocks Netgate update CA\n" | tee -a "$_slog"

    # Check recently installed packages for anything unexpected
    printf "\nRecently installed packages (last 10 by timestamp):\n" | tee -a "$_slog"
    pkg query -a "%t %n-%v" 2>/dev/null | sort -rn | head -10 | tee -a "$_slog"

    printf "\n=== PROCESS SCAN ===\n" | tee -a "$_slog"
    ps aux 2>/dev/null | grep -Ei "$_PROC_PAT" | grep -v grep | tee -a "$_slog"

    printf "\n=== WEBSHELL SCAN ===\n" | tee -a "$_slog"
    find /usr/local/www /tmp /var/tmp -type f \( -name "*.php" -o -name "*.sh" \) 2>/dev/null | \
    while read _f; do
        grep -qEi "eval\(base64_decode|passthru|shell_exec|bash -i|/dev/tcp" "$_f" 2>/dev/null && \
            printf "SHELL CANDIDATE: %s\n" "$_f" | tee -a "$_slog"
    done

    printf "\n=== TEMP DIR CONTENTS ===\n" | tee -a "$_slog"
    find /tmp /var/tmp -type f 2>/dev/null | tee -a "$_slog"

    printf "\n=== ACTIVE CONNECTIONS ===\n" | tee -a "$_slog"
    sockstat 2>/dev/null | tee -a "$_slog"

    printf "\n=== MINER CHECK ===\n" | tee -a "$_slog"
    ps aux 2>/dev/null | grep -iE "$_MINER_PAT" | grep -v grep | tee -a "$_slog"
    netstat -an 2>/dev/null | grep -E ":(3333|4444|5555|7777|14444)" | tee -a "$_slog"

    printf "\n==========================================================\n" >> "$_slog"
    printf "Full sweep complete: %s\n" "$(date)" | tee -a "$_slog"
    printf "\n"
    msg_ok "Sweep log saved to: $_slog"
    press_enter
}

mod_sweep
