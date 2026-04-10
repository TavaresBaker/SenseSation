#!/bin/sh
# =============================================================================
# manage_ssh.sh - pfSense Threat Hunter: SSH Manager Module
# Disable, enable, nuke, harden, and recover SSH
# Run standalone: sh manage_ssh.sh
# =============================================================================
SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "$0")" && pwd)}"
. "$SCRIPT_DIR/lib_shared.sh"
_SSHD_CONF="/etc/ssh/sshd_config"
_SSHD_BAK="$BACKUP_DIR/sshd_config.bak"

mod_ssh() {
    while true; do
        draw_screen
        printf "\n"
        printf "  ${B}SSH Manager${N}\n"
        divider
        # Inline status
        if pgrep sshd >/dev/null 2>&1; then
            printf "  Status : ${R}sshd RUNNING${N}  PIDs: %s\n" "$(pgrep sshd | tr '\n' ' ')"
        else
            printf "  Status : ${G}sshd STOPPED${N}\n"
        fi
        printf "\n"
        printf "  ${B}1)${N}  Disable SSH\n"
        printf "  ${B}2)${N}  Enable SSH\n"
        printf "  ${B}3)${N}  NUKE SSH (destructive)\n"
        printf "  ${B}4)${N}  Kill active SSH session by PID\n"
        printf "  ${B}5)${N}  Harden sshd_config\n"
        printf "  ${B}6)${N}  Show active sessions and config\n"
        printf "  ${B}7)${N}  ${Y}Recover from nuke${N}\n"
        printf "  ${B}0)${N}  Back\n"
        printf "\n"
        printf "  Enter an option: "
        read _c
        case "$_c" in
            1) _ssh_disable ;;
            2) _ssh_enable ;;
            3) _ssh_nuke ;;
            4) _ssh_kill_sess ;;
            5) _ssh_harden ;;
            6) _ssh_status ;;
            7) _ssh_recover_nuke ;;
            0) return ;;
        esac
    done
}

_ssh_status() {
    printf "\n"
    msg_in "Active SSH sessions:"
    who 2>/dev/null | grep -i "pts\|ssh" || printf "  None\n"
    printf "\n"
    msg_in "Key sshd_config entries:"
    [ -f "$_SSHD_CONF" ] && \
        grep -E "^(Port|PermitRootLogin|PasswordAuthentication|AllowUsers|DenyUsers|ListenAddress)" \
            "$_SSHD_CONF" 2>/dev/null | while read _l; do printf "  %s\n" "$_l"; done \
        || msg_wn "sshd_config not found"
    press_enter
}

_ssh_disable() {
    printf "\n"
    # Back up config before touching anything
    [ -f "$_SSHD_CONF" ] && cp "$_SSHD_CONF" "$_SSHD_BAK" && msg_ok "sshd_config backed up to: $_SSHD_BAK"

    # Kill the daemon directly — pfSense rc.d 'stop' requires sshd_enable=YES in rc.conf
    # and will print the warning you saw. We bypass it entirely.
    pkill -TERM sshd 2>/dev/null
    sleep 1
    pkill -KILL sshd 2>/dev/null

    pgrep sshd >/dev/null 2>&1 && msg_fl "sshd still running!" || msg_ok "sshd process stopped"

    # Tell pfSense's config system SSH is off so it won't restart on rc.reload
    if [ -f /cf/conf/config.xml ]; then
        # pfSense marks SSH enabled with <enablesshd/> or <sshd_enable>enabled</sshd_enable>
        sed -i.bak \
            -e 's|<enablesshd/>||g' \
            -e 's|<enablesshd></enablesshd>||g' \
            -e 's|<sshd_enable>enabled</sshd_enable>||g' \
            /cf/conf/config.xml 2>/dev/null \
            && msg_ok "SSH disabled in config.xml (will not restart on reload)"
    fi

    # Also disable in rc.conf so rc.d agrees
    if [ -f /etc/rc.conf ]; then
        sed -i.bak 's/sshd_enable="YES"/sshd_enable="NO"/' /etc/rc.conf 2>/dev/null
        grep -q 'sshd_enable' /etc/rc.conf || printf 'sshd_enable="NO"\n' >> /etc/rc.conf
        msg_ok "sshd_enable set to NO in /etc/rc.conf"
    fi

    log "SSH DISABLED"
    press_enter
}

_ssh_enable() {
    printf "\n"

    # 1. Restore sshd_config if it was wiped/missing
    if [ ! -f "$_SSHD_CONF" ] || [ ! -s "$_SSHD_CONF" ] || \
       grep -q "DISABLED BY THREAT HUNTER" "$_SSHD_CONF" 2>/dev/null; then
        if [ -f "$_SSHD_BAK" ] && [ -s "$_SSHD_BAK" ]; then
            cp "$_SSHD_BAK" "$_SSHD_CONF" && msg_ok "Restored sshd_config from backup"
        else
            msg_in "No backup found — writing a safe default sshd_config..."
            cat > "$_SSHD_CONF" << 'SSHD_DEFAULT'
# sshd_config restored by pfSense Threat Hunter
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
LoginGraceTime 30
PermitRootLogin no
MaxAuthTries 3
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/sftp-server
SSHD_DEFAULT
            msg_ok "Default sshd_config written"
        fi
    else
        msg_ok "sshd_config already present"
    fi

    # 2. Regenerate missing host keys
    if ! ls /etc/ssh/ssh_host_* >/dev/null 2>&1; then
        msg_in "Host keys missing — regenerating..."
        ssh-keygen -A 2>/dev/null && msg_ok "Host keys regenerated" \
            || msg_fl "ssh-keygen failed — sshd may not start"
    else
        msg_ok "Host keys present"
    fi

    # 3. Set sshd_enable=YES in rc.conf so rc.d is happy
    if [ -f /etc/rc.conf ]; then
        if grep -q 'sshd_enable' /etc/rc.conf; then
            sed -i.bak 's/sshd_enable="NO"/sshd_enable="YES"/' /etc/rc.conf
        else
            printf 'sshd_enable="YES"\n' >> /etc/rc.conf
        fi
        msg_ok "sshd_enable set to YES in /etc/rc.conf"
    fi

    # 4. Mark SSH enabled in pfSense config.xml
    if [ -f /cf/conf/config.xml ]; then
        # Only add if not already present
        grep -q '<enablesshd' /cf/conf/config.xml 2>/dev/null || \
            sed -i.bak 's|<system>|<system><enablesshd/>|' /cf/conf/config.xml 2>/dev/null \
            && msg_ok "SSH enabled in config.xml"
    fi

    # 5. Remove any pf block rule from nuke
    pfctl -a hunter/ssh -F rules 2>/dev/null && msg_ok "Removed pf block rule on port 22" \
        || msg_in "No hunter pf rule found (or pfctl unavailable)"

    # 6. Start sshd — use 'onestart' which works regardless of rc.conf state
    if [ -f /etc/rc.d/sshd ]; then
        /etc/rc.d/sshd onestart 2>/dev/null && msg_ok "sshd started (onestart)" \
            || {
                msg_wn "rc.d onestart failed — trying direct launch..."
                /usr/sbin/sshd 2>/dev/null && msg_ok "sshd started directly" \
                    || msg_fl "Could not start sshd — check /var/log/auth.log"
            }
    else
        /usr/sbin/sshd 2>/dev/null && msg_ok "sshd started" \
            || msg_fl "Could not start sshd"
    fi

    sleep 1
    pgrep sshd >/dev/null 2>&1 && msg_ok "sshd is running" || msg_fl "sshd does not appear to be running"
    log "SSH ENABLED"
    press_enter
}

_ssh_nuke() {
    printf "\n"
    msg_wn "NUKE SSH will:"
    msg_wn "  - Kill all SSH processes"
    msg_wn "  - Remove ALL authorized_keys files on the system"
    msg_wn "  - Delete SSH host keys"
    msg_wn "  - Wipe sshd_config"
    msg_wn "  - Block port 22 via pf"
    printf "\n"
    msg_wn "A BACKUP will be saved so you can recover with option 7."
    printf "\n"
    confirm "This is destructive. Are you sure?" || return
    confirm "FINAL CONFIRMATION - Nuke SSH completely?" || return

    # Save full recovery backup before destroying anything
    _nuke_bk="$BACKUP_DIR/nuke_recovery_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$_nuke_bk/authkeys" "$_nuke_bk/hostkeys"

    [ -f "$_SSHD_CONF" ] && cp "$_SSHD_CONF" "$_nuke_bk/sshd_config.bak"
    cp /etc/ssh/ssh_host_* "$_nuke_bk/hostkeys/" 2>/dev/null
    find / -name "authorized_keys" -not -path "/proc/*" 2>/dev/null | while read _f; do
        _safe="$(echo "$_f" | tr '/' '_')"
        cp "$_f" "$_nuke_bk/authkeys/${_safe}" 2>/dev/null
    done
    msg_ok "Recovery backup saved to: $_nuke_bk"
    printf "  (Use option 7 'Recover from nuke' to restore)\n\n"

    pkill -9 sshd 2>/dev/null; pkill -9 ssh 2>/dev/null
    msg_ok "SSH processes killed"

    find / -name "authorized_keys" -not -path "/proc/*" 2>/dev/null | while read _f; do
        rm -f "$_f" && msg_wn "Removed: $_f"
    done
    msg_ok "All authorized_keys files removed"

    rm -f /etc/ssh/ssh_host_* 2>/dev/null && msg_ok "Host keys removed"
    printf "# DISABLED BY THREAT HUNTER - use rc.hunter SSH recover to restore\n" \
        > "$_SSHD_CONF" && msg_ok "sshd_config cleared"

    # Disable in rc.conf
    [ -f /etc/rc.conf ] && \
        sed -i.bak 's/sshd_enable="YES"/sshd_enable="NO"/' /etc/rc.conf 2>/dev/null

    printf "block quick proto tcp from any to any port 22\n" | \
        pfctl -a hunter/ssh -f - 2>/dev/null && msg_ok "pf block rule added on port 22" \
        || msg_wn "Could not add pf rule (pfctl unavailable?)"

    # Leave a pointer file so recover option can find the backup
    printf "%s\n" "$_nuke_bk" > "$BACKUP_DIR/.last_nuke"

    log "SSH NUKED - backup at $_nuke_bk"
    msg_ok "SSH nuked. Recovery backup at: $_nuke_bk"
    press_enter
}

_ssh_recover_nuke() {
    printf "\n"
    printf "  ${B}=== SSH Nuke Recovery ===${N}\n\n"

    # Find the most recent nuke backup
    _nuke_bk=""
    [ -f "$BACKUP_DIR/.last_nuke" ] && _nuke_bk="$(cat "$BACKUP_DIR/.last_nuke" 2>/dev/null)"

    if [ -z "$_nuke_bk" ] || [ ! -d "$_nuke_bk" ]; then
        # Try to find one manually
        _nuke_bk="$(ls -dt "$BACKUP_DIR"/nuke_recovery_* 2>/dev/null | head -1)"
    fi

    if [ -z "$_nuke_bk" ] || [ ! -d "$_nuke_bk" ]; then
        msg_fl "No nuke recovery backup found in $BACKUP_DIR"
        msg_in "You will need to re-enable SSH manually or use option 2 (Enable SSH)"
        msg_in "to build a fresh config and regenerate host keys."
        press_enter; return
    fi

    msg_ok "Found nuke backup: $(basename $_nuke_bk)"
    msg_in "Contents:"
    ls -lh "$_nuke_bk/" 2>/dev/null | while read _l; do printf "  %s\n" "$_l"; done
    printf "\n"
    confirm "Restore SSH from this backup?" || return

    # Remove pf block rule first
    pfctl -a hunter/ssh -F rules 2>/dev/null && msg_ok "Removed pf block rule" \
        || msg_in "No hunter pf rule found"

    # Restore sshd_config
    if [ -f "$_nuke_bk/sshd_config.bak" ]; then
        cp "$_nuke_bk/sshd_config.bak" "$_SSHD_CONF" && msg_ok "Restored sshd_config"
    else
        msg_wn "No sshd_config in backup — will generate default on enable"
    fi

    # Restore host keys
    if ls "$_nuke_bk/hostkeys"/ssh_host_* >/dev/null 2>&1; then
        cp "$_nuke_bk/hostkeys"/ssh_host_* /etc/ssh/ 2>/dev/null \
            && chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null \
            && chmod 644 /etc/ssh/ssh_host_*_key.pub 2>/dev/null \
            && msg_ok "Host keys restored"
    else
        msg_in "No host keys in backup — regenerating..."
        ssh-keygen -A 2>/dev/null && msg_ok "Host keys regenerated"
    fi

    # Restore authorized_keys (prompt per file)
    if ls "$_nuke_bk/authkeys/"* >/dev/null 2>&1; then
        printf "\n"
        msg_in "Backed-up authorized_keys files found:"
        for _f in "$_nuke_bk/authkeys/"*; do
            _orig_path="$(basename "$_f" | tr '_' '/')"
            printf "  %s -> %s\n" "$(basename $_f)" "$_orig_path"
        done
        confirm "Restore all authorized_keys files to their original locations?" && \
        for _f in "$_nuke_bk/authkeys/"*; do
            # Convert the safe filename back to a path
            _orig="$(basename "$_f" | sed 's|^_||' | tr '_' '/')"
            _orig="/${_orig}"
            mkdir -p "$(dirname "$_orig")" 2>/dev/null
            cp "$_f" "$_orig" 2>/dev/null && msg_ok "Restored: $_orig" || msg_fl "Failed: $_orig"
        done || msg_in "Skipped authorized_keys restore"
    fi

    # Re-enable and start
    _ssh_enable
    log "SSH RECOVERED FROM NUKE - backup: $_nuke_bk"
}

_ssh_kill_sess() {
    printf "\n"
    who 2>/dev/null
    printf "\n"
    ps aux 2>/dev/null | grep "sshd:" | grep -v grep
    printf "\n  Enter PID(s) to kill (ENTER to cancel): "
    read _pids; [ -z "$_pids" ] && return
    for _pid in $_pids; do
        echo "$_pid" | grep -qE '^[0-9]+$' || { msg_wn "Invalid PID: $_pid"; continue; }
        confirm "Kill session PID $_pid?" && kill -9 "$_pid" 2>/dev/null && \
            msg_ok "Killed $_pid" || msg_wn "Failed: $_pid"
        log "KILLED SSH PID: $_pid"
    done
    press_enter
}

_ssh_harden() {
    printf "\n"
    [ -f "$_SSHD_CONF" ] || { msg_fl "sshd_config not found"; press_enter; return; }
    cp "$_SSHD_CONF" "$_SSHD_CONF.pre_harden"
    cat >> "$_SSHD_CONF" << 'HARDEN'

# == pfSense Threat Hunter hardening ==
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
AllowTcpForwarding no
HARDEN
    msg_ok "Hardening directives appended to sshd_config"
    log "SSH HARDENED"
    press_enter
}


mod_ssh
