#!/bin/sh
# =============================================================================
# restore_config.sh - pfSense Threat Hunter: Config Restore Module
#
# Applies a known-good config.xml from a clean pfSense installation.
# Validates the file before applying, backs up the current config first,
# then reloads pfSense to apply the new configuration.
#
# Run standalone: sh restore_config.sh
# =============================================================================
SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "$0")" && pwd)}"
. "$SCRIPT_DIR/lib_shared.sh"

_CONFIG_DEST="/cf/conf/config.xml"
_CONFIG_BAK_DIR="$BACKUP_DIR/config_backups"
_SEARCH_PATHS="
/tmp
/root
/mnt
/usr/home
$SCRIPT_DIR/../Resources
"

# =============================================================================
# Validate that a file looks like a real pfSense config.xml
# =============================================================================
_validate_config() {
    _f="$1"
    [ -f "$_f" ] || return 1

    # Must not be empty
    [ -s "$_f" ] || return 1

    # Must contain pfSense XML root element
    grep -q "<pfsense>" "$_f" 2>/dev/null || return 1
    grep -q "</pfsense>" "$_f" 2>/dev/null || return 1

    # Must have a version element
    grep -q "<version>" "$_f" 2>/dev/null || return 1

    # Must have interfaces section
    grep -q "<interfaces>" "$_f" 2>/dev/null || return 1

    return 0
}

# =============================================================================
# Show a summary of what's in a config.xml
# =============================================================================
_summarise_config() {
    _f="$1"

    _ver="$(grep -o '<version>[^<]*</version>' "$_f" 2>/dev/null | \
        sed 's/<[^>]*>//g' | head -1)"
    _hostname="$(grep -o '<hostname>[^<]*</hostname>' "$_f" 2>/dev/null | \
        sed 's/<[^>]*>//g' | head -1)"
    _domain="$(grep -o '<domain>[^<]*</domain>' "$_f" 2>/dev/null | \
        sed 's/<[^>]*>//g' | head -1)"
    _users="$(grep -c '<user>' "$_f" 2>/dev/null)"
    _ifaces="$(grep -c '<interface>' "$_f" 2>/dev/null)"
    _rules="$(grep -c '<rule>' "$_f" 2>/dev/null)"
    _filesize="$(ls -lh "$_f" 2>/dev/null | awk '{print $5}')"

    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  Config Summary${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  File       : %s\n" "$_f"
    printf "  Size       : %s\n" "${_filesize:-(unknown)}"
    printf "  Version    : %s\n" "${_ver:-(not found)}"
    printf "  Hostname   : %s\n" "${_hostname:-(not found)}"
    printf "  Domain     : %s\n" "${_domain:-(not found)}"
    printf "  Users      : %s\n" "${_users:-0}"
    printf "  Interfaces : %s\n" "${_ifaces:-0}"
    printf "  Rules      : %s\n" "${_rules:-0}"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
}

# =============================================================================
# Find config.xml files on the filesystem
# =============================================================================
_find_configs() {
    printf "\n"
    msg_in "Searching for config.xml files..."
    printf "\n"

    _found_list=""
    _idx=1

    # Search known locations first
    for _dir in $_SEARCH_PATHS; do
        [ -d "$_dir" ] || continue
        find "$_dir" -maxdepth 3 -name "config.xml" -o -name "*.xml" 2>/dev/null | \
        while read _f; do
            _validate_config "$_f" || continue
            printf "  ${W}%d)${N} %s\n" "$_idx" "$_f"
            _idx=$((_idx+1))
        done
    done

    # Also search USB mount points
    for _mp in /media /mnt /dev/da*; do
        [ -d "$_mp" ] || continue
        find "$_mp" -maxdepth 4 -name "config.xml" 2>/dev/null | \
        while read _f; do
            _validate_config "$_f" || continue
            printf "  ${W}%d)${N} %s  ${Y}(USB/external)${N}\n" "$_idx" "$_f"
            _idx=$((_idx+1))
        done
    done
}

# =============================================================================
# Core restore function
# =============================================================================
_do_restore() {
    _src="$1"

    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  Config Restore${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"

    # Validate source
    msg_in "Validating config file..."
    if _validate_config "$_src"; then
        msg_ok "File is a valid pfSense config.xml"
    else
        msg_fl "File failed validation — not a valid pfSense config.xml"
        msg_in "Checks: non-empty, contains <pfsense>, <version>, <interfaces>"
        press_enter
        return 1
    fi

    # Show summary
    _summarise_config "$_src"

    # Confirm
    printf "\n"
    msg_wn "This will REPLACE the current running config with the selected file."
    msg_wn "pfSense will be reloaded and some settings may change immediately."
    confirm "Apply this config.xml to pfSense?" || { msg_in "Cancelled."; return; }

    # Step 1: Backup current config
    printf "\n"
    msg_in "Backing up current config..."
    mkdir -p "$_CONFIG_BAK_DIR"
    _bak="$_CONFIG_BAK_DIR/config_$(date +%Y%m%d_%H%M%S).xml"
    if [ -f "$_CONFIG_DEST" ]; then
        cp -p "$_CONFIG_DEST" "$_bak" \
            && msg_ok "Current config backed up to: $_bak" \
            || { msg_fl "Could not back up current config — aborting"; press_enter; return 1; }
    else
        msg_wn "No existing config found at $_CONFIG_DEST — nothing to back up"
    fi

    # Step 2: Copy new config into place
    msg_in "Copying new config to $_CONFIG_DEST ..."
    cp "$_src" "$_CONFIG_DEST" \
        && msg_ok "Config file copied" \
        || { msg_fl "Failed to copy config — restoring backup"; cp "$_bak" "$_CONFIG_DEST"; press_enter; return 1; }

    # Step 3: Set correct ownership and permissions
    chown root:wheel "$_CONFIG_DEST" 2>/dev/null
    chmod 644 "$_CONFIG_DEST" 2>/dev/null
    msg_ok "Permissions set: root:wheel 644"

    # Step 4: Sync to disk (pfSense uses /cf for config partition)
    sync 2>/dev/null
    msg_ok "Synced to disk"

    # Step 5: Reload pfSense configuration
    printf "\n"
    msg_in "Reloading pfSense configuration..."

    if [ -x /etc/rc.reload_all ]; then
        /etc/rc.reload_all 2>/dev/null && msg_ok "rc.reload_all complete" \
            || msg_wn "rc.reload_all returned errors (may be normal)"
    fi

    # Reload config via pfSense's own mechanism
    if [ -x /usr/local/sbin/pfSsh.php ]; then
        printf "require_once('config.inc'); parse_config(true);" | \
            /usr/local/sbin/pfSsh.php 2>/dev/null \
            && msg_ok "pfSense config reloaded via pfSsh.php" \
            || msg_in "pfSsh.php reload skipped (non-critical)"
    fi

    # Restart web GUI so new config takes effect in browser
    if [ -x /usr/local/sbin/pfSsh.php ]; then
        /usr/local/sbin/pfSsh.php playback svc restart webgui 2>/dev/null \
            && msg_ok "Web GUI restarted" \
            || msg_in "Web GUI restart skipped"
    fi

    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    msg_ok "Config restore complete."
    msg_in "Backup of old config: $_bak"
    msg_wn "You may need to reconnect — IP addresses or interfaces may have changed."
    msg_in "If the system is unresponsive, restore the backup:"
    printf "  cp %s %s\n" "$_bak" "$_CONFIG_DEST"
    printf "  /etc/rc.reload_all\n"
    log "CONFIG RESTORED: src=$_src bak=$_bak"
    press_enter
}

# =============================================================================
# Main menu
# =============================================================================
mod_config_restore() {
    while true; do
        draw_screen
        printf "\n"
        printf "  ${B}Config Restore${N}\n"
        divider
        printf "  ${B}1)${N}  Search for config.xml files on this system\n"
        printf "  ${B}2)${N}  Enter path to config.xml manually\n"
        printf "  ${B}3)${N}  View current config.xml summary\n"
        printf "  ${B}4)${N}  List previous config backups\n"
        printf "  ${B}5)${N}  Restore a previous backup\n"
        printf "  ${B}0)${N}  Back\n"
        printf "\n"
        printf "  Enter an option: "
        read _c
        case "$_c" in
            1) _config_from_search ;;
            2) _config_from_path ;;
            3) _view_current ;;
            4) _list_backups ;;
            5) _restore_backup ;;
            0) return ;;
        esac
    done
}

_config_from_search() {
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  Find Config Files${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    msg_in "Searching common locations and USB mounts..."
    msg_in "To load a config from USB: plug in your drive before searching."
    printf "\n"

    # Build indexed list
    _idx=1
    _found=""
    for _dir in $_SEARCH_PATHS /media /mnt; do
        [ -d "$_dir" ] || continue
        for _f in $(find "$_dir" -maxdepth 4 \( -name "config.xml" -o -name "*.xml" \) 2>/dev/null); do
            _validate_config "$_f" || continue
            printf "  ${W}%d)${N} %s\n" "$_idx" "$_f"
            _found="${_found}${_f}\n"
            _idx=$((_idx+1))
        done
    done

    _total=$((_idx-1))
    if [ "$_total" -eq 0 ]; then
        msg_in "No valid config.xml files found."
        msg_in "Copy your config.xml to /tmp/ or /root/ then search again."
        msg_in "Or use option 2 to enter a path manually."
        press_enter; return
    fi

    printf "\n"
    printf "  Found %d valid config file(s).\n" "$_total"
    printf "  Select number to preview and apply (0 to cancel): "
    read _sel
    [ "$_sel" = "0" ] || [ -z "$_sel" ] && return

    _chosen="$(printf "%b" "$_found" | sed -n "${_sel}p")"
    [ -z "$_chosen" ] && msg_wn "Invalid selection" && press_enter && return

    _do_restore "$_chosen"
}

_config_from_path() {
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  Enter Config Path${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "\n"
    msg_in "Common locations to copy your config.xml to first:"
    printf "  scp config.xml admin@<pfsense-ip>:/tmp/config.xml\n"
    printf "  (or paste to USB and plug in)\n"
    printf "\n"
    printf "  Enter full path to config.xml (ENTER to cancel): "
    read _path
    [ -z "$_path" ] && return

    if [ ! -f "$_path" ]; then
        msg_fl "File not found: $_path"
        press_enter; return
    fi

    _do_restore "$_path"
}

_view_current() {
    printf "\n"
    if [ -f "$_CONFIG_DEST" ]; then
        msg_ok "Current config: $_CONFIG_DEST"
        _summarise_config "$_CONFIG_DEST"
    else
        msg_fl "No config found at $_CONFIG_DEST"
    fi
    press_enter
}

_list_backups() {
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  Config Backups${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n\n"
    mkdir -p "$_CONFIG_BAK_DIR"
    _baks="$(ls -t "$_CONFIG_BAK_DIR"/*.xml 2>/dev/null)"
    if [ -z "$_baks" ]; then
        msg_in "No backups found in $_CONFIG_BAK_DIR"
        press_enter; return
    fi
    _i=1
    for _b in $_baks; do
        _sz="$(ls -lh "$_b" 2>/dev/null | awk '{print $5}')"
        printf "  %d) %-45s %s\n" "$_i" "$(basename $_b)" "$_sz"
        _i=$((_i+1))
    done
    press_enter
}

_restore_backup() {
    printf "\n"
    mkdir -p "$_CONFIG_BAK_DIR"
    _baks="$(ls -t "$_CONFIG_BAK_DIR"/*.xml 2>/dev/null)"
    if [ -z "$_baks" ]; then
        msg_in "No backups found in $_CONFIG_BAK_DIR"
        press_enter; return
    fi

    printf "  ${B}  Available Backups${N}\n"
    divider
    _i=1
    for _b in $_baks; do
        printf "  ${W}%d)${N} %s\n" "$_i" "$(basename $_b)"
        _i=$((_i+1))
    done
    printf "\n  Select backup to restore (0 to cancel): "
    read _sel
    [ "$_sel" = "0" ] || [ -z "$_sel" ] && return

    _chosen="$(echo "$_baks" | sed -n "${_sel}p")"
    [ -z "$_chosen" ] && msg_wn "Invalid selection" && press_enter && return

    _do_restore "$_chosen"
}

mod_config_restore
