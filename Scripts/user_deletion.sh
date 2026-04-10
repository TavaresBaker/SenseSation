#!/bin/sh
# =============================================================================
# user_deletion.sh - pfSense Threat Hunter: User Hunter Module
# Detects and removes malicious/hidden users from pfSense
# Run standalone: sh user_deletion.sh
# =============================================================================
SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "$0")" && pwd)}"
. "$SCRIPT_DIR/lib_shared.sh"
_USER_XML="/conf/config.xml"
_USER_BACKUP_XML="/conf/config.xml.bak"
_DEFAULT_USERS="admin root toor"
_USER_DIRS="/home /usr/local/etc"

# Pull a value from config.xml using xmllint if available, else grep fallback
_xml_get_users() {
    if command -v xmllint >/dev/null 2>&1 && [ -f "$_USER_XML" ]; then
        xmllint --xpath '//user/name/text()' "$_USER_XML" 2>/dev/null | tr ' ' '\n'
    else
        # Fallback: grep names out of config.xml
        grep -o '<name>[^<]*</name>' "$_USER_XML" 2>/dev/null \
            | sed 's/<name>//;s/<\/name>//'
    fi
}

_xml_get_field() {
    # _xml_get_field <username> <field>
    _xuser="$1"; _xfield="$2"
    if command -v xmllint >/dev/null 2>&1 && [ -f "$_USER_XML" ]; then
        xmllint --xpath \
            "string(//user[name='$_xuser']/$_xfield)" \
            "$_USER_XML" 2>/dev/null
    else
        # Crude grep fallback — good enough for descr/groupname
        awk "/<name>$_xuser<\/name>/{f=1} f && /<$_xfield>/{gsub(/.*<$_xfield>|<\/$_xfield>.*/,\"\"); print; f=0}" \
            "$_USER_XML" 2>/dev/null | head -1
    fi
}

mod_users() {
    while true; do
        draw_screen
        printf "\n"
        printf "  ${B}User Hunter${N}\n"
        divider
        printf "  ${B}1)${N}  Show non-default pfSense users (from config.xml)\n"
        printf "  ${B}2)${N}  Show all system accounts (from /etc/passwd)\n"
        printf "  ${B}3)${N}  Find hidden / suspicious accounts\n"
        printf "  ${B}4)${N}  Delete user(s) by number\n"
        printf "  ${B}5)${N}  Full audit (all of the above)\n"
        printf "  ${B}0)${N}  Back\n"
        printf "\n"
        printf "  Enter an option: "
        read _c
        case "$_c" in
            1) _u_report ;;
            2) _u_passwd_list ;;
            3) _u_hidden ;;
            4) _u_delete ;;
            5) _u_report; _u_passwd_list; _u_hidden ;;
            0) return ;;
        esac
    done
}

# ------------------------------------------------------------------------------
# Option 1 — Numbered pfSense user report from config.xml
# ------------------------------------------------------------------------------
_u_report() {
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  pfSense Non-Default Users Report${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "\n"

    if [ ! -f "$_USER_XML" ]; then
        msg_wn "config.xml not found at $_USER_XML"
        msg_in "Falling back to /etc/passwd listing..."
        _u_passwd_list
        return
    fi

    _ALL_USERS="$(_xml_get_users)"
    _USER_LIST=""
    _INDEX=1

    for _user in $_ALL_USERS; do
        # Skip default/protected accounts
        echo "$_DEFAULT_USERS" | grep -qw "$_user" && continue

        _groups="$(_xml_get_field "$_user" "groups/item")"
        [ -z "$_groups" ] && _groups="(none)"

        _desc="$(_xml_get_field "$_user" "descr")"
        [ -z "$_desc" ] && _desc="(no description)"

        # Pull passwd info for extra context
        _passwd_line="$(grep "^$_user:" /etc/passwd 2>/dev/null)"
        _uid="$(echo "$_passwd_line" | cut -d: -f3)"
        _shell="$(echo "$_passwd_line" | cut -d: -f7)"
        _uid="${_uid:--}"
        _shell="${_shell:--}"

        # Suspicion flags
        _flags=""
        [ "$_uid" != "-" ] && [ "$_uid" -eq 0 ] 2>/dev/null \
            && _flags="${_flags}${R}[UID-0!]${N} "
        echo "$_shell" | grep -qE "(nologin|false)$" \
            || _flags="${_flags}${Y}[HAS SHELL]${N} "

        printf "  ${W}%d)${N} Username    : ${W}%s${N}\n" "$_INDEX" "$_user"
        printf "     UID         : %s\n" "$_uid"
        printf "     Groups      : %s\n" "$_groups"
        printf "     Description : %s\n" "$_desc"
        printf "     Shell       : %s\n" "$_shell"
        [ -n "$_flags" ] && printf "     Flags       : %b\n" "$_flags"
        printf "\n"

        _USER_LIST="${_USER_LIST}${_user} "
        _INDEX=$((_INDEX + 1))
    done

    _TOTAL_NON_DEFAULT=$((_INDEX - 1))

    if [ "$_TOTAL_NON_DEFAULT" -eq 0 ]; then
        msg_ok "No non-default users found."
    else
        printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
        printf "  Total non-default users: ${W}%d${N}\n" "$_TOTAL_NON_DEFAULT"
        printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    fi

    log "USER REPORT: $_TOTAL_NON_DEFAULT non-default users found"
    press_enter
}

# ------------------------------------------------------------------------------
# Option 2 — All system accounts from /etc/passwd
# ------------------------------------------------------------------------------
_u_passwd_list() {
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  All System Accounts (/etc/passwd)${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "\n"
    printf "  ${B}  %-20s %-6s %-6s %-20s %s${N}\n" "USERNAME" "UID" "GID" "SHELL" "FLAGS"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"

    while IFS=: read -r _un _ _uid _gid _ _home _sh; do
        _flags=""
        # UID-0 that isn't root/toor
        [ "$_uid" -eq 0 ] 2>/dev/null && [ "$_un" != "root" ] && [ "$_un" != "toor" ] \
            && _flags="${_flags}${R}[UID-0!]${N} "
        # Has a real shell
        echo "$_sh" | grep -qvE "(nologin|false|^$)" \
            && _flags="${_flags}${Y}[SHELL]${N} "
        # High UID (local user)
        [ "$_uid" -gt 999 ] 2>/dev/null \
            && _flags="${_flags}${C}[LOCAL]${N} "
        # Home is /
        [ "$_home" = "/" ] \
            && _flags="${_flags}${Y}[ROOTHOME]${N} "

        printf "  %-20s %-6s %-6s %-20s %b\n" \
            "$_un" "$_uid" "$_gid" "$_sh" "${_flags:--}"
    done < /etc/passwd
    printf "\n"
    press_enter
}

# ------------------------------------------------------------------------------
# Option 3 — Hidden / suspicious account checks
# ------------------------------------------------------------------------------
_u_hidden() {
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  Hidden and Suspicious Account Checks${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "\n"

    msg_in "Checking for non-root UID-0 accounts..."
    _found=0
    awk -F: '($3==0 && $1!="root" && $1!="toor"){print $1}' /etc/passwd | \
        while read _u; do
            msg_wn "UID-0 ACCOUNT DETECTED: $_u"
            log "ALERT UID0: $_u"
            _found=1
        done
    [ "$_found" -eq 0 ] && msg_ok "None found"

    printf "\n"
    msg_in "Checking for low-UID system accounts with a login shell..."
    _found=0
    while IFS=: read -r _un _ _uid _ _ _ _sh; do
        echo "$_sh" | grep -qE "(nologin|false|^$)" && continue
        [ "$_uid" -lt 1000 ] 2>/dev/null || continue
        echo "$_un" | grep -qE "^(root|toor)$" && continue
        msg_wn "Low-UID with shell: $_un (UID $_uid, shell: $_sh)"
        log "ALERT LOW-UID SHELL: $_un"
        _found=1
    done < /etc/passwd
    [ "$_found" -eq 0 ] && msg_ok "None found"

    printf "\n"
    msg_in "Checking master.passwd for ghost entries..."
    _found=0
    if [ -f /etc/master.passwd ]; then
        while IFS=: read -r _un _; do
            grep -q "^$_un:" /etc/passwd || {
                msg_wn "Ghost entry (in master.passwd, not in passwd): $_un"
                log "ALERT GHOST: $_un"
                _found=1
            }
        done < /etc/master.passwd
    fi
    [ "$_found" -eq 0 ] && msg_ok "None found"

    printf "\n"
    msg_in "Wheel / admin group members..."
    _wh="$(grep '^wheel:' /etc/group 2>/dev/null | cut -d: -f4)"
    printf "  Members: ${W}%s${N}\n" "${_wh:-none}"
    log "Wheel members: $_wh"

    printf "\n"
    msg_in "Scanning filesystem for authorized_keys files..."
    _found=0
    find / -name "authorized_keys" -not -path "/proc/*" 2>/dev/null | while read _f; do
        msg_wn "Found: $_f"
        _kcount="$(wc -l < "$_f" 2>/dev/null)"
        printf "        Keys in file: %s\n" "${_kcount:-unknown}"
        log "AUTHKEYS: $_f"
        _found=1
    done
    [ "$_found" -eq 0 ] && msg_ok "No authorized_keys files found"

    printf "\n"
    msg_in "Recent login history (last 15 entries):"
    printf "\n"
    last 2>/dev/null | head -15 || who -a 2>/dev/null | head -15

    press_enter
}

# ------------------------------------------------------------------------------
# Option 4 — Delete users by number (matches style of reference script)
# ------------------------------------------------------------------------------
_u_delete() {
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  User Deletion${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "\n"

    # Build the numbered list from config.xml (non-default users)
    if [ ! -f "$_USER_XML" ]; then
        msg_wn "config.xml not found — falling back to /etc/passwd non-system users"
    fi

    _ALL_USERS="$(_xml_get_users 2>/dev/null)"
    # Fallback: if XML gives nothing, use passwd
    if [ -z "$_ALL_USERS" ]; then
        _ALL_USERS="$(awk -F: '$3>=1000 && $1!="nobody"{print $1}' /etc/passwd 2>/dev/null)"
    fi

    _USER_LIST=""
    _INDEX=1

    printf "  Found users:\n\n"

    for _user in $_ALL_USERS; do
        echo "$_DEFAULT_USERS" | grep -qw "$_user" && continue

        _groups="$(_xml_get_field "$_user" "groups/item")"
        [ -z "$_groups" ] && _groups="$(groups "$_user" 2>/dev/null | cut -d: -f2 | xargs)"
        [ -z "$_groups" ] && _groups="(none)"

        _desc="$(_xml_get_field "$_user" "descr")"
        [ -z "$_desc" ] && _desc="(no description)"

        printf "  ${W}%d)${N} Username    : ${W}%s${N}\n" "$_INDEX" "$_user"
        printf "     Groups      : %s\n" "$_groups"
        printf "     Description : %s\n" "$_desc"
        printf "\n"

        _USER_LIST="${_USER_LIST}${_user} "
        _INDEX=$((_INDEX + 1))
    done

    _TOTAL=$((_INDEX - 1))

    if [ "$_TOTAL" -eq 0 ]; then
        msg_ok "No deletable users found."
        press_enter; return
    fi

    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  Enter user number(s) to delete:\n"
    printf "    Examples : ${W}1 3 5${N}  or  ${W}1,3,5${N}\n"
    printf "    Type     : ${W}all${N} to delete all listed users\n"
    printf "    Press ENTER to cancel\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  Selection: "
    read _sel

    [ -z "$_sel" ] && msg_in "No users selected." && press_enter && return

    # Normalize commas to spaces
    _sel="$(echo "$_sel" | tr ',' ' ' | tr -s ' ')"

    # Back up config.xml before any changes
    if [ -f "$_USER_XML" ]; then
        cp "$_USER_XML" "$_USER_BACKUP_XML" \
            && msg_ok "config.xml backed up to $_USER_BACKUP_XML" \
            || { msg_fl "Backup failed — aborting."; press_enter; return; }
    fi

    # Resolve selection to usernames
    _TO_DELETE=""
    if [ "$_sel" = "all" ]; then
        _TO_DELETE="$_USER_LIST"
    else
        for _n in $_sel; do
            echo "$_n" | grep -qE '^[0-9]+$' \
                || { msg_fl "Invalid input: '$_n' (must be a number or 'all')"; continue; }
            [ "$_n" -lt 1 ] || [ "$_n" -gt "$_TOTAL" ] 2>/dev/null \
                && { msg_fl "Out of range: $_n (valid: 1-$_TOTAL)"; continue; }
            _resolved="$(echo "$_USER_LIST" | tr ' ' '\n' | sed -n "${_n}p")"
            [ -z "$_resolved" ] && { msg_fl "Could not resolve user #$_n"; continue; }
            # Deduplicate
            echo "$_TO_DELETE" | grep -qw "$_resolved" \
                || _TO_DELETE="$_TO_DELETE $_resolved"
        done
    fi

    if [ -z "$(echo "$_TO_DELETE" | tr -d ' ')" ]; then
        msg_wn "No valid users resolved from selection."
        press_enter; return
    fi

    printf "\n"
    printf "  ${Y}  Selected for deletion:${N}\n"
    for _u in $_TO_DELETE; do
        printf "    - %s\n" "$_u"
    done
    printf "\n"

    confirm "Proceed with deletion of the above user(s)?" || {
        msg_in "Cancelled."
        press_enter; return
    }

    _FAIL=0

    for _u in $_TO_DELETE; do
        # Safety guard — never touch protected accounts
        echo "$_DEFAULT_USERS" | grep -qw "$_u" && {
            msg_wn "Skipping protected user: $_u"
            continue
        }

        printf "\n"
        msg_in "Removing user: $_u ..."

        # 1. Kill active processes
        pkill -9 -u "$_u" 2>/dev/null \
            && msg_ok "Killed active processes for $_u" \
            || msg_in "No active processes for $_u"

        # 2. Remove from config.xml using awk (same approach as reference)
        if [ -f "$_USER_XML" ]; then
            _TMP_XML="/tmp/config_del_$$.xml"
            _ESC_USER="$(printf '%s\n' "$_u" | sed 's/[][\.\*^$(){}?+|/]/\\&/g')"

            awk -v user="$_ESC_USER" '
                BEGIN { in_block=0; block="" }
                /<user>/ { in_block=1; block=$0 ORS; next }
                /<\/user>/ {
                    block = block $0 ORS
                    if (block ~ ("<name>" user "</name>")) {
                        in_block=0; block=""; next
                    } else {
                        printf "%s", block
                        in_block=0; block=""; next
                    }
                }
                { if (in_block) { block=block $0 ORS } else { print } }
            ' "$_USER_XML" > "$_TMP_XML" \
                && mv "$_TMP_XML" "$_USER_XML" \
                && msg_ok "Removed $_u from config.xml" \
                || { msg_fl "Failed to update config.xml for $_u"; rm -f "$_TMP_XML"; _FAIL=1; }
        fi

        # 3. Remove from /etc/passwd, master.passwd, group
        if command -v pw >/dev/null 2>&1; then
            pw userdel -n "$_u" -r 2>/dev/null \
                && msg_ok "Removed $_u via pw userdel" \
                || {
                    # pw may fail if user doesn't exist in passwd — not fatal
                    sed -i.bak "/^$_u:/d" /etc/passwd 2>/dev/null
                    sed -i.bak "/^$_u:/d" /etc/master.passwd 2>/dev/null
                    sed -i.bak "s/,$_u//g;s/$_u,//g;s/:$_u$/:/g" /etc/group 2>/dev/null
                    pwd_mkdb /etc/master.passwd 2>/dev/null
                    msg_ok "Removed $_u from passwd/group files"
                }
        else
            sed -i.bak "/^$_u:/d" /etc/passwd 2>/dev/null
            sed -i.bak "/^$_u:/d" /etc/master.passwd 2>/dev/null
            sed -i.bak "s/,$_u//g;s/$_u,//g;s/:$_u$/:/g" /etc/group 2>/dev/null
            pwd_mkdb /etc/master.passwd 2>/dev/null
            msg_ok "Removed $_u from passwd/group files"
        fi

        # 4. Remove home directories
        for _dir in $_USER_DIRS; do
            _ud="$_dir/$_u"
            if [ -d "$_ud" ]; then
                rm -rf "$_ud" && msg_ok "Removed directory: $_ud" \
                    || { msg_fl "Could not remove: $_ud"; _FAIL=1; }
            fi
        done

        msg_ok "User '$_u' removal complete."
        log "DELETED USER: $_u"
    done

    # Reload pfSense config
    printf "\n"
    msg_in "Reloading pfSense configuration..."
    /etc/rc.reload_all 2>/dev/null && msg_ok "Config reloaded" \
        || msg_wn "rc.reload_all not available — config may need manual reload"

    printf "\n"
    if [ "$_FAIL" -eq 0 ]; then
        msg_ok "All selected users removed successfully."
    else
        msg_wn "Some deletions encountered errors. Review output above."
        msg_in "Config backup is at: $_USER_BACKUP_XML"
    fi

    log "USER DELETION COMPLETE - failures: $_FAIL"
    press_enter
}


mod_users
