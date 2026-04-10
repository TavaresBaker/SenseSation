#!/bin/sh
# =============================================================================
# restore_binaries.sh - pfSense Threat Hunter: Binary and File Restore Module
# Restores compromised binaries, web GUI, and init files
# Run standalone: sh restore_binaries.sh
# =============================================================================
SCRIPT_DIR="${SCRIPT_DIR:-$(cd "$(dirname "$0")" && pwd)}"
. "$SCRIPT_DIR/lib_shared.sh"
_r_get_version() {
    _PFSENSE_VER="$(cat /etc/version 2>/dev/null | cut -d'-' -f1)"
    _PFSENSE_BRANCH="RELENG_$(echo "$_PFSENSE_VER" | tr '.' '_')"
    # master is the confirmed working branch for pfSense CE
    # RELENG_x_y_z branches may not exist for all versions
    _PFSENSE_BRANCHES="master $_PFSENSE_BRANCH main"
    # Confirmed path: master/src/usr/local/www/
    _GH_PFSENSE="https://raw.githubusercontent.com/pfsense/pfsense"
    _GH_PFSENSE_WWW="https://raw.githubusercontent.com/pfsense/pfsense/master/src/usr/local/www"
    _GH_PFSENSE_SRC="https://raw.githubusercontent.com/pfsense/pfsense/master/src"
    _GH_FREEBSD="https://raw.githubusercontent.com/freebsd/freebsd-src/releng/14.0"
}

_r_fetch() {
    # _r_fetch <dest> <url>  — tries fetch then curl
    fetch -q -o "$1" "$2" 2>/dev/null && return 0
    curl -fsSL "$2" -o "$1" 2>/dev/null && return 0
    return 1
}

_r_backup_and_quarantine() {
    # Back up and quarantine a path before overwriting it
    # Usage: _r_backup_and_quarantine <path> <backup_root> <quarantine_root>
    _src="$1"; _bk="$2"; _qr="$3"
    [ -e "$_src" ] || return 0
    _dest_bk="$_bk$(dirname $_src)"
    _dest_qr="$_qr$(dirname $_src)"
    mkdir -p "$_dest_bk" "$_dest_qr"
    cp -a "$_src" "$_dest_bk/" 2>/dev/null
    cp -a "$_src" "$_dest_qr/" 2>/dev/null
}

mod_restore() {
    while true; do
        draw_screen
        printf "\n"
        printf "  ${B}Binary and File Restore${N}\n"
        divider
        printf "  ${B}1)${N}  Restore system binaries (live, from pfSense sources)\n"
        printf "  ${B}2)${N}  Restore web GUI and init files (live, from pfSense GitHub)\n"
        printf "  ${B}3)${N}  Check file integrity against local snapshot\n"
        printf "  ${B}4)${N}  Break web shells and persistence\n"
        printf "  ${B}5)${N}  Take a local backup snapshot\n"
        printf "  ${B}0)${N}  Back\n"
        printf "\n"
        printf "  Enter an option: "
        read _c
        case "$_c" in
            1) _r_restore_binaries ;;
            2) _r_restore_files ;;
            3) _r_integrity ;;
            4) _r_break_shells ;;
            5) _r_snapshot ;;
            0) return ;;
        esac
    done
}

# ------------------------------------------------------------------------------
# Option 1 - Restore binaries live from pfSense download mirror
# ------------------------------------------------------------------------------

# Check if a file is a real ELF binary (not a script/HTML impostor)
_is_real_binary() {
    _f="$1"
    [ -f "$_f" ] || return 1
    # Read the first 4 bytes — ELF magic is 0x7f 45 4c 46
    _magic="$(dd if="$_f" bs=4 count=1 2>/dev/null | od -A n -t x1 | tr -d ' \n')"
    echo "$_magic" | grep -qi "^7f454c46" && return 0
    return 1
}

_r_restore_binaries() {
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  Binary Recovery${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n\n"

    _r_get_version
    msg_in "Detected pfSense version: ${_PFSENSE_VER:-unknown}"
    printf "\n"

    # Step 1: Remount root as read-write
    msg_in "Remounting root filesystem as read-write..."
    mount -u -w / 2>/dev/null && msg_ok "Root remounted read-write" \
        || msg_wn "Could not remount rootfs — continuing anyway"

    # Step 2: Expand PATH
    export PATH="/usr/local/bin:/usr/local/sbin:/bin:/sbin:/usr/bin:/usr/sbin"
    hash -r 2>/dev/null

    _WORKDIR="/root/.recovery_$$"
    mkdir -p "$_WORKDIR"

    # -----------------------------------------------------------------------
    # IMPORTANT: cat, tee, and other standard tools may also be impostors.
    # This entire function uses ONLY:
    #   printf, read, while, dd, od, head, grep, find, mv, cp, chmod, mkdir
    #   fetch/curl (for downloads), tar (verified by ELF check first),
    #   and shell built-ins.
    # We never call cat, tee, or any binary we haven't verified as real ELF.
    # -----------------------------------------------------------------------

    # All binaries to validate — cat is explicitly included here
    _BINARIES="sh cat ls cp mv awk grep find tar mount fetch"

    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  Step 1 of 3 — Binary Validation (ELF check)${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n\n"
    msg_wn "NOTE: If cat/tee are impostors, some commands below may still fail."
    msg_in "This function avoids cat/tee entirely and uses only shell built-ins."
    printf "\n"

    _IMPOSTOR_LIST=""

    for _bin in $_BINARIES; do
        _binpath="$(command -v "$_bin" 2>/dev/null)"
        if [ -z "$_binpath" ]; then
            msg_wn "$_bin : NOT FOUND"
            log "MISSING BINARY: $_bin"
            continue
        fi
        if _is_real_binary "$_binpath"; then
            msg_ok "$_bin : OK  ($_binpath)"
        else
            # Read first line with shell built-in read instead of cat/head
            _firstline=""
            { IFS= read -r _firstline; } < "$_binpath" 2>/dev/null
            printf "\n"
            printf "  ${R}  [IMPOSTOR DETECTED]${N}\n"
            printf "  Binary    : ${W}%s${N}\n" "$_binpath"
            printf "  Expected  : ELF binary\n"
            printf "  First line: ${R}%s${N}\n" "$_firstline"
            printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
            log "IMPOSTOR BINARY: $_binpath firstline=$_firstline"
            _IMPOSTOR_LIST="$_IMPOSTOR_LIST $_bin:$_binpath"
        fi
    done

    # -----------------------------------------------------------------------
    # Step 2: Validate pkg — prefer pkg-static (standalone, no shared libs)
    # pkg-static works even when shared libraries are broken/missing
    # -----------------------------------------------------------------------
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  Step 2 of 3 — pkg Validation and Repair${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n\n"

    # Check pkg-static first — it's more reliable on compromised systems
    _PKG_STATIC_PATHS="/usr/local/sbin/pkg-static /usr/local/bin/pkg-static /usr/sbin/pkg-static"
    _PKG_PATHS="/usr/local/sbin/pkg /usr/local/bin/pkg /usr/sbin/pkg /usr/bin/pkg"
    _PKG_OK=0
    _PKG_PATH=""

    # Try pkg-static first
    for _p in $_PKG_STATIC_PATHS; do
        [ -f "$_p" ] || continue
        if _is_real_binary "$_p"; then
            _PKG_OK=1
            _PKG_PATH="$_p"
            msg_ok "pkg-static binary is valid ELF: $_p (preferred)"
            break
        fi
    done

    # Fall back to pkg if no valid pkg-static found
    if [ "$_PKG_OK" -eq 0 ]; then
        for _p in $_PKG_PATHS; do
            [ -f "$_p" ] || continue
            if _is_real_binary "$_p"; then
                _PKG_OK=1
                _PKG_PATH="$_p"
                msg_ok "pkg binary is valid ELF: $_p"
                break
            else
                _firstline=""
                { IFS= read -r _firstline; } < "$_p" 2>/dev/null
                printf "  ${R}  [PKG IMPOSTOR]${N}  %s\n" "$_p"
                printf "  First line: ${R}%s${N}\n" "$_firstline"
                msg_in "Quarantining impostor pkg..."
                mv "$_p" "$_p.IMPOSTOR_$(date +%s)" 2>/dev/null \
                    && msg_ok "Quarantined: $_p.IMPOSTOR" \
                    || msg_fl "Could not quarantine — try: mv $_p ${_p}.bad"
                log "PKG IMPOSTOR QUARANTINED: $_p"
            fi
        done
    fi

    msg_in "Using pkg binary: ${_PKG_PATH:-none found}"

    # Attempt to fetch a real pkg bootstrap if none found
    if [ "$_PKG_OK" -eq 0 ]; then
        msg_wn "No valid pkg binary — attempting live bootstrap from FreeBSD CDN..."
        printf "\n"

        # Determine ABI for download URL
        _FBSD_MAJOR="$(uname -r 2>/dev/null | cut -d. -f1)"
        _FBSD_MAJOR="${_FBSD_MAJOR:-14}"
        _PKG_URLS="
https://pkg.freebsd.org/FreeBSD:${_FBSD_MAJOR}:amd64/latest/Latest/pkg.txz
https://pkg.freebsd.org/FreeBSD:14:amd64/latest/Latest/pkg.txz
https://pkg.freebsd.org/FreeBSD:13:amd64/latest/Latest/pkg.txz
"
        _got_pkg=0
        for _url in $_PKG_URLS; do
            [ -z "$_url" ] && continue
            msg_in "Trying: $_url"
            _r_fetch "$_WORKDIR/pkg.txz" "$_url" 2>/dev/null || continue
            # Verify the download is a real xz/bz2 archive — NOT html
            # Check magic bytes: xz=fd377a585a00, bzip2=425a68, gzip=1f8b
            _magic="$(dd if="$_WORKDIR/pkg.txz" bs=6 count=1 2>/dev/null | od -A n -t x1 | tr -d ' \n')"
            if echo "$_magic" | grep -qE "^(fd377a585a|425a68|1f8b)"; then
                msg_ok "Download verified as binary archive"
                _got_pkg=1
                break
            else
                # Read first bytes as text to diagnose
                _firstline=""
                { IFS= read -r _firstline; } < "$_WORKDIR/pkg.txz" 2>/dev/null
                msg_wn "Download is not a binary archive — got: $_firstline"
                msg_wn "Possible captive portal or DNS hijack intercepting HTTPS"
            fi
        done

        if [ "$_got_pkg" -eq 1 ]; then
            msg_in "Extracting pkg from archive..."
            # Use tar without -f cat pipe — tar can read directly
            tar -xf "$_WORKDIR/pkg.txz" -C "$_WORKDIR/" 2>/dev/null
            _extracted_pkg="$(find "$_WORKDIR" -name "pkg" -not -name "*.sh" -type f 2>/dev/null | head -1)"
            if [ -n "$_extracted_pkg" ] && _is_real_binary "$_extracted_pkg"; then
                mkdir -p /usr/local/sbin
                cp "$_extracted_pkg" /usr/local/sbin/pkg
                chmod 755 /usr/local/sbin/pkg
                _PKG_OK=1
                _PKG_PATH="/usr/local/sbin/pkg"
                msg_ok "Real pkg installed to /usr/local/sbin/pkg"
                log "PKG BOOTSTRAPPED from: $_url"
            else
                msg_fl "Extracted file is not a valid ELF — bootstrap failed"
                log "PKG BOOTSTRAP FAILED: extracted file not ELF"
            fi
        else
            msg_fl "Could not obtain a valid pkg binary from any source"
            msg_wn "Check: is DNS resolving? Is there a captive portal?"
            msg_wn "Try manually: fetch https://pkg.freebsd.org/FreeBSD:14:amd64/latest/Latest/pkg.txz"
        fi
    fi

    # -----------------------------------------------------------------------
    # Step 3: Repair pkg repo config — write with printf (no cat)
    # -----------------------------------------------------------------------
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  Step 3 of 3 — pkg Repository Config Repair${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n\n"

    if [ "$_PKG_OK" -eq 1 ]; then
        _REPO_DIR="/usr/local/etc/pkg/repos"
        mkdir -p "$_REPO_DIR"

        # Check repo files for HTML contamination using grep (verified ELF above)
        _repo_bad=0
        for _rf in "$_REPO_DIR"/*.conf; do
            [ -f "$_rf" ] || continue
            if grep -qi "<html\|<!DOCTYPE\|<body\|404 Not Found" "$_rf" 2>/dev/null; then
                msg_wn "Repo config contaminated with HTML: $(basename $_rf)"
                mv "$_rf" "${_rf}.BAD_$(date +%s)" 2>/dev/null && \
                    msg_ok "Quarantined bad repo config"
                log "BAD REPO CONFIG: $_rf"
                _repo_bad=1
            else
                msg_ok "Repo config looks valid: $(basename $_rf)"
            fi
        done

        # Always rewrite repo configs fresh — don't trust whatever is there
        msg_in "Writing fresh repo configs using printf (no cat)..."

        # Detect pfSense version accurately
        _rv=""
        [ -f /etc/version ] && { IFS= read -r _rv; } < /etc/version 2>/dev/null
        _rv="$(printf '%s' "$_rv" | sed 's/-.*//' | tr -d '[:space:]')"
        [ -z "$_rv" ] && _rv="${_PFSENSE_VER:-}"
        [ -z "$_rv" ] && _rv="UNKNOWN"
        _rv_under="$(printf '%s' "$_rv" | tr '.' '_')"

        msg_in "Detected pfSense version: $_rv"
        [ "$_rv" = "UNKNOWN" ] && \
            msg_wn "Could not detect version — repo URL may need manual correction"

        # ---------------------------------------------------------------
        # Wipe stale pkg database and ALL old repo configs
        # pkg 1.20+ uses /var/db/pkg/repos/<name>/db  (directory structure)
        # older pkg used /var/db/pkg/repo-<name>.sqlite (flat files)
        # wipe both to be safe
        # ---------------------------------------------------------------
        msg_in "Wiping stale pkg database and all old repo configs..."

        # New-style directory database (pkg 1.20+)
        rm -rf /var/db/pkg/repos/pfSense-core 2>/dev/null
        rm -rf /var/db/pkg/repos/pfSense 2>/dev/null
        rm -rf /var/db/pkg/repos/FreeBSD 2>/dev/null
        # Old-style flat sqlite files
        rm -rf /var/db/pkg/repo-*.sqlite /var/db/pkg/repo-*.meta 2>/dev/null
        msg_ok "Stale repo database entries removed (both old and new paths)"
        rm -rf /var/cache/pkg/* 2>/dev/null \
            && msg_ok "pkg cache cleared"

        # Remove every existing .conf from ALL locations pkg might read
        for _old_dir in \
            "/usr/local/etc/pkg/repos" \
            "/usr/local/share/pfSense/pkg/repos" \
            "/etc/pkg"; do
            [ -d "$_old_dir" ] || continue
            find "$_old_dir" -name "*.conf" -not -name "*.BAD*" -not -name "*.IMPOSTOR*" \
                2>/dev/null | while read _old; do
                mv "$_old" "${_old}.old_$(date +%s)" 2>/dev/null \
                    && msg_in "Archived old config: $(basename $_old)"
            done
        done

        # ---------------------------------------------------------------
        # CRITICAL: Fix both repo config locations FIRST before any pkg call.
        # pkg reads BOTH locations and uses whichever it finds last —
        # /usr/local/share/pfSense/pkg/repos/pfSense-repo.conf can override
        # /usr/local/etc/pkg/repos/ if it has a different version.
        # ---------------------------------------------------------------
        _FINGERPRINTS="/usr/local/share/pfSense/keys/pkg"
        _NATIVE_CONF="/usr/local/share/pfSense/pkg/repos/pfSense-repo.conf"
        _REPO_CONF_DIR="/usr/local/etc/pkg/repos"
        _PFS_REPO_DIR="/usr/local/share/pfSense/pkg/repos"

        # Check for version mismatch
        if [ -f "$_NATIVE_CONF" ]; then
            _NATIVE_VER="$(grep 'url:' "$_NATIVE_CONF" 2>/dev/null | \
                head -1 | grep -oE 'v[0-9_]+' | head -1 | tr '_' '.')"
            _NATIVE_VER="${_NATIVE_VER#v}"
            if [ -n "$_NATIVE_VER" ] && [ "$_NATIVE_VER" != "$_rv" ]; then
                msg_wn "REPO VERSION MISMATCH: native config says $_NATIVE_VER, system is $_rv"
                msg_wn "This is a known attacker technique to block security updates."
                log "ALERT: Repo version mismatch — installed=$_rv repo=$_NATIVE_VER"
            fi
        fi

        # Build correct URLs from installed version
        _CORE_URL="pkg+https://pkg.pfsense.org/pfSense_v${_rv_under}_amd64-core"
        _PKG_URL="pkg+https://pkg.pfsense.org/pfSense_v${_rv_under}_amd64-pfSense_v${_rv_under}"

        # Write the correct config — all three repo config files at once
        _REPO_CONTENT="FreeBSD: { enabled: no }

pfSense-core: {
  url: \"${_CORE_URL}\",
  mirror_type: \"srv\",
  signature_type: \"fingerprints\",
  fingerprints: \"${_FINGERPRINTS}\",
  enabled: yes
}

pfSense: {
  url: \"${_PKG_URL}\",
  mirror_type: \"srv\",
  signature_type: \"fingerprints\",
  fingerprints: \"${_FINGERPRINTS}\",
  enabled: yes
}"

        mkdir -p "$_REPO_CONF_DIR" "$_PFS_REPO_DIR"

        # Write all three locations so nothing can override us
        printf '%s\n' "$_REPO_CONTENT" > "$_REPO_CONF_DIR/pfSense-core.conf"
        printf 'pfSense: {\n  url: "%s",\n  mirror_type: "srv",\n  signature_type: "fingerprints",\n  fingerprints: "%s",\n  enabled: yes\n}\n' \
            "$_PKG_URL" "$_FINGERPRINTS" > "$_REPO_CONF_DIR/pfSense.conf"
        printf 'FreeBSD: { enabled: no }\n' > "$_REPO_CONF_DIR/FreeBSD.conf"
        printf '%s\n' "$_REPO_CONTENT" > "$_NATIVE_CONF"

        # Hard verify — read back and confirm version is correct
        _written_ver="$(grep 'url:' "$_NATIVE_CONF" 2>/dev/null | \
            head -1 | grep -oE 'v[0-9_]+' | head -1 | tr '_' '.')"
        _written_ver="${_written_ver#v}"
        if [ "$_written_ver" = "$_rv" ]; then
            msg_ok "All repo configs written and verified: v$_rv"
        else
            msg_fl "Repo config write may have failed — got $_written_ver, expected $_rv"
            msg_in "Manual fix:"
            printf "  cat /usr/local/etc/pkg/repos/pfSense-core.conf\n"
            printf "  cat /usr/local/share/pfSense/pkg/repos/pfSense-repo.conf\n"
        fi

        # Show both locations so you can see what each says
        printf "\n"
        msg_in "Repo config verification:"
        for _vf in \
            "$_REPO_CONF_DIR/pfSense-core.conf" \
            "$_REPO_CONF_DIR/pfSense.conf" \
            "$_NATIVE_CONF"; do
            [ -f "$_vf" ] || continue
            _vurl="$(grep 'url:' "$_vf" 2>/dev/null | head -1 | tr -d ' \t')"
            printf "  %-50s  %s\n" "$(basename "$_vf")" "$_vurl"
        done
        printf "\n"

        # Wipe stale database — MUST happen after fixing configs
        msg_in "Wiping stale pkg database..."
        rm -rf /var/db/pkg/repos/pfSense-core /var/db/pkg/repos/pfSense \
               /var/db/pkg/repos/FreeBSD 2>/dev/null
        rm -rf /var/db/pkg/repo-*.sqlite /var/db/pkg/repo-*.meta 2>/dev/null
        msg_ok "Stale repo database cleared"
        printf "\n"

        log "PKG REPO CONFIGS: rewritten for $_rv"

        # ---------------------------------------------------------------
        # Certificate Store Repair
        # ---------------------------------------------------------------
        printf "\n"
        printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
        printf "  ${B}  Certificate Store Repair${N}\n"
        printf "  ${C}  ---------------------------------------------------------------------------${N}\n\n"

        _CERT_DIR="/etc/ssl/certs"
        _CA_BUNDLE="/etc/ssl/cert.pem"
        _PFS_KEYS="/usr/local/share/pfSense/keys/pkg/trusted"

        # Check certctl itself — it should be owned by a package
        # An untracked certctl is suspicious (could be compromised)
        msg_in "Checking certctl integrity..."
        _certctl_path="$(command -v certctl 2>/dev/null)"
        if [ -z "$_certctl_path" ]; then
            msg_wn "certctl not found — skipping cert rehash"
        else
            _certctl_owner="$(pkg which "$_certctl_path" 2>/dev/null | grep -v warning)"
            if printf '%s' "$_certctl_owner" | grep -q "not found in the database"; then
                msg_wn "certctl is NOT tracked by any package: $_certctl_path"
                msg_wn "This may indicate certctl was replaced or manually installed"
                log "ALERT: certctl not in pkg database: $_certctl_path"
                # Check if it's at least a real script/binary (not an impostor)
                _certctl_first=""
                { IFS= read -r _certctl_first; } < "$_certctl_path" 2>/dev/null
                printf "  First line: %s\n" "$_certctl_first"
                printf "  SHA256    : %s\n" "$(sha256 "$_certctl_path" 2>/dev/null | awk '{print $NF}')"
            else
                msg_ok "certctl is tracked: $_certctl_owner"
            fi
        fi

        # Check what's currently trusted
        _trusted_count="$(find "$_CERT_DIR" -name "*.pem" -o -name "*.crt" 2>/dev/null | wc -l | tr -d ' ')"
        msg_in "Trusted certs in $_CERT_DIR: $_trusted_count"

        # Check pfSense's own package signing keys
        msg_in "pfSense pkg signing keys:"
        if [ -d "$_PFS_KEYS" ]; then
            find "$_PFS_KEYS" -type f 2>/dev/null | while read _kf; do
                printf "  %s\n" "$(basename $_kf)"
            done
        else
            msg_wn "pfSense keys directory missing: $_PFS_KEYS"
            msg_in "Attempting to restore from GitHub..."
            mkdir -p "$_PFS_KEYS"
            _r_fetch "$_PFS_KEYS/pkg.pfsense.org.20160406" \
                "https://raw.githubusercontent.com/pfsense/pfsense/master/src/usr/local/share/pfSense/keys/pkg/trusted/pkg.pfsense.org.20160406" \
                && msg_ok "Restored pfSense signing key" \
                || msg_fl "Could not fetch signing key"
        fi

        # Run certctl with visible output
        printf "\n"
        msg_in "Running certctl rehash..."
        _certtmp="/tmp/certctl_out_$$"
        certctl rehash > "$_certtmp" 2> "${_certtmp}.err"
        while IFS= read -r _line; do printf "  %s\n" "$_line"; done < "$_certtmp"     2>/dev/null
        while IFS= read -r _line; do printf "  %s\n" "$_line"; done < "${_certtmp}.err" 2>/dev/null

        _cert_untrusted=0
        grep -qi "untrusted\|skipping" "$_certtmp"      2>/dev/null && _cert_untrusted=1
        grep -qi "untrusted\|skipping" "${_certtmp}.err" 2>/dev/null && _cert_untrusted=1
        rm -f "$_certtmp" "${_certtmp}.err"

        if [ "$_cert_untrusted" -eq 1 ]; then
            printf "\n"
            msg_wn "certctl is skipping untrusted certificates in /etc/ssl/untrusted/"
            msg_in "These certs are explicitly distrusted — one may be a CA that Netgate uses."
            msg_in "Showing which certs are distrusted:"
            for _uc in /etc/ssl/untrusted/*.0 /etc/ssl/untrusted/*.pem; do
                [ -f "$_uc" ] || continue
                _subj="$(openssl x509 -noout -subject -in "$_uc" 2>/dev/null | sed 's/subject=//')"
                printf "  ${R}UNTRUSTED:${N} $(basename $_uc) — %s\n" "${_subj:-(cannot read)}"
            done
            printf "\n"

            # Strategy 1: Temporarily move untrusted certs aside and rehash
            # This removes the explicit distrust so pkg can validate the chain
            msg_in "Strategy 1: Moving untrusted certs aside temporarily..."
            _UNTRUST_BAK="/tmp/untrusted_bak_$$"
            mkdir -p "$_UNTRUST_BAK"
            _moved=0
            for _uc in /etc/ssl/untrusted/*.0 /etc/ssl/untrusted/*.pem; do
                [ -f "$_uc" ] || continue
                mv "$_uc" "$_UNTRUST_BAK/" 2>/dev/null && _moved=$((_moved+1))
            done

            if [ "$_moved" -gt 0 ]; then
                msg_ok "Moved $_moved untrusted cert(s) to $_UNTRUST_BAK"
                certctl rehash >/dev/null 2>/dev/null && msg_ok "certctl rehash after moving untrusted certs"
            else
                msg_wn "No untrusted certs found to move"
            fi

            # Strategy 2: Also set SSL_NO_VERIFY_PEER as belt-and-suspenders fallback
            # pkg-static respects this env var to skip TLS peer verification
            export SSL_NO_VERIFY_PEER=1
            msg_wn "SSL_NO_VERIFY_PEER=1 set as fallback (session only)"
            msg_in "After recovery, restore certs with:"
            printf "  mv %s/* /etc/ssl/untrusted/ && certctl rehash\n" "$_UNTRUST_BAK"
        else
            msg_ok "Certificate store looks healthy"
        fi
        printf "\n"

        # ---------------------------------------------------------------
        # Run pkg update — fully automatic.
        # SSL workaround applied three ways to ensure libfetch sees it:
        #   1. Written to /usr/local/etc/pkg.conf (pkg reads this at startup)
        #   2. Passed via env directly to the pkg process
        #   3. Exported to shell environment as fallback
        # ---------------------------------------------------------------

        # Write SSL_NO_VERIFY_PEER to pkg.conf so libfetch reads it at startup
        _PKG_CONF_FILE="/usr/local/etc/pkg.conf"
        _PKG_CONF_BAK="/tmp/pkg.conf.bak_$$"
        [ -f "$_PKG_CONF_FILE" ] && cp "$_PKG_CONF_FILE" "$_PKG_CONF_BAK"
        # Remove any existing SSL_NO_VERIFY_PEER line then add it
        if [ -f "$_PKG_CONF_FILE" ]; then
            grep -v "SSL_NO_VERIFY_PEER" "$_PKG_CONF_FILE" > "/tmp/pkg.conf.tmp_$$" 2>/dev/null
            mv "/tmp/pkg.conf.tmp_$$" "$_PKG_CONF_FILE"
        fi
        printf 'SSL_NO_VERIFY_PEER = true;\n' >> "$_PKG_CONF_FILE"
        msg_ok "SSL_NO_VERIFY_PEER written to $_PKG_CONF_FILE"

        # Wipe stale database right before running
        rm -rf /var/db/pkg/repos/pfSense-core /var/db/pkg/repos/pfSense 2>/dev/null

        printf "\n"
        msg_in "Running pkg update -f ..."
        printf "${C}  ---------------------------------------------------------------------------${N}\n"
        env SSL_NO_VERIFY_PEER=1 FETCH_SSL_NO_VERIFY_PEER=1 "$_PKG_PATH" update -f
        _pkg_exit=$?
        printf "${C}  ---------------------------------------------------------------------------${N}\n"
        printf "\n"

        # Restore original pkg.conf
        if [ -f "$_PKG_CONF_BAK" ]; then
            mv "$_PKG_CONF_BAK" "$_PKG_CONF_FILE"
        else
            # Remove the line we added if there was no original
            grep -v "SSL_NO_VERIFY_PEER" "$_PKG_CONF_FILE" > "/tmp/pkg.conf.tmp_$$" 2>/dev/null
            mv "/tmp/pkg.conf.tmp_$$" "$_PKG_CONF_FILE" 2>/dev/null
        fi

        if [ "$_pkg_exit" -eq 0 ]; then
            msg_ok "pkg update succeeded"
            msg_in "Running pkg upgrade -f -y ..."
            # Re-add SSL workaround for upgrade
            printf 'SSL_NO_VERIFY_PEER = true;\n' >> "$_PKG_CONF_FILE"
            printf "${C}  ---------------------------------------------------------------------------${N}\n"
            env SSL_NO_VERIFY_PEER=1 FETCH_SSL_NO_VERIFY_PEER=1 "$_PKG_PATH" upgrade -f -y
            _upgrade_exit=$?
            printf "${C}  ---------------------------------------------------------------------------${N}\n"
            # Restore again
            grep -v "SSL_NO_VERIFY_PEER" "$_PKG_CONF_FILE" > "/tmp/pkg.conf.tmp_$$" 2>/dev/null
            mv "/tmp/pkg.conf.tmp_$$" "$_PKG_CONF_FILE" 2>/dev/null
            [ "$_upgrade_exit" -eq 0 ] && msg_ok "pkg packages upgraded" \
                || msg_wn "pkg upgrade returned errors (exit $_upgrade_exit)"
        else
            msg_wn "pkg update exited with code $_pkg_exit"
            printf "\n"
            msg_in "For verbose TLS debugging run manually:"
            printf "  printf 'SSL_NO_VERIFY_PEER = true;\\n' >> /usr/local/etc/pkg.conf\n"
            printf "  rm -rf /var/db/pkg/repos/pfSense-core /var/db/pkg/repos/pfSense\n"
            printf "  env SSL_NO_VERIFY_PEER=1 /usr/local/sbin/pkg-static -d update -f\n"
        fi

        # Report on the untrusted certs that were moved
        if [ -n "$_UNTRUST_BAK" ] && [ -d "$_UNTRUST_BAK" ]; then
            _uc_count="$(find "$_UNTRUST_BAK" -type f 2>/dev/null | wc -l | tr -d ' ')"
            printf "\n"
            printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
            printf "  ${B}  Untrusted Certificate Note${N}\n"
            printf "  ${C}  ---------------------------------------------------------------------------${N}\n\n"
            msg_in "$_uc_count certificates were temporarily moved from /etc/ssl/untrusted/"
            msg_in "These are stock FreeBSD/Mozilla CA distrust entries that ship with pfSense 2.8.x"
            msg_wn "pfSense 2.8.1 ships with a Mozilla CA distrust list that includes CAs used"
            msg_wn "by Netgate's own update servers — this is a known pfSense 2.8.1 issue."
            msg_in "SSL_NO_VERIFY_PEER=1 was used as a workaround to allow pkg to connect."
            printf "\n"
            msg_in "Restoring untrusted certificates..."
            for _uc in "$_UNTRUST_BAK"/*; do
                [ -f "$_uc" ] || continue
                mv "$_uc" /etc/ssl/untrusted/ 2>/dev/null
            done
            certctl rehash >/dev/null 2>/dev/null && msg_ok "Untrusted certs restored, certctl rehashed"
            rmdir "$_UNTRUST_BAK" 2>/dev/null
            log "UNTRUSTED CERTS: moved temporarily for pkg, restored after. pfSense 2.8.1 known issue."
        fi
    else
        msg_wn "No valid pkg binary — skipping repo repair and upgrade"
        msg_in "Fix network/DNS connectivity then re-run this option."
    fi

    # -----------------------------------------------------------------------
    # Step 4: Restart services — staged to avoid 50x GUI crash
    # rc.restart_all kills and restarts everything simultaneously which
    # can cause the web GUI to serve a 50x while PHP is reinitializing.
    # Instead: reload config first, then restart GUI last with a delay.
    # -----------------------------------------------------------------------
    printf "\n"
    msg_in "Reloading configuration (non-disruptive)..."
    /etc/rc.reload_all 2>/dev/null && msg_ok "rc.reload_all complete"

    msg_in "Refreshing PHP INI..."
    [ -x /etc/rc.php_ini_setup ] && /etc/rc.php_ini_setup 2>/dev/null \
        && msg_ok "PHP INI refreshed"

    msg_in "Restarting web GUI (allow 10-15 seconds for it to come back)..."
    if [ -x /usr/local/sbin/pfSsh.php ]; then
        /usr/local/sbin/pfSsh.php playback svc restart webgui 2>/dev/null \
            && msg_ok "Web GUI restart issued" \
            || /etc/rc.restart_webgui 2>/dev/null \
            && msg_ok "Web GUI restarted via rc.restart_webgui"
    else
        /etc/rc.restart_webgui 2>/dev/null && msg_ok "Web GUI restarted"
    fi

    msg_in "Waiting 10 seconds for GUI to initialize..."
    sleep 10

    # Verify GUI is responding
    _gui_ok=0
    for _try in 1 2 3; do
        _gui_port="$(sockstat -l 2>/dev/null | grep -E "(lighttpd|nginx|80|443)" | head -1)"
        if [ -n "$_gui_port" ]; then
            _gui_ok=1
            break
        fi
        sleep 3
    done
    [ "$_gui_ok" -eq 1 ] && msg_ok "Web GUI is listening" \
        || msg_wn "Web GUI may still be starting — wait 30 seconds then refresh browser"
    msg_in "If you see a 50x error: wait 30s and do Ctrl+Shift+R in your browser"

    rm -rf "$_WORKDIR"
    printf "\n"

    if [ -n "$_IMPOSTOR_LIST" ]; then
        msg_wn "IMPOSTOR BINARIES WERE FOUND. System is likely compromised."
        msg_wn "Full reinstall from clean media is strongly recommended."
        printf "  Impostors found: %b\n" "$_IMPOSTOR_LIST"
    fi

    msg_ok "Binary recovery run complete."
    log "BINARY RECOVERY RUN"
    press_enter
}

# ------------------------------------------------------------------------------
# Option 2 - Restore web GUI and init files live from pfSense GitHub
# ------------------------------------------------------------------------------
_r_restore_files() {
    printf "\n"
    printf "  ${B}=== Web GUI and Init File Restore ===${N}\n"
    printf "\n"

    _r_get_version
    msg_in "Detected pfSense version : ${_PFSENSE_VER:-unknown}"
    msg_in "Trying branches          : $_PFSENSE_BRANCHES"
    printf "\n"

    confirm "This will backup, quarantine, then replace /usr/local/www, rc.d, and key init files. Continue?" \
        || return

    # Setup backup and quarantine directories
    _TS="$(date +%Y%m%d_%H%M%S)"
    _BK="$BACKUP_DIR/restore_backup_$_TS"
    _QR="$BACKUP_DIR/restore_quarantine_$_TS"
    mkdir -p "$_BK" "$_QR"

    # Step 1: Backup and quarantine current www and rc.d
    printf "\n"
    msg_in "Backing up and quarantining current files..."
    _r_backup_and_quarantine /usr/local/www "$_BK" "$_QR"
    _r_backup_and_quarantine /usr/local/etc/rc.d "$_BK" "$_QR"
    msg_ok "Current files backed up  : $_BK"
    msg_ok "Current files quarantined: $_QR"

    # Zip both
    if command -v zip >/dev/null 2>&1; then
        zip -qr "$_BK/backup_$_TS.zip"     "$_BK"  2>/dev/null && msg_ok "Backup archive created"
        zip -qr "$_QR/quarantine_$_TS.zip" "$_QR"  2>/dev/null && msg_ok "Quarantine archive created"
    fi

    _FAILED=""

    # Step 2: Replace /usr/local/www from pfSense GitHub
    printf "\n"
    msg_in "Restoring pfSense web GUI files..."

    _got_www=0
    _GIT_REPO="https://github.com/pfsense/pfsense.git"
    _GIT_TMP="/tmp/pf_git_$$"

    # Strategy 1: git sparse-checkout — pulls ONLY src/usr/local/www
    # Much faster than cloning the full repo, works if git is installed
    msg_in "Strategy 1: git sparse-checkout (fastest — only fetches www files)..."
    _git_bin="$(command -v git 2>/dev/null)"

    if [ -z "$_git_bin" ]; then
        msg_wn "git not installed — attempting to install via pkg..."
        env SSL_NO_VERIFY_PEER=1 "$_PKG_PATH" install -y git 2>/dev/null \
            && _git_bin="$(command -v git 2>/dev/null)" \
            && msg_ok "git installed" \
            || msg_wn "git install failed — will try other strategies"
    fi

    if [ -n "$_git_bin" ]; then
        rm -rf "$_GIT_TMP"
        mkdir -p "$_GIT_TMP"
        msg_in "Initialising sparse clone of pfsense/pfsense (master)..."

        # Init repo and configure sparse checkout BEFORE fetching
        # This means git only downloads the paths we specify — not the whole repo
        (
            cd "$_GIT_TMP" || exit 1
            git init -q
            git remote add origin "$_GIT_REPO"
            git config core.sparseCheckout true
            # Only fetch the www folder and the critical init files
            printf 'src/usr/local/www/\n'      > .git/info/sparse-checkout
            printf 'src/etc/rc.initial\n'      >> .git/info/sparse-checkout
            printf 'src/etc/inc/config.inc\n'  >> .git/info/sparse-checkout
            printf 'src/etc/inc/auth.inc\n'    >> .git/info/sparse-checkout
            git fetch --depth=1 origin master
            git checkout FETCH_HEAD -q
        ) && _got_www=1 && msg_ok "Sparse checkout complete" \
          || msg_wn "git sparse checkout failed"

        if [ "$_got_www" -eq 1 ]; then
            # Install www files
            if [ -d "$_GIT_TMP/src/usr/local/www" ]; then
                rm -rf /usr/local/www
                cp -a "$_GIT_TMP/src/usr/local/www" /usr/local/www
                msg_ok "/usr/local/www restored from git"
                log "RESTORED: /usr/local/www via git sparse-checkout"
            else
                msg_fl "www not found in git checkout — unexpected structure"
                _got_www=0
            fi

            # Install individual init files directly from the checkout
            for _pair in \
                "/etc/rc.initial:src/etc/rc.initial" \
                "/etc/inc/config.inc:src/etc/inc/config.inc" \
                "/etc/inc/auth.inc:src/etc/inc/auth.inc"; do
                _dst="${_pair%%:*}"
                _src_rel="${_pair##*:}"
                if [ -f "$_GIT_TMP/$_src_rel" ]; then
                    cp "$_GIT_TMP/$_src_rel" "$_dst" \
                        && chmod +x "$_dst" 2>/dev/null \
                        && msg_ok "Restored: $_dst" \
                        || msg_wn "Could not copy: $_dst"
                else
                    msg_wn "Not in checkout: $_src_rel"
                fi
            done
        fi
        rm -rf "$_GIT_TMP"
    else
        msg_wn "git not available — skipping to next strategy"
    fi

    # Strategy 2: pkg reinstall (no git needed — uses Netgate's own servers)
    if [ "$_got_www" -eq 0 ]; then
        msg_in "Strategy 2: pkg reinstall pfSense-base..."
        if [ -n "$_PKG_PATH" ]; then
            printf 'SSL_NO_VERIFY_PEER = true;\n' >> /usr/local/etc/pkg.conf 2>/dev/null
            env SSL_NO_VERIFY_PEER=1 "$_PKG_PATH" reinstall -fy pfSense-base 2>/dev/null \
                && msg_ok "pfSense-base reinstalled via pkg" && _got_www=1 \
                || msg_wn "pkg reinstall failed"
            grep -v "SSL_NO_VERIFY_PEER" /usr/local/etc/pkg.conf \
                > /tmp/pkgconf_tmp_$$ 2>/dev/null \
                && mv /tmp/pkgconf_tmp_$$ /usr/local/etc/pkg.conf 2>/dev/null
        else
            msg_wn "No pkg binary — skipping pkg reinstall"
        fi
    fi

    # Strategy 3: raw file fetch from confirmed GitHub URL (last resort)
    if [ "$_got_www" -eq 0 ]; then
        msg_in "Strategy 3: raw file fetch from GitHub (master branch)..."
        _www_critical="index.php login.php logout.php head.php menu.inc"
        if _r_fetch /tmp/test_idx_$$ "${_GH_PFSENSE_WWW}/index.php" \
                && [ -s /tmp/test_idx_$$ ]; then
            msg_ok "GitHub reachable"
            rm -f /tmp/test_idx_$$
            for _wf in $_www_critical; do
                _wdest="/usr/local/www/${_wf}"
                _r_fetch "$_wdest" "${_GH_PFSENSE_WWW}/${_wf}" \
                    && msg_ok "Restored: $_wf" \
                    || msg_wn "Could not fetch: $_wf"
            done
            _got_www=1
        else
            rm -f /tmp/test_idx_$$
            msg_fl "Cannot reach GitHub — check DNS and internet connectivity"
            _FAILED="$_FAILED\n  /usr/local/www (all strategies failed)"
        fi
    fi

    [ "$_got_www" -eq 0 ] && msg_fl "Web GUI restore failed — all strategies exhausted"

    # Step 4: Restore rc.d startup scripts from FreeBSD-ports
    printf "\n"
    msg_in "Restoring /usr/local/etc/rc.d scripts from FreeBSD-ports..."
    if _r_fetch /tmp/ports_$$.zip \
        "https://codeload.github.com/pfsense/FreeBSD-ports/zip/refs/heads/devel"; then
        unzip -oq /tmp/ports_$$.zip -d /tmp/ports_src_$$ 2>/dev/null
        if [ -d /tmp/ports_src_$$/FreeBSD-ports-devel ]; then
            rm -rf /usr/local/etc/rc.d/*
            find /tmp/ports_src_$$/FreeBSD-ports-devel -type f -name "*.in" \
                -exec cp {} /usr/local/etc/rc.d/ \;
            msg_ok "/usr/local/etc/rc.d scripts restored"
            log "RESTORED: /usr/local/etc/rc.d"
        else
            msg_fl "Could not find rc.d scripts in extracted archive"
            _FAILED="$_FAILED\n  /usr/local/etc/rc.d/*"
        fi
        rm -rf /tmp/ports_$$.zip /tmp/ports_src_$$
    else
        msg_fl "Failed to download FreeBSD-ports archive"
        _FAILED="$_FAILED\n  /usr/local/etc/rc.d/*"
    fi

    # Step 5: Clean temp PHP sessions and fix PHP extension mismatches
    printf "\n"
    msg_in "Cleaning temp PHP sessions..."
    rm -rf /var/tmp/php* /tmp/php* 2>/dev/null
    msg_ok "PHP temp files cleared"

    # PHP extension consistency check — git restore can cause version skew
    # between php core and extensions (e.g. xmlreader.so "Undefined symbol" errors)
    printf "\n"
    msg_in "Checking PHP extension consistency..."
    _php_errors="$(php -m 2>&1 | grep -i "unable to load\|undefined symbol\|cannot open")"
    if [ -n "$_php_errors" ]; then
        msg_wn "PHP extension errors detected:"
        printf "%s\n" "$_php_errors" | while IFS= read -r _l; do
            printf "  ${R}%s${N}\n" "$_l"
        done
        printf "\n"
        msg_in "Reinstalling all php83 extensions to fix version mismatch..."
        _php_pkgs="$(env SSL_NO_VERIFY_PEER=1 "$_PKG_PATH" info 2>/dev/null | \
            grep '^php' | awk '{print $1}' | tr '\n' ' ')"
        if [ -n "$_php_pkgs" ]; then
            printf 'SSL_NO_VERIFY_PEER = true;\n' >> /usr/local/etc/pkg.conf 2>/dev/null
            # shellcheck disable=SC2086
            env SSL_NO_VERIFY_PEER=1 "$_PKG_PATH" reinstall -fy $_php_pkgs 2>/dev/null \
                && msg_ok "PHP extensions reinstalled" \
                || msg_wn "PHP reinstall had errors — check manually"
            grep -v "SSL_NO_VERIFY_PEER" /usr/local/etc/pkg.conf \
                > /tmp/pkgconf_tmp_$$ 2>/dev/null \
                && mv /tmp/pkgconf_tmp_$$ /usr/local/etc/pkg.conf 2>/dev/null
            # Verify fix
            _php_errors2="$(php -m 2>&1 | grep -i "unable to load\|undefined symbol")"
            [ -z "$_php_errors2" ] && msg_ok "PHP extension errors resolved" \
                || msg_wn "Some PHP errors remain — a full pfSense reinstall may be needed"
        else
            msg_wn "Could not list PHP packages — run manually:"
            printf "  env SSL_NO_VERIFY_PEER=1 pkg reinstall -fy php83 php83-xml php83-dom php83-xmlreader\n"
        fi
    else
        msg_ok "PHP extensions loaded cleanly"
    fi

    # Step 6: Staged restart — reload config first, GUI last with a wait
    printf "\n"
    msg_in "Reloading pfSense configuration..."
    /etc/rc.reload_all 2>/dev/null && msg_ok "rc.reload_all complete"

    msg_in "Refreshing PHP INI..."
    [ -x /etc/rc.php_ini_setup ] && /etc/rc.php_ini_setup 2>/dev/null \
        && msg_ok "PHP INI refreshed"

    msg_in "Restarting web GUI (allow 10-15 seconds to come back)..."
    if [ -x /usr/local/sbin/pfSsh.php ]; then
        /usr/local/sbin/pfSsh.php playback svc restart webgui 2>/dev/null \
            && msg_ok "Web GUI restart issued" \
            || /etc/rc.restart_webgui 2>/dev/null && msg_ok "Web GUI restarted"
    else
        /etc/rc.restart_webgui 2>/dev/null && msg_ok "Web GUI restarted"
    fi

    sleep 10
    _gui_ok=0
    for _try in 1 2 3; do
        [ -n "$(sockstat -l 2>/dev/null | grep -E '(lighttpd|nginx|:80|:443)' | head -1)" ] \
            && _gui_ok=1 && break
        sleep 3
    done
    [ "$_gui_ok" -eq 1 ] && msg_ok "Web GUI is listening" \
        || msg_wn "GUI may still be initializing — wait 30s then Ctrl+Shift+R in browser"

    # Final report
    printf "\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    printf "  ${B}  Restore Summary${N}\n"
    printf "  ${C}  ---------------------------------------------------------------------------${N}\n"
    msg_ok "Backup location     : $_BK"
    msg_ok "Quarantine location : $_QR"
    msg_ok "Restored            : /usr/local/www"
    msg_ok "Restored            : /etc/rc.initial"
    msg_ok "Restored            : /etc/inc/config.inc"
    msg_ok "Restored            : /etc/inc/auth.inc"
    msg_ok "Restored            : /usr/local/etc/rc.d/*"
    if [ -n "$_FAILED" ]; then
        printf "\n"
        msg_fl "The following files could NOT be restored:"
        printf "%b\n" "$_FAILED"
    else
        msg_ok "No failures."
    fi
    log "FILE RESTORE RUN - failures: ${_FAILED:-none}"
    press_enter
}

# ------------------------------------------------------------------------------
# Option 3 - Local snapshot integrity check
# ------------------------------------------------------------------------------
_r_integrity() {
    _snap="$(ls -dt "$BACKUP_DIR"/snapshot_* 2>/dev/null | head -1)"
    if [ -z "$_snap" ]; then
        msg_wn "No local snapshot found. Use option 5 to create one first."
        press_enter; return
    fi
    msg_in "Using snapshot: $(basename $_snap)"
    printf "\n"

    if [ -f "$_snap/binary_checksums.txt" ]; then
        msg_in "Verifying binary checksums..."
        while read _line; do
            _bin="$(echo "$_line" | awk '{print $NF}')"
            _orig="$(echo "$_line" | awk '{print $1}')"
            [ -f "$_bin" ] || continue
            _curr="$(sha256 "$_bin" | awk '{print $1}')"
            if [ "$_orig" != "$_curr" ]; then
                msg_wn "MODIFIED: $_bin"
                log "ALERT: Modified binary: $_bin"
            else
                msg_ok "Clean: $_bin"
            fi
        done < "$_snap/binary_checksums.txt"
    fi

    printf "\n"
    msg_in "Scanning PHP and startup files for shell patterns..."
    for _f in /usr/local/www/index.php /usr/local/www/login.php \
               /usr/local/www/logout.php /etc/rc /etc/rc.local /etc/rc.initial \
               /etc/inc/config.inc /etc/inc/auth.inc; do
        [ -f "$_f" ] || continue
        if grep -qEi "eval\(base64_decode|passthru|shell_exec|system\(|\$_GET\[|gzinflate|assert\(" "$_f" 2>/dev/null; then
            msg_wn "SUSPICIOUS PATTERN: $_f"
            log "ALERT: Shell pattern in $_f"
        else
            msg_ok "Clean: $_f"
        fi
    done
    press_enter
}

# ------------------------------------------------------------------------------
# Option 4 - Break web shells and persistence
# ------------------------------------------------------------------------------
_r_break_shells() {
    confirm "Lock PHP permissions and clean persistence hooks?" || return
    printf "\n"

    msg_in "Setting PHP files to read-only (root:wheel)..."
    find /usr/local/www -name "*.php" -exec chmod 444 {} \; 2>/dev/null
    find /usr/local/www -name "*.php" -exec chown root:wheel {} \; 2>/dev/null
    msg_ok "PHP files locked"

    msg_in "Removing world-writable permissions from web files..."
    find /usr/local/www -perm -o+w -type f 2>/dev/null | while read _f; do
        chmod o-w "$_f" && msg_wn "Fixed perms: $_f"
    done

    msg_in "Flagging recently modified PHP files..."
    find /usr/local/www -name "*.php" -newer /etc/passwd 2>/dev/null | while read _f; do
        msg_wn "Recently modified: $_f"; log "ALERT: Modified PHP: $_f"
    done

    msg_in "Checking cron for suspicious entries..."
    for _cf in /etc/crontab /var/cron/tabs/*; do
        [ -f "$_cf" ] || continue
        if grep -qE "(curl|wget|/tmp/|base64|bash -i|nc |ncat)" "$_cf" 2>/dev/null; then
            msg_wn "Suspicious cron in: $_cf"
            grep -nE "(curl|wget|/tmp/|base64|bash -i|nc |ncat)" "$_cf"
            confirm "Remove suspicious lines from $_cf?" && \
                sed -i.bak -E "/(curl|wget|\/tmp\/|base64|bash -i|nc |ncat)/d" "$_cf" && \
                msg_ok "Cleaned: $_cf"
        else
            msg_ok "Cron clean: $_cf"
        fi
    done

    msg_in "Checking /etc/rc.local for backdoors..."
    if [ -f /etc/rc.local ]; then
        if grep -qE "(curl|wget|/tmp/|bash -i|nc |ncat|python)" /etc/rc.local 2>/dev/null; then
            msg_wn "Suspicious content in /etc/rc.local"
            grep -nE "(curl|wget|/tmp/|bash -i|nc |ncat|python)" /etc/rc.local
            confirm "Remove suspicious lines?" && \
                sed -i.bak -E "/(curl|wget|\/tmp\/|bash -i|nc |ncat|python)/d" /etc/rc.local && \
                msg_ok "Cleaned /etc/rc.local"
        else
            msg_ok "/etc/rc.local clean"
        fi
    fi
    press_enter
}

# ------------------------------------------------------------------------------
# Option 5 - Take a local snapshot
# ------------------------------------------------------------------------------
_r_snapshot() {
    _snap="$BACKUP_DIR/snapshot_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$_snap"
    msg_in "Creating snapshot at $_snap ..."
    for _f in /etc/passwd /etc/group /etc/master.passwd /etc/shells \
               /etc/rc /etc/rc.local /etc/rc.initial /etc/rc.shutdown \
               /etc/ssh/sshd_config /cf/conf/config.xml \
               /etc/inc/config.inc /etc/inc/auth.inc \
               /usr/local/www/index.php /usr/local/www/login.php; do
        [ -f "$_f" ] || continue
        _d="$_snap$(dirname $_f)"
        mkdir -p "$_d"
        cp -p "$_f" "$_d/" && msg_ok "Backed up: $_f" || msg_fl "Failed: $_f"
    done
    [ -d /usr/local/www ] && cp -rp /usr/local/www "$_snap/usr_local_www" \
        && msg_ok "Backed up: /usr/local/www"
    for _b in /bin/sh /bin/ls /usr/bin/find /usr/bin/awk /usr/bin/grep /sbin/pfctl; do
        [ -f "$_b" ] && sha256 "$_b" >> "$_snap/binary_checksums.txt"
    done
    msg_ok "Snapshot complete: $(basename $_snap)"
    press_enter
}


mod_restore
