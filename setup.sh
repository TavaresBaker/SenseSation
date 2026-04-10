#!/bin/sh
# =============================================================================
# setup.sh - pfSense Threat Hunter Bootstrap Installer
#
# Run this ONE command on pfSense to download and install everything:
#
#   fetch -o /tmp/setup.sh https://raw.githubusercontent.com/YOUR_USER/YOUR_REPO/main/setup.sh && sh /tmp/setup.sh
#
# Or if you already have the repo on disk, run from the repo root:
#   sh setup.sh
#
# Edit GITHUB_USER and GITHUB_REPO below to match your repo.
# =============================================================================

# Install root — scripts go into Scripts/ subdirectory to match repo layout
INSTALL_ROOT="/opt/pf_hunter"
INSTALL_SCRIPTS="$INSTALL_ROOT/Scripts"
GITHUB_USER="YOUR_GITHUB_USERNAME"
GITHUB_REPO="YOUR_REPO_NAME"
GITHUB_BRANCH="main"
GITHUB_ZIP="https://github.com/${GITHUB_USER}/${GITHUB_REPO}/archive/refs/heads/${GITHUB_BRANCH}.zip"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1m'; N='\033[0m'
ok()   { printf "${G}  [OK]${N}  %s\n" "$1"; }
fail() { printf "${R}  [!!]${N}  %s\n" "$1"; }
info() { printf "${Y}  [--]${N}  %s\n" "$1"; }

printf "\n${C}${B}  ============================================================${N}\n"
printf "${C}${B}       pfSense Threat Hunter - Bootstrap Installer           ${N}\n"
printf "${C}${B}  ============================================================${N}\n\n"

[ "$(id -u)" -ne 0 ] && fail "Must be run as root." && exit 1
ok "Running as root"

# -----------------------------------------------------------------------
# Detect: running from repo on disk, or need to download?
# -----------------------------------------------------------------------
_SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)"
_HAVE_REPO=0
[ -f "$_SCRIPT_PATH/Scripts/rc.hunter" ] && _HAVE_REPO=1

if [ "$_HAVE_REPO" -eq 0 ]; then
    info "Scripts/ not found here — downloading repo from GitHub..."

    if [ "$GITHUB_USER" = "YOUR_GITHUB_USERNAME" ]; then
        fail "Edit GITHUB_USER and GITHUB_REPO in setup.sh before running."
        fail "Or scp the full repo to pfSense and run setup.sh from repo root."
        exit 1
    fi

    if ! fetch -q -o /dev/null "https://github.com" 2>/dev/null &&
       ! curl -fsS -o /dev/null "https://github.com" 2>/dev/null; then
        fail "Cannot reach GitHub. Set DNS to 1.1.1.1 in System > General Setup."
        exit 1
    fi
    ok "Internet reachable"

    _ZIP="/tmp/pf_hunter_$$.zip"
    _EXTRACT="/tmp/pf_hunter_src_$$"
    info "Downloading: $GITHUB_ZIP"
    if ! { fetch -o "$_ZIP" "$GITHUB_ZIP" 2>/dev/null ||
           curl -fsSL "$GITHUB_ZIP" -o "$_ZIP" 2>/dev/null; }; then
        fail "Download failed. Check GITHUB_USER/GITHUB_REPO/GITHUB_BRANCH."
        rm -f "$_ZIP"; exit 1
    fi
    ok "Downloaded ($(ls -lh "$_ZIP" 2>/dev/null | awk '{print $5}'))"

    info "Extracting..."
    mkdir -p "$_EXTRACT"
    if ! unzip -q "$_ZIP" -d "$_EXTRACT" 2>/dev/null; then
        fail "Extraction failed — zip may be corrupt"
        rm -f "$_ZIP"; rm -rf "$_EXTRACT"; exit 1
    fi
    rm -f "$_ZIP"

    _REPO_DIR="$(ls "$_EXTRACT" | head -1)"
    if [ -z "$_REPO_DIR" ] || [ ! -d "$_EXTRACT/$_REPO_DIR/Scripts" ]; then
        fail "Scripts/ not found in extracted archive"
        rm -rf "$_EXTRACT"; exit 1
    fi
    ok "Extracted: $_REPO_DIR"
    _SCRIPT_PATH="$_EXTRACT/$_REPO_DIR"
else
    ok "Using repo at: $_SCRIPT_PATH"
fi

# -----------------------------------------------------------------------
# Install — preserve Scripts/ subdirectory so ../logs and ../backups work
# -----------------------------------------------------------------------
info "Creating directory structure..."
for _d in "$INSTALL_ROOT" \
           "$INSTALL_SCRIPTS" \
           "$INSTALL_ROOT/logs" \
           "$INSTALL_ROOT/backups" \
           "$INSTALL_ROOT/backups/config_backups" \
           "$INSTALL_ROOT/Resources"; do
    mkdir -p "$_d" && ok "Created: $_d" || { fail "mkdir failed: $_d"; exit 1; }
done
chmod 700 "$INSTALL_ROOT"

info "Deploying scripts to $INSTALL_SCRIPTS/ ..."
cp "$_SCRIPT_PATH/Scripts/"*.sh "$INSTALL_SCRIPTS/" 2>/dev/null
cp "$_SCRIPT_PATH/Scripts/rc.hunter" "$INSTALL_SCRIPTS/" 2>/dev/null
chmod 750 "$INSTALL_SCRIPTS/"*.sh "$INSTALL_SCRIPTS/rc.hunter" 2>/dev/null
ok "Scripts deployed"

[ -d "$_SCRIPT_PATH/Resources" ] &&
    cp -r "$_SCRIPT_PATH/Resources/." "$INSTALL_ROOT/Resources/" 2>/dev/null &&
    ok "Resources copied"

# Symlink rc.hunter so it's callable from anywhere
ln -sf "$INSTALL_SCRIPTS/rc.hunter" /usr/local/sbin/rc.hunter 2>/dev/null &&
    ok "Symlink: /usr/local/sbin/rc.hunter" ||
    info "Symlink skipped (non-critical)"

[ -n "${_EXTRACT:-}" ] && rm -rf "$_EXTRACT" 2>/dev/null

# -----------------------------------------------------------------------
# Snapshot
# -----------------------------------------------------------------------
info "Taking system snapshot..."
_snap="$INSTALL_ROOT/backups/snapshot_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$_snap"
for _f in /etc/passwd /etc/group /etc/master.passwd \
          /etc/rc /etc/rc.local /etc/rc.initial \
          /etc/ssh/sshd_config /cf/conf/config.xml \
          /etc/inc/config.inc /etc/inc/auth.inc \
          /usr/local/www/index.php \
          /usr/local/share/pfSense/pkg/repos/pfSense-repo.conf; do
    [ -f "$_f" ] || continue
    _dst="$_snap$(dirname "$_f")"; mkdir -p "$_dst"
    cp -p "$_f" "$_dst/"
done
for _b in /bin/sh /bin/ls /usr/bin/awk /usr/bin/grep /sbin/pfctl \
          /usr/local/sbin/pkg /usr/local/sbin/pkg-static; do
    [ -f "$_b" ] && sha256 "$_b" >> "$_snap/binary_checksums.txt" 2>/dev/null
done
ok "Snapshot: $_snap"

# -----------------------------------------------------------------------
# Done
# -----------------------------------------------------------------------
printf "\n${C}${B}  ============================================================${N}\n"
printf "${G}${B}  Setup complete!${N}\n"
printf "${C}${B}  ============================================================${N}\n\n"
printf "  Install dir : %s\n" "$INSTALL_ROOT"
printf "  Scripts dir : %s\n" "$INSTALL_SCRIPTS"
printf "  Snapshot    : %s\n" "$(basename "$_snap")"
printf "\n  ${B}To launch:${N}\n"
printf "    rc.hunter\n"
printf "    sh %s/rc.hunter\n\n" "$INSTALL_SCRIPTS"
