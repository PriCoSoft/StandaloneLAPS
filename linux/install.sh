#!/bin/sh
# SLAPS Linux agent installer. Run as root from the extracted SLAPS client package:
#   sudo sh install.sh [--api-url URL] [--no-start] [--skip-connectivity-test]
#   sudo sh install.sh --uninstall [--purge]
# Debian/Ubuntu: installs the included .deb. Other systemd distributions: copies the files directly.
set -eu

DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
API_URL=""
NO_START=0
SKIP_TEST=0
UNINSTALL=0
PURGE=0

step() { printf '\n==> %s\n' "$1"; }
fail() { printf 'ERROR: %s\n' "$1" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --api-url) [ $# -ge 2 ] || fail "--api-url needs a value"; API_URL="$2"; shift 2 ;;
        --no-start) NO_START=1; shift ;;
        --skip-connectivity-test) SKIP_TEST=1; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        --purge) PURGE=1; shift ;;
        -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
        *) fail "unknown option: $1" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || fail "run as root, e.g. sudo sh install.sh"
command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ] || fail "systemd is required"

deb_installed() { command -v dpkg-query >/dev/null 2>&1 && dpkg-query -W -f='${Status}' slaps-agent 2>/dev/null | grep -q 'install ok installed'; }

if [ "$UNINSTALL" -eq 1 ]; then
    step "Removing the SLAPS agent"
    systemctl disable --now slaps-agent.service >/dev/null 2>&1 || true
    if deb_installed; then
        if [ "$PURGE" -eq 1 ]; then dpkg --purge slaps-agent; else dpkg --remove slaps-agent; fi
    fi
    rm -f /usr/sbin/slaps-agent /etc/systemd/system/slaps-agent.service
    systemctl daemon-reload
    if [ "$PURGE" -eq 1 ]; then rm -rf /etc/slaps /var/lib/slaps; echo "Configuration, keys and state removed."; else echo "Kept /etc/slaps and /var/lib/slaps (use --purge to remove)."; fi
    echo "Done. The last password of the account stays valid and is stored on the SLAPS server."
    exit 0
fi

step "Checking prerequisites"
command -v python3 >/dev/null 2>&1 || fail "python3 is required (e.g. apt install python3 / dnf install python3)"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' || fail "Python 3.6 or newer is required"
command -v openssl >/dev/null 2>&1 || fail "the openssl command is required (e.g. apt install openssl)"
command -v chpasswd >/dev/null 2>&1 || fail "chpasswd is required (package passwd/shadow-utils)"
for file in slaps-settings.json agent.pfx recovery.cer; do
    [ -f "$DIR/$file" ] || fail "$file is missing; run install.sh from the extracted SLAPS client package"
done
echo "python3 $(python3 -c 'import platform; print(platform.python_version())'), $(openssl version)"

step "Installing the agent"
DEB=$(ls "$DIR"/slaps-agent_*_all.deb 2>/dev/null | head -n 1 || true)
if command -v dpkg >/dev/null 2>&1 && [ -n "$DEB" ]; then
    dpkg -i "$DEB"
    echo "Installed $(basename "$DEB")."
else
    [ -f "$DIR/slaps-agent" ] && [ -f "$DIR/slaps-agent.service" ] || fail "agent files are missing in the package"
    install -m 0755 -o root -g root "$DIR/slaps-agent" /usr/sbin/slaps-agent
    install -m 0644 -o root -g root "$DIR/slaps-agent.service" /etc/systemd/system/slaps-agent.service
    install -d -m 0755 /etc/slaps
    install -d -m 0700 /var/lib/slaps
    if [ ! -f /etc/slaps/agent.conf ]; then install -m 0644 "$DIR/agent.conf" /etc/slaps/agent.conf; fi
    systemctl daemon-reload
    echo "Installed /usr/sbin/slaps-agent and the systemd unit."
fi

step "Checking the local cryptography"
slaps-agent self-test

step "Importing certificate and settings"
if [ -z "${SLAPS_PFX_PASSWORD:-}" ]; then
    printf 'PFX password (shown once in the SLAPS portal): '
    stty -echo 2>/dev/null || true
    IFS= read -r SLAPS_PFX_PASSWORD || true
    stty echo 2>/dev/null || true
    printf '\n'
fi
export SLAPS_PFX_PASSWORD
if [ -n "$API_URL" ]; then slaps-agent enroll "$DIR" --api-url "$API_URL"; else slaps-agent enroll "$DIR"; fi
unset SLAPS_PFX_PASSWORD

step "Validating the configuration (/etc/slaps/agent.conf)"
slaps-agent validate-config

if [ "$SKIP_TEST" -eq 0 ]; then
    step "Testing the connection to the SLAPS server"
    slaps-agent test-connection || fail "connectivity test failed: check DNS, firewall (HTTPS), the server's TLS CA (CaFile in /etc/slaps/agent.conf) and the client certificate pin in the portal"
fi

systemctl enable slaps-agent.service >/dev/null 2>&1
if [ "$NO_START" -eq 0 ]; then
    systemctl restart slaps-agent.service
    echo "Service slaps-agent started. Log: journalctl -u slaps-agent"
else
    echo "Service slaps-agent enabled but not started (--no-start)."
fi

printf '\nDone. Delete this package folder now: agent.pfx contains the agent private key.\n'
