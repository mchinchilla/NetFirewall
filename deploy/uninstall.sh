#!/usr/bin/env bash
#
# Reverses what install.sh did. Default: keeps user data ($STATE_DIR + $ETC_DIR).
# Pass --purge to also remove configs, master key, logs, the netfirewall users
# AND the database (the database drop must be confirmed interactively).
#
# Usage (as root):
#   deploy/uninstall.sh
#   deploy/uninstall.sh --purge

set -euo pipefail

readonly PREFIX=/opt/netfirewall
readonly ETC_DIR=/etc/netfirewall
readonly STATE_DIR=/var/lib/netfirewall
readonly LOG_DIR=/var/log/netfirewall
readonly RUN_DIR=/run/netfirewall
readonly GROUP_NAME=netfirewall
readonly WEB_USER=netfirewall-web

PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m  %s\n' "$*" >&2; }

[[ $EUID -eq 0 ]] || { echo "must run as root"; exit 1; }

log "Stopping + disabling services"
systemctl disable --now netfirewall-dhcp.service   2>/dev/null || true
systemctl disable --now netfirewall-web.service    2>/dev/null || true
systemctl disable --now netfirewall-daemon.service 2>/dev/null || true

log "Removing systemd units"
rm -f /etc/systemd/system/netfirewall-{daemon,web,dhcp}.service
systemctl daemon-reload

log "Removing sysctl drop-in"
rm -f /etc/sysctl.d/netfirewall.conf

log "Removing TUI symlink + manpage + completion (if present)"
rm -f /usr/local/bin/netfirewall-tui
rm -f /usr/local/bin/netfirewall-doctor
rm -f /usr/local/share/man/man1/netfirewall-tui.1
rm -f /etc/bash_completion.d/netfirewall-tui

log "Removing $PREFIX"
rm -rf "$PREFIX"

if [[ $PURGE -eq 1 ]]; then
    warn "PURGE mode — removing config + secrets + state + logs + users."
    read -rp "Type 'purge' to confirm: " confirm
    [[ "$confirm" == "purge" ]] || { echo "Aborted."; exit 1; }

    rm -rf "$ETC_DIR" "$STATE_DIR" "$LOG_DIR" "$RUN_DIR"
    userdel "$WEB_USER" 2>/dev/null || true
    groupdel "$GROUP_NAME" 2>/dev/null || true

    warn "The PostgreSQL database is NOT touched. To drop it manually:"
    echo "    psql -U postgres -c 'DROP DATABASE net_firewall;'"
    echo "    psql -U postgres -c 'DROP ROLE netfirewall;'"
else
    log "Preserved: $ETC_DIR (configs + master key), $STATE_DIR, $LOG_DIR, PG database, '$WEB_USER' user."
    log "Re-running install.sh later resumes with all data intact."
fi

log "Done."
