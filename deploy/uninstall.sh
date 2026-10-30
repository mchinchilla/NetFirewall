#!/usr/bin/env bash
#
# Reverses what setup.sh did. Default: keeps config, secrets, state, logs, the
# backups and the database — re-running setup.sh later resumes with everything
# intact. --purge also removes config + master key + state + logs + users (the
# database is never dropped automatically).
#
# Only NetFirewall's own pieces under the prefix are removed (releases/, current,
# .previous): the prefix may be shared with other products (/opt/tekium).
#
# Usage (as root):
#   ./uninstall.sh
#   ./uninstall.sh --purge
#
set -euo pipefail

readonly ETC_DIR=/etc/netfirewall
readonly STATE_DIR=/var/lib/netfirewall
readonly LOG_DIR=/var/log/netfirewall
readonly RUN_DIR=/run/netfirewall
readonly GROUP_NAME=netfirewall
readonly WEB_USER=netfirewall-web

if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
    C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_ACCENT=$'\033[38;5;208m'
    C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'; C_OFF=$'\033[0m'
else
    C_OK=""; C_WARN=""; C_ERR=""; C_ACCENT=""; C_DIM=""; C_BOLD=""; C_OFF=""
fi
step() { printf '\n %s▸%s %s%s%s\n' "$C_ACCENT" "$C_OFF" "$C_BOLD" "$1" "$C_OFF"; }
ok()   { printf '   %s✓%s %s\n' "$C_OK" "$C_OFF" "$1"; }
warn() { printf '   %s!%s %s\n' "$C_WARN" "$C_OFF" "$1" >&2; }
fail() { printf '\n  %s✗ %s%s\n\n' "$C_ERR" "$1" "$C_OFF" >&2; exit 1; }

PURGE=false
case "${1:-}" in
    --purge)   PURGE=true ;;
    -h|--help) sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    "")        ;;
    *)         fail "unknown option: $1" ;;
esac

[[ $EUID -eq 0 ]] || fail "run as root"

# The prefix setup.sh used (saved only when it differs from the default).
PREFIX=/opt/tekium
if [[ -f "$ETC_DIR/setup.conf" ]]; then
    saved=$(sed -n 's/^PREFIX="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$ETC_DIR/setup.conf" | tail -1)
    [[ -n "$saved" ]] && PREFIX="$saved"
fi

printf '\n  %sNetFirewall uninstall%s  %s%s%s\n' "$C_BOLD" "$C_OFF" "$C_DIM" "prefix $PREFIX" "$C_OFF"

if [[ "$PURGE" == true ]]; then
    warn "PURGE: config, master key (every TOTP enrollment), state, logs and users go too."
    read -rp "   Type 'purge' to confirm: " confirm
    [[ "$confirm" == "purge" ]] || fail "aborted, nothing changed"
fi

step "Services"
for unit in netfirewall-bootstrap netfirewall-dhcp netfirewall-web netfirewall-daemon; do
    systemctl disable --now "$unit.service" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/$unit.service"
done
systemctl daemon-reload
ok "units stopped, disabled and removed"

step "System files"
rm -f /etc/sysctl.d/netfirewall.conf /etc/modprobe.d/netfirewall.conf \
      /etc/modules-load.d/netfirewall.conf /etc/tmpfiles.d/netfirewall.conf
rm -f /usr/local/bin/netfirewall-tui /usr/local/bin/netfirewall-doctor /usr/local/bin/netfirewall-migrate
rm -f /usr/local/share/man/man1/netfirewall-tui.1 /etc/bash_completion.d/netfirewall-tui
ok "drop-ins, console tools, man page and completion"
if [[ -f /etc/nginx/sites-available/netfirewall.conf ]]; then
    warn "nginx site left in place: /etc/nginx/sites-available/netfirewall.conf (remove it + reload nginx if unwanted)"
fi

step "Releases"
rm -rf "${PREFIX:?}/releases" "$PREFIX/current" "$PREFIX/.previous" "$PREFIX/.current.tmp"
ok "removed $PREFIX/releases, current, .previous"
rmdir "$PREFIX" 2>/dev/null && ok "removed empty $PREFIX" || true

if [[ "$PURGE" == true ]]; then
    step "Purge"
    rm -rf "$ETC_DIR" "$STATE_DIR" "$LOG_DIR" "$RUN_DIR"
    userdel "$WEB_USER" 2>/dev/null || true
    groupdel "$GROUP_NAME" 2>/dev/null || true
    ok "removed $ETC_DIR, $STATE_DIR, $LOG_DIR, user $WEB_USER, group $GROUP_NAME"
    warn "the PostgreSQL database and /var/backups/netfirewall are NOT touched. To drop the database:"
    printf '       %srunuser -u postgres -- psql -c "DROP DATABASE net_firewall;" -c "DROP ROLE netfirewall;"%s\n' "$C_DIM" "$C_OFF"
else
    ok "kept: $ETC_DIR (config + master key), $STATE_DIR, $LOG_DIR, backups, database, user $WEB_USER"
    printf '   %sRe-running ./setup.sh from a bundle resumes with all data intact.%s\n' "$C_DIM" "$C_OFF"
fi
echo
