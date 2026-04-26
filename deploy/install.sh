#!/usr/bin/env bash
#
# NetFirewall production installer for Debian / Ubuntu / Rocky / Alma / openSUSE.
# Runs from a checked-out repo on the target server. Builds, installs, configures,
# enables and starts both systemd units.
#
# Usage (as root):
#   deploy/install.sh                       # interactive
#   deploy/install.sh --noninteractive      # use defaults + env vars (CI)
#   deploy/install.sh --skip-publish        # reuse a previous publish
#   deploy/install.sh --uninstall           # see uninstall.sh
#
# Idempotent: re-running upgrades existing installs in-place.

set -euo pipefail

# ───────────────────────────── config ─────────────────────────────

readonly PREFIX=/opt/netfirewall
readonly ETC_DIR=/etc/netfirewall
readonly STATE_DIR=/var/lib/netfirewall
readonly LOG_DIR=/var/log/netfirewall
readonly RUN_DIR=/run/netfirewall
readonly GROUP_NAME=netfirewall
readonly WEB_USER=netfirewall-web
readonly DAEMON_PORT_WEB=5000

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

NONINTERACTIVE=0
SKIP_PUBLISH=0

for arg in "$@"; do
    case "$arg" in
        --noninteractive) NONINTERACTIVE=1 ;;
        --skip-publish)   SKIP_PUBLISH=1 ;;
        -h|--help)
            grep -E '^#( |!)' "$0" | sed 's/^# \?//'
            exit 0
            ;;
    esac
done

# ───────────────────────────── helpers ─────────────────────────────

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m  %s\n' "$*" >&2; }
fail() { printf '\033[1;31m✗\033[0m  %s\n' "$*" >&2; exit 1; }

require_root() { [[ $EUID -eq 0 ]] || fail "must run as root (use sudo)"; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "missing dependency: $1 — install it first"
}

prompt() {
    local var="$1" prompt_text="$2" default="${3:-}"
    if [[ $NONINTERACTIVE -eq 1 ]]; then
        printf -v "$var" '%s' "${!var:-$default}"
        return
    fi
    local current="${!var:-$default}"
    local input
    if [[ -n "$current" ]]; then
        read -rp "$prompt_text [$current]: " input
    else
        read -rp "$prompt_text: " input
    fi
    printf -v "$var" '%s' "${input:-$current}"
}

# ───────────────────────────── preflight ─────────────────────────────

require_root
require_cmd systemctl
require_cmd dotnet
require_cmd psql      # for the migration runner / sanity probe
require_cmd openssl

if ! systemctl --version >/dev/null 2>&1; then
    fail "systemd not detected — this installer targets systemd hosts only"
fi

log "NetFirewall installer · running from $REPO_DIR"

# ───────────────────────────── prompt for secrets ─────────────────────────────

PG_PASSWORD="${PG_PASSWORD:-}"
prompt PG_PASSWORD "PostgreSQL password for the netfirewall DB user" ""
[[ -n "$PG_PASSWORD" ]] || fail "PostgreSQL password required"

PG_HOST="${PG_HOST:-127.0.0.1}"
prompt PG_HOST "PostgreSQL host" "127.0.0.1"

PG_DATABASE="${PG_DATABASE:-net_firewall}"
prompt PG_DATABASE "PostgreSQL database" "net_firewall"

PG_USER="${PG_USER:-netfirewall}"
prompt PG_USER "PostgreSQL user" "netfirewall"

# ───────────────────────────── users + dirs ─────────────────────────────

log "Ensuring group and user accounts"
if ! getent group "$GROUP_NAME" >/dev/null; then
    groupadd --system "$GROUP_NAME"
fi
if ! getent passwd "$WEB_USER" >/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
            --gid "$GROUP_NAME" --home "$STATE_DIR/web" "$WEB_USER"
else
    usermod -aG "$GROUP_NAME" "$WEB_USER" 2>/dev/null || true
fi

WEB_UID=$(id -u "$WEB_USER")

log "Creating directories"
install -d -m 0755 -o root -g root              "$PREFIX"
install -d -m 0750 -o root -g "$GROUP_NAME"     "$ETC_DIR"
install -d -m 0750 -o root -g root              "$STATE_DIR" "$STATE_DIR/daemon"
install -d -m 0750 -o "$WEB_USER" -g "$GROUP_NAME" "$STATE_DIR/web"
install -d -m 0750 -o root -g root              "$LOG_DIR" "$LOG_DIR/daemon"
install -d -m 0750 -o "$WEB_USER" -g "$GROUP_NAME" "$LOG_DIR/web"

# ───────────────────────────── publish ─────────────────────────────

if [[ $SKIP_PUBLISH -eq 0 ]]; then
    log "Publishing daemon (Release / linux-x64)"
    dotnet publish -c Release -r linux-x64 --self-contained false \
        -o "$PREFIX/daemon" \
        "$REPO_DIR/NetFirewall.Daemon/NetFirewall.Daemon.csproj" >/dev/null

    log "Publishing web"
    dotnet publish -c Release -r linux-x64 --self-contained false \
        -o "$PREFIX/web" \
        "$REPO_DIR/NetFirewall.Web/NetFirewall.Web.csproj" >/dev/null

    log "Publishing migration runner"
    dotnet publish -c Release -r linux-x64 --self-contained false \
        -o "$PREFIX/migrations" \
        "$REPO_DIR/NetFirewall.Migrations/NetFirewall.Migrations.csproj" >/dev/null

    # Copy SQL migration files alongside the binary.
    install -d -m 0755 "$PREFIX/migrations/sql/migrations"
    install -m 0644 "$REPO_DIR/NetFirewall.Services/sql/migrations/"*.sql \
            "$PREFIX/migrations/sql/migrations/"
fi

# Web's wwwroot lives under the publish output already; chmod for nginx-alike
# users that may proxy static files separately.
chown -R "$WEB_USER:$GROUP_NAME" "$PREFIX/web/wwwroot" 2>/dev/null || true

# ───────────────────────────── config + secrets ─────────────────────────────

log "Writing config files"
install -m 0640 -o root -g "$GROUP_NAME" \
    "$SCRIPT_DIR/config/daemon.json.template" "$PREFIX/daemon/appsettings.Production.json"
install -m 0640 -o root -g "$GROUP_NAME" \
    "$SCRIPT_DIR/config/web.json.template" "$PREFIX/web/appsettings.Production.json"

log "Writing environment files"

# Daemon env (root-only — peer UID + DB password live here).
DAEMON_ENV="$ETC_DIR/daemon.env"
sed -e "s|__REPLACE__|$PG_PASSWORD|" -e "s|Daemon__ExpectedPeerUid=__REPLACE__|Daemon__ExpectedPeerUid=$WEB_UID|" \
    "$SCRIPT_DIR/env/daemon.env.template" > "$DAEMON_ENV.tmp"
sed -i \
    -e "s|Host=127.0.0.1;Port=5432|Host=$PG_HOST;Port=5432|" \
    -e "s|Username=netfirewall|Username=$PG_USER|" \
    -e "s|Database=net_firewall|Database=$PG_DATABASE|" \
    "$DAEMON_ENV.tmp"
install -m 0600 -o root -g root "$DAEMON_ENV.tmp" "$DAEMON_ENV"
rm -f "$DAEMON_ENV.tmp"

# Web env. Generate master key only if not already present (preserves TOTP enrollments on upgrade).
WEB_ENV="$ETC_DIR/web.env"
if [[ -f "$WEB_ENV" ]] && grep -q '^NETFIREWALL_MASTER_KEY=' "$WEB_ENV" \
        && ! grep -q '^NETFIREWALL_MASTER_KEY=__REPLACE__' "$WEB_ENV"; then
    log "Preserving existing master key from $WEB_ENV"
    MASTER_KEY=$(grep '^NETFIREWALL_MASTER_KEY=' "$WEB_ENV" | head -1 | cut -d= -f2-)
else
    log "Generating new AES-256 master key"
    MASTER_KEY=$(openssl rand -base64 32)
fi

sed -e "s|__REPLACE__|placeholder|" "$SCRIPT_DIR/env/web.env.template" > "$WEB_ENV.tmp"
# Two REPLACE tokens: connection string password, and master key. Apply distinctly.
sed -i \
    -e "0,/__REPLACE__/{s|__REPLACE__|$PG_PASSWORD|}" \
    -e "s|NETFIREWALL_MASTER_KEY=placeholder|NETFIREWALL_MASTER_KEY=$MASTER_KEY|" \
    -e "s|Host=127.0.0.1;Port=5432|Host=$PG_HOST;Port=5432|" \
    -e "s|Username=netfirewall|Username=$PG_USER|" \
    -e "s|Database=net_firewall|Database=$PG_DATABASE|" \
    "$WEB_ENV.tmp"
install -m 0640 -o root -g "$WEB_USER" "$WEB_ENV.tmp" "$WEB_ENV"
rm -f "$WEB_ENV.tmp"

log "Master key (KEEP A SECURE BACKUP — losing it invalidates all TOTP enrollments):"
echo "    NETFIREWALL_MASTER_KEY=$MASTER_KEY"

# ───────────────────────────── migrations ─────────────────────────────

log "Applying database migrations"
NETFIREWALL_CONN="Host=$PG_HOST;Port=5432;Username=$PG_USER;Password=$PG_PASSWORD;Database=$PG_DATABASE" \
    dotnet "$PREFIX/migrations/netfirewall-migrate.dll" up \
        --dir "$PREFIX/migrations/sql/migrations"

# ───────────────────────────── systemd ─────────────────────────────

log "Installing systemd units"
install -m 0644 "$SCRIPT_DIR/systemd/netfirewall-daemon.service" /etc/systemd/system/
install -m 0644 "$SCRIPT_DIR/systemd/netfirewall-web.service"    /etc/systemd/system/
systemctl daemon-reload

log "Enabling + starting services"
systemctl enable --now netfirewall-daemon.service
sleep 1
systemctl enable --now netfirewall-web.service

# ───────────────────────────── done ─────────────────────────────

cat <<EOF

\033[1;32m✓ NetFirewall installed.\033[0m

  Daemon : systemctl status netfirewall-daemon
  Web    : systemctl status netfirewall-web
  Logs   : $LOG_DIR/{daemon,web}/
  Config : $ETC_DIR/{daemon,web}.env  (mode 0600/0640)
  Socket : $RUN_DIR/control.sock      (root:netfirewall 0660)
  Web URL: http://127.0.0.1:$DAEMON_PORT_WEB  (set up TLS via the nginx example in deploy/nginx)

Next steps:
  1. Configure your reverse proxy (deploy/nginx/netfirewall.conf for nginx).
  2. Open a browser to https://your-host/setup/bootstrap?token=<...>
     (token printed to journalctl -u netfirewall-web on first start with empty users table).
  3. Create the first admin → enroll TOTP → walk through the setup wizard.

To upgrade later: re-run this installer (preserves master key + TOTP enrollments).
To remove:        deploy/uninstall.sh

EOF
