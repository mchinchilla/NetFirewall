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
readonly TUI_SYMLINK=/usr/local/bin/netfirewall-tui

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

# ── DHCP server (optional) ──
# Binds UDP/67, so it's opt-in: only install it on hosts that should serve DHCP.
# INSTALL_DHCP accepts yes/no (env-overridable for CI). DHCP_IFACE is the fallback
# listening interface written to dhcp.env (enabled DB subnets override it at runtime).
INSTALL_DHCP="${INSTALL_DHCP:-no}"
prompt INSTALL_DHCP "Install the DHCP server? (binds UDP/67) [yes/no]" "no"
case "${INSTALL_DHCP,,}" in
    y|yes|true|1) INSTALL_DHCP=yes ;;
    *)            INSTALL_DHCP=no ;;
esac

DHCP_IFACE="${DHCP_IFACE:-ens256}"
if [[ "$INSTALL_DHCP" == "yes" ]]; then
    prompt DHCP_IFACE "DHCP fallback listening interface" "ens256"
fi

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
if [[ "$INSTALL_DHCP" == "yes" ]]; then
    # DHCP runs as root; systemd's LogsDirectory= also provisions this, but create
    # it here so a --skip-publish re-run or manual start has it ready.
    install -d -m 0750 -o root -g root          "$LOG_DIR/dhcp"
fi

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

    log "Publishing TUI"
    dotnet publish -c Release -r linux-x64 --self-contained false \
        -o "$PREFIX/tui" \
        "$REPO_DIR/NetFirewall.Tui/NetFirewall.Tui.csproj" >/dev/null

    log "Publishing Doctor (requirements validator)"
    dotnet publish -c Release -r linux-x64 --self-contained false \
        -o "$PREFIX/doctor" \
        "$REPO_DIR/NetFirewall.Doctor/NetFirewall.Doctor.csproj" >/dev/null

    if [[ "$INSTALL_DHCP" == "yes" ]]; then
        log "Publishing DHCP server"
        dotnet publish -c Release -r linux-x64 --self-contained false \
            -o "$PREFIX/dhcp-server" \
            "$REPO_DIR/NetFirewall.DhcpServer/NetFirewall.DhcpServer.csproj" >/dev/null
    fi
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

WEB_ENV="$ETC_DIR/web.env"
DAEMON_ENV="$ETC_DIR/daemon.env"

# ── Master key: resolve ONCE, then write the SAME value into BOTH env files. ──
# The daemon AND the Web must hold the identical AES-256 key: the Web enrolls TOTP
# secrets and (with Daemon:UseForTotp=true) the daemon decrypts/verifies them
# (login crypto endpoints + the web terminal's TOTP gate). A drift between the two
# files is silent — every valid TOTP code gets rejected daemon-side. So we compute
# it before writing either file. Preference order for an UPGRADE (preserve, never
# rotate — rotating invalidates all enrollments): existing web.env, then daemon.env.
resolve_existing_key() {
    local f
    for f in "$WEB_ENV" "$DAEMON_ENV"; do
        if [[ -f "$f" ]] && grep -q '^NETFIREWALL_MASTER_KEY=' "$f" \
                && ! grep -qE '^NETFIREWALL_MASTER_KEY=(__REPLACE__|__REPLACE_MASTER_KEY__|placeholder)$' "$f"; then
            grep '^NETFIREWALL_MASTER_KEY=' "$f" | head -1 | cut -d= -f2-
            return 0
        fi
    done
    return 1
}

if MASTER_KEY=$(resolve_existing_key); then
    log "Preserving existing master key"
else
    log "Generating new AES-256 master key"
    MASTER_KEY=$(openssl rand -base64 32)
fi

# Daemon env (root-only — peer UID + DB password + master key live here).
# REPLACE tokens in the template: DB password (first __REPLACE__), the Web UID
# for AcceptedPeerUids[0], and the master key (__REPLACE_MASTER_KEY__).
sed -e "0,/__REPLACE__/{s|__REPLACE__|$PG_PASSWORD|}" \
    -e "s|Daemon__AcceptedPeerUids__0=__REPLACE__|Daemon__AcceptedPeerUids__0=$WEB_UID|" \
    -e "s|NETFIREWALL_MASTER_KEY=__REPLACE_MASTER_KEY__|NETFIREWALL_MASTER_KEY=$MASTER_KEY|" \
    "$SCRIPT_DIR/env/daemon.env.template" > "$DAEMON_ENV.tmp"
sed -i \
    -e "s|Host=127.0.0.1;Port=5432|Host=$PG_HOST;Port=5432|" \
    -e "s|Username=netfirewall|Username=$PG_USER|" \
    -e "s|Database=net_firewall|Database=$PG_DATABASE|" \
    "$DAEMON_ENV.tmp"
install -m 0600 -o root -g root "$DAEMON_ENV.tmp" "$DAEMON_ENV"
rm -f "$DAEMON_ENV.tmp"

# Web env (root:netfirewall 0640 — Web reads it, group lets the unit load it).
# Distinct tokens: __REPLACE__ = DB password (only occurrence), and
# __REPLACE_MASTER_KEY__ = master key. No ordering hazard between the two.
sed -e "s|Password=__REPLACE__|Password=$PG_PASSWORD|" \
    -e "s|NETFIREWALL_MASTER_KEY=__REPLACE_MASTER_KEY__|NETFIREWALL_MASTER_KEY=$MASTER_KEY|" \
    -e "s|Host=127.0.0.1;Port=5432|Host=$PG_HOST;Port=5432|" \
    -e "s|Username=netfirewall|Username=$PG_USER|" \
    -e "s|Database=net_firewall|Database=$PG_DATABASE|" \
    "$SCRIPT_DIR/env/web.env.template" > "$WEB_ENV.tmp"
install -m 0640 -o root -g "$WEB_USER" "$WEB_ENV.tmp" "$WEB_ENV"
rm -f "$WEB_ENV.tmp"

# Defensive post-condition: both files must carry the SAME real key. Catches any
# future template/token drift before it becomes a silent prod TOTP outage.
if ! diff -q \
        <(grep '^NETFIREWALL_MASTER_KEY=' "$DAEMON_ENV") \
        <(grep '^NETFIREWALL_MASTER_KEY=' "$WEB_ENV") >/dev/null 2>&1; then
    echo "FATAL: master key differs between $DAEMON_ENV and $WEB_ENV — daemon TOTP would fail." >&2
    exit 1
fi

log "Master key (KEEP A SECURE BACKUP — losing it invalidates all TOTP enrollments):"
echo "    NETFIREWALL_MASTER_KEY=$MASTER_KEY"

# DHCP env (root:root 0640 — holds the DB password; DHCP runs as root). Optional
# file: the unit loads it with EnvironmentFile=- and the server still reads its
# bundled appsettings.json. We write it so the DHCP connection string + listening
# interface come from one host-specific place instead of the published JSON.
if [[ "$INSTALL_DHCP" == "yes" ]]; then
    DHCP_ENV="$ETC_DIR/dhcp.env"
    sed -e "s|Password=__REPLACE__|Password=$PG_PASSWORD|" \
        -e "s|__REPLACE_DHCP_IFACE__|$DHCP_IFACE|" \
        -e "s|Host=127.0.0.1;Port=5432|Host=$PG_HOST;Port=5432|" \
        -e "s|Username=netfirewall|Username=$PG_USER|" \
        -e "s|Database=net_firewall|Database=$PG_DATABASE|" \
        "$SCRIPT_DIR/env/dhcp.env.template" > "$DHCP_ENV.tmp"
    install -m 0640 -o root -g root "$DHCP_ENV.tmp" "$DHCP_ENV"
    rm -f "$DHCP_ENV.tmp"
fi

# ───────────────────────────── TUI config + symlink ─────────────────────────────

# The TUI runs ad-hoc (no systemd unit) — needs minimal config telling it
# where the daemon socket lives. Mode 0644 because anyone running the TUI
# (typically root via sudo) needs to read it.
TUI_CONFIG="$PREFIX/tui/appsettings.json"
cat >"$TUI_CONFIG" <<EOF
{
  "Daemon": {
    "SocketPath": "$RUN_DIR/control.sock",
    "SessionHeader": "X-NetFw-Session",
    "Timeout": "00:00:10"
  },
  "Logging": { "LogLevel": { "Default": "Warning" } }
}
EOF
chmod 0644 "$TUI_CONFIG"

# Convenience symlink so operators can run `netfirewall-tui` directly
# instead of `dotnet /opt/netfirewall/tui/netfirewall-tui.dll`. We wrap the
# dotnet invocation in a tiny shim because the publish output is a managed
# DLL with a launcher executable next to it — both must stay together.
TUI_LAUNCHER="$PREFIX/tui/netfirewall-tui"
if [[ ! -x "$TUI_LAUNCHER" ]]; then
    # The publish target produces a native launcher; if absent, write a shim.
    cat >"$TUI_LAUNCHER" <<EOF
#!/usr/bin/env bash
exec dotnet "$PREFIX/tui/netfirewall-tui.dll" "\$@"
EOF
    chmod 0755 "$TUI_LAUNCHER"
fi
ln -sfn "$TUI_LAUNCHER" "$TUI_SYMLINK"

# Same shim + symlink for the Doctor validator so operators can run
# `netfirewall-doctor` directly.
DOCTOR_LAUNCHER="$PREFIX/doctor/netfirewall-doctor"
if [[ ! -x "$DOCTOR_LAUNCHER" ]]; then
    cat >"$DOCTOR_LAUNCHER" <<EOF
#!/usr/bin/env bash
exec dotnet "$PREFIX/doctor/netfirewall-doctor.dll" "\$@"
EOF
    chmod 0755 "$DOCTOR_LAUNCHER"
fi
ln -sfn "$DOCTOR_LAUNCHER" /usr/local/bin/netfirewall-doctor

# Manpage + bash completion for the TUI. Both are best-effort: skip silently
# if the system doesn't have the standard target dirs (some minimal distros
# strip them).
if [[ -d /usr/local/share/man/man1 ]]; then
    install -m 0644 "$SCRIPT_DIR/man/netfirewall-tui.1" \
        /usr/local/share/man/man1/netfirewall-tui.1
fi
if [[ -d /etc/bash_completion.d ]]; then
    install -m 0644 "$SCRIPT_DIR/completion/netfirewall-tui" \
        /etc/bash_completion.d/netfirewall-tui
fi

# ───────────────────────────── migrations ─────────────────────────────

log "Applying database migrations"
NETFIREWALL_CONN="Host=$PG_HOST;Port=5432;Username=$PG_USER;Password=$PG_PASSWORD;Database=$PG_DATABASE" \
    dotnet "$PREFIX/migrations/netfirewall-migrate.dll" up \
        --dir "$PREFIX/migrations/sql/migrations"

# ───────────────────────────── systemd ─────────────────────────────

log "Installing systemd units"
install -m 0644 "$SCRIPT_DIR/systemd/netfirewall-daemon.service" /etc/systemd/system/
install -m 0644 "$SCRIPT_DIR/systemd/netfirewall-web.service"    /etc/systemd/system/
if [[ "$INSTALL_DHCP" == "yes" ]]; then
    install -m 0644 "$SCRIPT_DIR/systemd/netfirewall-dhcp.service" /etc/systemd/system/
else
    # If DHCP was previously installed and is now being opted out, stop + remove
    # the unit so we don't leave a dangling UDP/67 binder behind.
    if [[ -f /etc/systemd/system/netfirewall-dhcp.service ]]; then
        systemctl disable --now netfirewall-dhcp.service 2>/dev/null || true
        rm -f /etc/systemd/system/netfirewall-dhcp.service
    fi
fi
systemctl daemon-reload

# Kernel tunables — enables conntrack per-flow accounting so the dashboard's
# top-talkers panel has byte counters to read. The daemon itself can't write
# /proc/sys because its unit sets ProtectKernelTunables=yes.
#
# The sysctl drop-in ALONE does not survive reboots: systemd-sysctl runs
# before nf_conntrack is loaded (nftables loads it later), so the
# nf_conntrack_acct key doesn't exist yet and the write is silently skipped.
# Hence the modprobe.d default (applies at module load, order-independent)
# and the modules-load.d entry (loads the module before systemd-sysctl).
log "Installing sysctl + modprobe + modules-load drop-ins"
install -m 0644 "$SCRIPT_DIR/sysctl/netfirewall.conf" /etc/sysctl.d/netfirewall.conf
install -m 0644 "$SCRIPT_DIR/modprobe.d/netfirewall.conf" /etc/modprobe.d/netfirewall.conf
install -m 0644 "$SCRIPT_DIR/modules-load.d/netfirewall.conf" /etc/modules-load.d/netfirewall.conf
modprobe nf_conntrack 2>/dev/null || true
sysctl --quiet --load=/etc/sysctl.d/netfirewall.conf || \
    log "warning: sysctl --load failed; reboot or run \`sysctl --system\` manually"

log "Enabling + starting services"
systemctl enable --now netfirewall-daemon.service
sleep 1
systemctl enable --now netfirewall-web.service
if [[ "$INSTALL_DHCP" == "yes" ]]; then
    sleep 1
    systemctl enable --now netfirewall-dhcp.service
fi

# ───────────────────────────── post-install verification ─────────────────────────────

# Give the services a moment to bind sockets / open the DB before validating.
sleep 2
log "Running post-install verification (netfirewall-doctor)"
# Don't abort the install on a Doctor failure — the operator may still be mid-setup
# (no TLS yet, etc.). But surface problems loudly so issues like a missing/mismatched
# master key are caught NOW, not on first use.
if ! "$PREFIX/doctor/netfirewall-doctor"; then
    log "warning: netfirewall-doctor reported problems above — review them before going live."
fi

# ───────────────────────────── done ─────────────────────────────

DHCP_LINE=""
DHCP_LOG_LINE="{daemon,web}"
DHCP_CFG_LINE="{daemon,web}"
if [[ "$INSTALL_DHCP" == "yes" ]]; then
    DHCP_LINE="  DHCP   : systemctl status netfirewall-dhcp   (binds UDP/67; fallback iface=$DHCP_IFACE)"
    DHCP_LOG_LINE="{daemon,web,dhcp}"
    DHCP_CFG_LINE="{daemon,web,dhcp}"
fi

cat <<EOF

\033[1;32m✓ NetFirewall installed.\033[0m

  Daemon : systemctl status netfirewall-daemon
  Web    : systemctl status netfirewall-web
$DHCP_LINE
  TUI    : sudo netfirewall-tui    (console-only; reaches daemon as root via SO_PEERCRED)
  Doctor : netfirewall-doctor      (re-run anytime to validate the deployment; --json for CI)
  Logs   : $LOG_DIR/$DHCP_LOG_LINE/
  Config : $ETC_DIR/$DHCP_CFG_LINE.env  (mode 0600/0640)
  Socket : $RUN_DIR/control.sock      (root:netfirewall 0660 — Web UID + root accepted)
  Web URL: http://127.0.0.1:$DAEMON_PORT_WEB  (set up TLS via the nginx example in deploy/nginx)

Next steps:
  1. Configure your reverse proxy (deploy/nginx/netfirewall.conf for nginx).
  2. Open a browser to https://your-host/setup/bootstrap?token=<...>
     (token printed to journalctl -u netfirewall-web on first start with empty users table).
  3. Create the first admin → enroll TOTP → walk through the setup wizard.
  4. (Optional) On the console: \`sudo netfirewall-tui\` for offline / break-glass admin.

To upgrade later: re-run this installer (preserves master key + TOTP enrollments).
To remove:        deploy/uninstall.sh

EOF
