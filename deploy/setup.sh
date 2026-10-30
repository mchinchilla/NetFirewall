#!/usr/bin/env bash
#
# NetFirewall installer / upgrader. Runs from an extracted release bundle
# (deploy/build-bundle.sh) on a Debian/Ubuntu host with systemd, as root.
#
# The same script installs and upgrades: every step detects what is already
# there and keeps it. Re-running on a live firewall never regenerates the master
# key or the DB password, never rewrites an existing env file wholesale, never
# touches the live nftables ruleset or the network config, and only restarts the
# NetFirewall services.
#
# Each version lands in <PREFIX>/releases/<version>; <PREFIX>/current is a
# symlink to the active one and is what the systemd units run. An upgrade is:
# back up the DB → stage the release → migrate with the NEW binaries → flip the
# symlink → restart → health-check. If the daemon or the Web do not come back,
# the symlink is flipped back and the services restarted on the previous release.
#
# Usage:  ./setup.sh [options]
#         ./setup.sh --preflight        check the host, change nothing
#         ./setup.sh --rollback [VER]   go back to the previous (or given) release
#         ./setup.sh --help
#
# Full reference: docs/setup.md
#
set -euo pipefail
shopt -u patsub_replacement 2>/dev/null || true   # bash 5.2: '&' literal in ${x//a/b}

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# BUNDLE_VERSION, not VERSION: /etc/os-release defines VERSION.
readonly BUNDLE_VERSION="$(cat "$SCRIPT_DIR/VERSION" 2>/dev/null || echo "")"
readonly BUNDLE_COMMIT="$(sed -n 's/^commit=//p' "$SCRIPT_DIR/BUILD_INFO" 2>/dev/null | cut -c1-12)"
readonly BUNDLE_APP="$SCRIPT_DIR/app"
readonly BUNDLE_DEPLOY="$SCRIPT_DIR/deploy"

# ─────────────────────────────── fixed layout ───────────────────────────────

readonly ETC_DIR=/etc/netfirewall
readonly STATE_DIR=/var/lib/netfirewall
readonly LOG_DIR=/var/log/netfirewall
readonly RUN_DIR=/run/netfirewall
readonly SETUP_CONF="$ETC_DIR/setup.conf"
readonly GROUP_NAME=netfirewall
readonly WEB_USER=netfirewall-web
readonly WEB_URL=http://127.0.0.1:5000
readonly SOCKET="$RUN_DIR/control.sock"
readonly UNIT_DIR=/etc/systemd/system
readonly DAEMON_ENV="$ETC_DIR/daemon.env"
readonly WEB_ENV="$ETC_DIR/web.env"
readonly DHCP_ENV="$ETC_DIR/dhcp.env"
readonly NGINX_SITE=/etc/nginx/sites-available/netfirewall.conf
readonly NGINX_ENABLED=/etc/nginx/sites-enabled/netfirewall.conf
readonly TLS_DIR="$ETC_DIR/tls"

# ─────────────────────────────── options ───────────────────────────────
# Defaults first, then the saved setup.conf, then the command line.

PREFIX=/opt/tekium
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=net_firewall
DB_USER=netfirewall
DB_PASSWORD=""
DB_EXPLICIT=false            # a --db-* flag was passed → rewrite the connection strings
INSTALL_DHCP=auto            # auto = keep whatever is installed now
DHCP_IFACE=""
DHCP_IFACE_EXPLICIT=false
BOOT_APPLY=auto              # auto = yes on a fresh install, else keep what is installed
CONFIGURE_NGINX=auto         # auto = only on a fresh install
TLS_CERT=""
TLS_KEY=""
SKIP_PACKAGES=false
APPLY_SEEDS=false
SKIP_BACKUP=false
BACKUP_DIR=/var/backups/netfirewall
BACKUP_KEEP=10
KEEP_RELEASES=3
SKIP_DOCTOR=false
ASSUME_YES=false
FORGET_OPTIONS=false
MODE=install                 # install | preflight | rollback | list
ROLLBACK_TO=""

# Options worth remembering between runs (never secrets: the password lives in the env files).
readonly SAVED_KEYS=(PREFIX DB_HOST DB_PORT DB_NAME DB_USER INSTALL_DHCP DHCP_IFACE BOOT_APPLY
                     SKIP_PACKAGES BACKUP_DIR BACKUP_KEEP KEEP_RELEASES)

# ─────────────────────────────── presentation ───────────────────────────────
#
# On a terminal: colours, a progress bar per step and a spinner while something
# runs. Anywhere else (a pipe, NO_COLOR, TERM=dumb) plain text with no control
# sequences. Command output never goes to the screen: it goes to the setup log,
# and the tail of it is shown when a command fails.

if [[ -t 1 && -z "${NO_COLOR:-}" && "${TERM:-dumb}" != "dumb" ]]; then
    C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_INFO=$'\033[36m'
    C_ACCENT=$'\033[38;5;208m'; C_DIM=$'\033[2m'; C_BOLD=$'\033[1m'; C_OFF=$'\033[0m'
    FANCY=true
else
    C_OK=""; C_WARN=""; C_ERR=""; C_INFO=""; C_ACCENT=""; C_DIM=""; C_BOLD=""; C_OFF=""
    FANCY=false
fi
# Box drawing and the spinner are multi-byte; ${#s} must count characters, not bytes.
if locale -a 2>/dev/null | grep -qix 'c.utf-\?8'; then export LC_ALL=C.UTF-8; fi

SETUP_LOG=/dev/null          # becomes a real file once we know we're root
SETUP_START=$SECONDS
WARNINGS=0
STEP_N=0
STEP_TOTAL=0                 # set per mode; 0 = unnumbered sections

elapsed() {   # seconds → "42s" / "3m 07s"
    local s="$1"
    if (( s >= 60 )); then printf '%dm %02ds' $((s / 60)) $((s % 60)); else printf '%ds' "$s"; fi
}
repeat() { local i out=""; for ((i = 0; i < $2; i++)); do out+="$1"; done; printf '%s' "$out"; }
tolog()  { printf '%s\n' "$*" >> "$SETUP_LOG"; }

step() {
    STEP_N=$((STEP_N + 1))
    tolog "" "=== ${STEP_N}${STEP_TOTAL:+/$STEP_TOTAL} $1"
    if (( STEP_TOTAL == 0 )); then
        printf '\n %s▸%s %s%s%s\n' "$C_ACCENT" "$C_OFF" "$C_BOLD" "$1" "$C_OFF"
        return 0
    fi
    (( STEP_N <= STEP_TOTAL )) || STEP_TOTAL=$STEP_N
    local pct=$(( STEP_N * 100 / STEP_TOTAL )) width=20 full
    full=$(( pct * width / 100 ))
    if [[ "$FANCY" == true ]]; then
        printf '\n %s%2d/%d%s  %s%-28s%s %s%s%s%s%s%s %s%3d%% · %s%s\n' \
            "$C_ACCENT" "$STEP_N" "$STEP_TOTAL" "$C_OFF" "$C_BOLD" "$1" "$C_OFF" \
            "$C_OK" "$(repeat '━' "$full")" "$C_OFF" "$C_DIM" "$(repeat '─' $((width - full)))" "$C_OFF" \
            "$C_DIM" "$pct" "$(elapsed $((SECONDS - SETUP_START)))" "$C_OFF"
    else
        printf '\n %d/%d. %s\n' "$STEP_N" "$STEP_TOTAL" "$1"
    fi
}
ok()   { printf '   %s✓%s %s\n' "$C_OK" "$C_OFF" "$1"; tolog "  ok: $1"; }
skip() { printf '   %s· %s%s\n' "$C_DIM" "$1" "$C_OFF"; tolog "  skip: $1"; }
info() { printf '   %s→%s %s\n' "$C_INFO" "$C_OFF" "$1"; tolog "  $1"; }
warn() { WARNINGS=$((WARNINGS + 1)); printf '   %s!%s %s\n' "$C_WARN" "$C_OFF" "$1" >&2; tolog "  WARN: $1"; }
kv()   { printf '   %s%-14s%s %s\n' "$C_DIM" "$1" "$C_OFF" "$2"; tolog "  $1 $2"; }
fail() {
    tolog "FATAL: $1"
    printf '\n  %s✗ %s%s\n' "$C_ERR" "$1" "$C_OFF" >&2
    [[ "$SETUP_LOG" == /dev/null ]] || printf '  %slog: %s%s\n' "$C_DIM" "$SETUP_LOG" "$C_OFF" >&2
    printf '\n' >&2
    exit 1
}

# run "Doing x…" "x done" cmd args…   → spinner, then ✓/✗ with the time it took;
#                                        returns the command's exit code.
# must …                               → same, but a failure stops the setup.
# Only the step text reaches the log header, never the command line: pass secrets
# as a prefix assignment (PGPASSWORD=… run …), which reaches the child through
# its environment and never shows in ps.
SPIN_PID=""
RUN_FROM=0
run() {
    local busy="$1" done_msg="$2"; shift 2
    local start=$SECONDS rc=0
    tolog "--- $busy"
    RUN_FROM=$(wc -l < "$SETUP_LOG" 2>/dev/null || echo 0)
    if [[ "$FANCY" == true ]]; then
        "$@" >> "$SETUP_LOG" 2>&1 < /dev/null &
        SPIN_PID=$!
        local frames=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏) i=0
        printf '\033[?25l'
        while kill -0 "$SPIN_PID" 2>/dev/null; do
            printf '\r   %s%s%s %s %s%s%s\033[K' "$C_ACCENT" "${frames[i++ % 10]}" "$C_OFF" \
                "$busy" "$C_DIM" "$(elapsed $((SECONDS - start)))" "$C_OFF"
            sleep 0.1
        done
        wait "$SPIN_PID" || rc=$?
        SPIN_PID=""
        printf '\r\033[K\033[?25h'
    else
        printf '   … %s\n' "$busy"
        "$@" >> "$SETUP_LOG" 2>&1 < /dev/null || rc=$?
    fi
    if (( rc != 0 )); then
        printf '   %s✗%s %s %s(%s)%s\n' "$C_ERR" "$C_OFF" "$busy" "$C_DIM" "$(elapsed $((SECONDS - start)))" "$C_OFF"
        tolog "  failed rc=$rc"
        return "$rc"
    fi
    printf '   %s✓%s %s %s(%s)%s\n' "$C_OK" "$C_OFF" "$done_msg" "$C_DIM" "$(elapsed $((SECONDS - start)))" "$C_OFF"
}
must() {
    local busy="$1" hint="${MUST_HINT:-}"
    run "$@" && return 0
    log_tail
    fail "${hint:-failed: $busy}"
}
log_tail() {   # output of the last run only
    [[ -s "$SETUP_LOG" ]] || return 0
    tail -n +"$((RUN_FROM + 1))" "$SETUP_LOG" | tail -n 15 | sed "s/^/     ${C_DIM}│${C_OFF} /" >&2
}

on_exit() {
    if [[ -n "$SPIN_PID" ]]; then kill "$SPIN_PID" 2>/dev/null || true; fi
    if [[ "$FANCY" == true ]]; then printf '\033[?25h'; fi
}
trap on_exit EXIT
trap 'on_exit; printf "\n"; exit 130' INT TERM

boxed() {   # colour line…   — width follows the longest line
    local l width=0 color="$1"; shift
    for l in "$@"; do if (( ${#l} > width )); then width=${#l}; fi; done
    if [[ "$FANCY" != true ]]; then
        printf '\n'; for l in "$@"; do printf '  %s\n' "$l"; done; return 0
    fi
    printf '\n  %s╭%s╮%s\n' "$color" "$(repeat '─' $((width + 2)))" "$C_OFF"
    for l in "$@"; do
        printf '  %s│%s %s%*s %s│%s\n' "$color" "$C_OFF" "$l" $((width - ${#l})) "" "$color" "$C_OFF"
    done
    printf '  %s╰%s╯%s\n' "$color" "$(repeat '─' $((width + 2)))" "$C_OFF"
}

banner() {   # subtitle
    if [[ "$FANCY" == true ]]; then
        printf '\n'
        printf '  %s    _   __     __  _______                         ____%s\n' "$C_ACCENT" "$C_OFF"
        printf '  %s   / | / /__  / /_/ ____(_)_______ _      ______ _/ / /%s\n' "$C_ACCENT" "$C_OFF"
        printf '  %s  /  |/ / _ \\/ __/ /_  / / ___/ _ \\ | /| / / __ `/ / / %s\n' "$C_ACCENT" "$C_OFF"
        printf '  %s / /|  /  __/ /_/ __/ / / /  /  __/ |/ |/ / /_/ / / /  %s\n' "$C_ACCENT" "$C_OFF"
        printf '  %s/_/ |_/\\___/\\__/_/   /_/_/   \\___/|__/|__/\\__,_/_/_/   %s\n' "$C_ACCENT" "$C_OFF"
        printf '\n  %s%s%s  %s%s%s%s\n' "$C_BOLD" "${BUNDLE_VERSION:-dev}" "$C_OFF" \
            "$C_DIM" "${BUNDLE_COMMIT:+commit $BUNDLE_COMMIT · }" "$1" "$C_OFF"
    else
        printf '\nNetFirewall %s — %s\n' "${BUNDLE_VERSION:-dev}" "$1"
    fi
}

usage() {
    cat <<EOF
${C_BOLD}NetFirewall setup${C_OFF} ${BUNDLE_VERSION:-(no VERSION file)}

${C_ACCENT}Usage${C_OFF}  ./setup.sh [options]          (as root, from the extracted bundle)

${C_ACCENT}Modes${C_OFF}
  (none)                   Install, or upgrade the installed release in place.
  --preflight              Check the host and the bundle; change nothing.
  --rollback [VERSION]     Switch back to the previous release (or VERSION) and restart.
  --list-releases          Show the installed releases and which one is active.

${C_ACCENT}Layout${C_OFF}
  --prefix DIR             Install root (default /opt/tekium). Releases go in
                           DIR/releases/<version>, DIR/current is the active one.
  --keep-releases N        Releases kept on disk after an upgrade (default 3, min 2).

${C_ACCENT}Database${C_OFF}
  --db-host HOST           PostgreSQL host (default 127.0.0.1). A local host is
  --db-port PORT           provisioned automatically: postgresql is installed if
  --db-name NAME           missing and the role + database are created.
  --db-user USER           (defaults 5432 / net_firewall / netfirewall)
  --db-password PASS       Kept from the env files on upgrades; generated for a
                           new local database; required for a new remote one.

${C_ACCENT}Services${C_OFF}
  --with-dhcp [--dhcp-iface IF]   Install + enable the DHCP server (binds UDP/67).
  --without-dhcp                  Stop and remove the DHCP unit.
  --with-boot-apply               Push the DB state into the kernel at every boot
  --without-boot-apply            (netfirewall-bootstrap.service). Default: on for new
                                  installs, unchanged on upgrades.

${C_ACCENT}Reverse proxy${C_OFF}
  --configure-nginx        Write the nginx TLS site (automatic only on a fresh install).
  --skip-nginx             Never touch nginx.
  --tls-cert FILE --tls-key FILE  Use this certificate instead of a self-signed one.

${C_ACCENT}Other${C_OFF}
  --skip-packages          Don't apt-get install anything; only check.
  --apply-seeds            Apply deploy/seeds/*.sql (idempotent, host-specific defaults).
  --skip-backup            Upgrade without the pg_dump safety copy.
  --backup-dir DIR         Where the pre-upgrade dumps go (default /var/backups/netfirewall).
  --backup-keep N          Dumps kept (default 10).
  --skip-doctor            Don't run netfirewall-doctor at the end.
  --forget-options         Ignore the options saved in $SETUP_CONF.
  -y, --yes                No confirmation prompt.
  -h, --help               This help.

Options that differ from the defaults are saved in $SETUP_CONF, so an
upgrade is just: ${C_BOLD}./setup.sh${C_OFF}       Full reference: docs/setup.md
EOF
}

is_true() { [[ "${1,,}" =~ ^(1|y|yes|true|on)$ ]]; }

# ─────────────────────────────── arguments ───────────────────────────────

# --forget-options must be known before setup.conf is read.
for a in "$@"; do if [[ "$a" == "--forget-options" ]]; then FORGET_OPTIONS=true; fi; done

load_saved_options() {
    [[ -f "$SETUP_CONF" && "$FORGET_OPTIONS" == false ]] || return 0
    # Parsed, not sourced: only whitelisted KEY=value lines are honoured.
    local line key value k
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ "$line" =~ ^([A-Z_]+)=\"?([^\"]*)\"?$ ]] || continue
        key="${BASH_REMATCH[1]}"; value="${BASH_REMATCH[2]}"
        for k in "${SAVED_KEYS[@]}"; do
            if [[ "$k" == "$key" ]]; then printf -v "$key" '%s' "$value"; fi
        done
    done < "$SETUP_CONF"
    return 0
}
load_saved_options

need_arg() { [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || fail "$1 needs a value"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --preflight)        MODE=preflight; shift ;;
        --rollback)         MODE=rollback; shift
                            if [[ $# -gt 0 && "$1" != --* ]]; then ROLLBACK_TO="$1"; shift; fi ;;
        --list-releases)    MODE=list; shift ;;
        --prefix)           need_arg "$@"; PREFIX="${2%/}"; shift 2 ;;
        --keep-releases)    need_arg "$@"; KEEP_RELEASES="$2"; shift 2 ;;
        --db-host)          need_arg "$@"; DB_HOST="$2"; DB_EXPLICIT=true; shift 2 ;;
        --db-port)          need_arg "$@"; DB_PORT="$2"; DB_EXPLICIT=true; shift 2 ;;
        --db-name)          need_arg "$@"; DB_NAME="$2"; DB_EXPLICIT=true; shift 2 ;;
        --db-user)          need_arg "$@"; DB_USER="$2"; DB_EXPLICIT=true; shift 2 ;;
        --db-password)      need_arg "$@"; DB_PASSWORD="$2"; DB_EXPLICIT=true; shift 2 ;;
        --with-dhcp)        INSTALL_DHCP=yes; shift ;;
        --without-dhcp)     INSTALL_DHCP=no; shift ;;
        --dhcp-iface)       need_arg "$@"; DHCP_IFACE="$2"; DHCP_IFACE_EXPLICIT=true; shift 2 ;;
        --with-boot-apply)  BOOT_APPLY=yes; shift ;;
        --without-boot-apply) BOOT_APPLY=no; shift ;;
        --configure-nginx)  CONFIGURE_NGINX=yes; shift ;;
        --skip-nginx)       CONFIGURE_NGINX=no; shift ;;
        --tls-cert)         need_arg "$@"; TLS_CERT="$2"; shift 2 ;;
        --tls-key)          need_arg "$@"; TLS_KEY="$2"; shift 2 ;;
        --skip-packages)    SKIP_PACKAGES=true; shift ;;
        --apply-seeds)      APPLY_SEEDS=true; shift ;;
        --skip-backup)      SKIP_BACKUP=true; shift ;;
        --backup-dir)       need_arg "$@"; BACKUP_DIR="${2%/}"; shift 2 ;;
        --backup-keep)      need_arg "$@"; BACKUP_KEEP="$2"; shift 2 ;;
        --skip-doctor)      SKIP_DOCTOR=true; shift ;;
        --forget-options)   shift ;;
        -y|--yes)           ASSUME_YES=true; shift ;;
        -h|--help)          usage; exit 0 ;;
        *)                  fail "unknown option: $1 (see --help)" ;;
    esac
done

# ─────────────────────────────── validation ───────────────────────────────

[[ "$PREFIX" == /* && "$PREFIX" != "/" ]]     || fail "--prefix must be an absolute path other than /"
[[ "$DB_PORT" =~ ^[0-9]{1,5}$ ]]              || fail "--db-port must be a number"
[[ "$DB_HOST" =~ ^[A-Za-z0-9._:-]+$ ]]        || fail "--db-host has unexpected characters"
[[ "$DB_NAME" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]  || fail "--db-name must be a plain identifier"
[[ "$DB_USER" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]  || fail "--db-user must be a plain identifier"
[[ "$KEEP_RELEASES" =~ ^[0-9]+$ && "$KEEP_RELEASES" -ge 2 ]] || fail "--keep-releases must be ≥ 2 (rollback needs one)"
[[ "$BACKUP_KEEP" =~ ^[0-9]+$ && "$BACKUP_KEEP" -ge 1 ]]     || fail "--backup-keep must be ≥ 1"
# The password ends up inside a Npgsql connection string and an env file.
[[ "$DB_PASSWORD" != *[\;\"\'\\[:space:]]* ]] || fail "--db-password can't contain ; quotes, backslashes or spaces"
[[ -z "$DHCP_IFACE" || "$DHCP_IFACE" =~ ^[A-Za-z0-9._@-]{1,15}$ ]] || fail "--dhcp-iface is not an interface name"
if [[ -n "$TLS_CERT$TLS_KEY" ]]; then
    [[ -f "$TLS_CERT" && -f "$TLS_KEY" ]] || fail "--tls-cert and --tls-key must both point to existing files"
    if [[ "$CONFIGURE_NGINX" == no ]]; then fail "--tls-cert contradicts --skip-nginx"; fi
    CONFIGURE_NGINX=yes
fi

readonly RELEASES_DIR="$PREFIX/releases"
readonly CURRENT_LINK="$PREFIX/current"
readonly PREVIOUS_FILE="$PREFIX/.previous"

is_local_db() { [[ "$DB_HOST" =~ ^(127\.0\.0\.1|localhost|::1)$ ]]; }

# ─────────────────────────────── helpers ───────────────────────────────

current_version() {
    [[ -L "$CURRENT_LINK" ]] || return 1
    basename "$(readlink "$CURRENT_LINK")"
}

has_apt() { command -v apt-get >/dev/null 2>&1 && command -v dpkg-query >/dev/null 2>&1; }
pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'; }

# Value of KEY in an env file (first match), empty if absent.
env_get() { [[ -f "$2" ]] && grep -m1 "^$1=" "$2" | cut -d= -f2- || true; }

# One part (Host, Port, Username, Password, Database) of a Npgsql connection string.
conn_part() {
    local conn="$1" key="$2" kv
    IFS=';' read -ra kvs <<< "$conn"
    for kv in "${kvs[@]}"; do
        if [[ "${kv%%=*}" == "$key" ]]; then printf '%s' "${kv#*=}"; return 0; fi
    done
    return 0
}

# The connection string with the five parts this script owns replaced; pool
# settings and anything else the operator added are kept.
conn_with_ours() {
    local conn="$1" kv out="" seen=""
    IFS=';' read -ra kvs <<< "$conn"
    for kv in "${kvs[@]}"; do
        [[ -z "$kv" ]] && continue
        case "${kv%%=*}" in
            Host)     out+="Host=$DB_HOST;";         seen+=H ;;
            Port)     out+="Port=$DB_PORT;";         seen+=P ;;
            Username) out+="Username=$DB_USER;";     seen+=U ;;
            Password) out+="Password=$DB_PASSWORD;"; seen+=W ;;
            Database) out+="Database=$DB_NAME;";     seen+=D ;;
            *)        out+="$kv;" ;;
        esac
    done
    [[ "$seen" == *H* ]] || out="Host=$DB_HOST;$out"
    [[ "$seen" == *P* ]] || out+="Port=$DB_PORT;"
    [[ "$seen" == *U* ]] || out+="Username=$DB_USER;"
    [[ "$seen" == *W* ]] || out+="Password=$DB_PASSWORD;"
    [[ "$seen" == *D* ]] || out+="Database=$DB_NAME;"
    printf '%s' "${out%;}"
}

conn_string() { printf 'Host=%s;Port=%s;Username=%s;Password=%s;Database=%s' \
    "$DB_HOST" "$DB_PORT" "$DB_USER" "$DB_PASSWORD" "$DB_NAME"; }

confirm() {
    [[ "$ASSUME_YES" == true || ! -t 0 ]] && return 0
    local answer
    printf '\n  %s?%s %s %s[y/N]%s ' "$C_ACCENT" "$C_OFF" "$1" "$C_DIM" "$C_OFF"
    read -r answer
    is_true "${answer:-n}"
}

wait_active() {   # unit seconds
    local i
    for ((i = 0; i < $2; i++)); do
        systemctl is-active --quiet "$1" && return 0
        systemctl is-failed --quiet "$1" && return 1
        sleep 1
    done
    return 1
}

wait_web() {      # seconds — any HTTP answer means Kestrel is serving
    local i code
    for ((i = 0; i < $1; i++)); do
        code=$(curl -s -o /dev/null -m 2 -w '%{http_code}' "$WEB_URL/" 2>/dev/null || true)
        [[ -n "$code" && "$code" != "000" ]] && return 0
        systemctl is-failed --quiet netfirewall-web.service && return 1
        sleep 1
    done
    return 1
}

daemon_health_version() {
    curl -s -m 3 --unix-socket "$SOCKET" http://daemon/health 2>/dev/null \
        | sed -n 's/.*"version":"\([^"]*\)".*/\1/p' || true
}

switch_current() {  # version
    ln -sfn "releases/$1" "$PREFIX/.current.tmp"
    mv -Tf "$PREFIX/.current.tmp" "$CURRENT_LINK"
}

unit_installed() { [[ -f "$UNIT_DIR/$1" ]]; }

# ─────────────────────────────── host checks ───────────────────────────────

require_root() { [[ $EUID -eq 0 ]] || fail "run as root"; }

check_host() {   # → number of blocking problems
    local errors=0
    if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
        ok "systemd $(systemctl --version | awk 'NR==1 {print $2}')"
    else
        warn "systemd is not running — this installer targets systemd hosts"; errors=$((errors + 1))
    fi
    if [[ "$(uname -m)" == "x86_64" ]]; then
        ok "architecture x86_64, kernel $(uname -r)"
    else
        warn "architecture $(uname -m): the bundle is linux-x64"; errors=$((errors + 1))
    fi
    if [[ -r /etc/os-release ]]; then
        local os_id os_like os_name
        os_id=$(. /etc/os-release; echo "${ID:-}")
        os_like=$(. /etc/os-release; echo "${ID_LIKE:-}")
        os_name=$(. /etc/os-release; echo "${PRETTY_NAME:-$os_id}")
        if [[ "$os_id" == debian || "$os_id" == ubuntu || "$os_like" == *debian* ]]; then
            ok "$os_name"
        else
            warn "$os_name — only Debian/Ubuntu are tested; packages can't be installed (use --skip-packages)"
            [[ "$SKIP_PACKAGES" == true ]] || errors=$((errors + 1))
        fi
    fi
    return "$errors"
}

check_bundle() {
    [[ -n "$BUNDLE_VERSION" ]] || fail "no VERSION file next to setup.sh — run it from an extracted release bundle"
    [[ "$BUNDLE_VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]] || fail "VERSION '$BUNDLE_VERSION' is not a safe directory name"
    local bin
    for bin in daemon/netfirewall-daemon web/NetFirewall.Web dhcp-server/NetFirewall.DhcpServer \
               migrations/netfirewall-migrate tui/netfirewall-tui doctor/netfirewall-doctor bin/netfirewall-bootstrap; do
        [[ -x "$BUNDLE_APP/$bin" ]] || fail "bundle incomplete: app/$bin missing or not executable"
    done
    compgen -G "$BUNDLE_APP/migrations/sql/migrations/*.sql" >/dev/null || fail "bundle has no SQL migrations"
    local f
    for f in systemd/netfirewall-daemon.service systemd/netfirewall-web.service env/daemon.env.template \
             env/web.env.template config/daemon.json.template config/web.json.template; do
        [[ -f "$BUNDLE_DEPLOY/$f" ]] || fail "bundle incomplete: deploy/$f missing"
    done
    ok "bundle $BUNDLE_VERSION complete ($(ls "$BUNDLE_APP/migrations/sql/migrations/"*.sql | wc -l) migrations)"
}

check_disk() {
    local need_kb=$(( $(du -sk "$BUNDLE_APP" | cut -f1) + 102400 )) avail_kb probe="$PREFIX"
    while [[ ! -d "$probe" ]]; do probe=$(dirname "$probe"); done
    avail_kb=$(df -Pk "$probe" | awk 'NR==2 {print $4}')
    if (( avail_kb < need_kb )); then
        warn "only $((avail_kb / 1024)) MB free under $probe, need ~$((need_kb / 1024)) MB"
        return 1
    fi
    ok "disk: $((avail_kb / 1024)) MB free under $probe (needs ~$((need_kb / 1024)) MB)"
}

# ─────────────────────────────── state resolution ───────────────────────────────

FRESH=false
DB_PASSWORD_GENERATED=false
PREV_VERSION=""
resolve_state() {
    [[ -f "$DAEMON_ENV" || -f "$WEB_ENV" ]] || FRESH=true

    # DB password: CLI > existing env files > generated (local DB only).
    if [[ -z "$DB_PASSWORD" ]]; then
        local f conn
        for f in "$WEB_ENV" "$DAEMON_ENV"; do
            conn=$(env_get ConnectionStrings__DefaultConnection "$f")
            DB_PASSWORD=$(conn_part "$conn" Password)
            if [[ -n "$DB_PASSWORD" && "$DB_PASSWORD" != __REPLACE__ ]]; then break; fi
            DB_PASSWORD=""
        done
        # On an upgrade without --db-*, the env files are the truth for where the DB is.
        if [[ -n "$DB_PASSWORD" && "$DB_EXPLICIT" == false ]]; then
            conn=$(env_get ConnectionStrings__DefaultConnection "$WEB_ENV")
            [[ -n "$conn" ]] || conn=$(env_get ConnectionStrings__DefaultConnection "$DAEMON_ENV")
            DB_HOST=$(conn_part "$conn" Host);     DB_HOST=${DB_HOST:-127.0.0.1}
            DB_PORT=$(conn_part "$conn" Port);     DB_PORT=${DB_PORT:-5432}
            DB_USER=$(conn_part "$conn" Username); DB_USER=${DB_USER:-netfirewall}
            DB_NAME=$(conn_part "$conn" Database); DB_NAME=${DB_NAME:-net_firewall}
        fi
    fi
    if [[ -z "$DB_PASSWORD" ]]; then
        is_local_db || fail "no DB password known for remote host $DB_HOST — pass --db-password"
        DB_PASSWORD_GENERATED=true   # minted later, once the operator said go
    fi

    # auto → keep what's installed (never silently remove a running DHCP server).
    if [[ "$INSTALL_DHCP" == auto ]]; then
        if unit_installed netfirewall-dhcp.service; then INSTALL_DHCP=yes; else INSTALL_DHCP=no; fi
    fi
    if [[ "$INSTALL_DHCP" == yes && -z "$DHCP_IFACE" ]]; then
        DHCP_IFACE=$(env_get DHCP__Interface "$DHCP_ENV")
    fi
    if [[ "$BOOT_APPLY" == auto ]]; then
        if [[ "$FRESH" == true ]] || unit_installed netfirewall-bootstrap.service; then BOOT_APPLY=yes; else BOOT_APPLY=no; fi
    fi
    if [[ "$CONFIGURE_NGINX" == auto ]]; then
        if [[ "$FRESH" == true && ! -e "$NGINX_SITE" ]]; then CONFIGURE_NGINX=yes; else CONFIGURE_NGINX=no; fi
    fi

    PREV_VERSION=$(current_version || true)
    return 0
}

legacy_layout_dirs() {
    local d
    for d in "$PREFIX/daemon" "$PREFIX/web" "$PREFIX/dhcp-server" "$PREFIX/Migrations" "$PREFIX/migrations" \
             "$PREFIX/tui" "$PREFIX/doctor" /opt/netfirewall; do
        if [[ -d "$d" && ! -L "$d" ]]; then printf '%s\n' "$d"; fi
    done
    return 0
}

print_plan() {
    local action db_note="existing" legacy
    if [[ -n "$PREV_VERSION" && "$PREV_VERSION" == "$BUNDLE_VERSION" ]]; then
        action="Reinstall $BUNDLE_VERSION (same version)"
    elif [[ -n "$PREV_VERSION" ]]; then
        action="Upgrade $PREV_VERSION → $BUNDLE_VERSION"
    elif [[ "$FRESH" == true ]]; then
        action="Fresh install of $BUNDLE_VERSION"
    elif [[ -n "$(legacy_layout_dirs)" ]]; then
        action="Install $BUNDLE_VERSION over an existing config (legacy layout)"
    else
        action="Install $BUNDLE_VERSION over an existing config"
    fi
    is_local_db && db_note="local"
    [[ "$DB_PASSWORD_GENERATED" == true ]] && db_note="local, new role password"

    boxed "$C_ACCENT" \
        "$action" \
        "" \
        "Prefix       $PREFIX/releases/$BUNDLE_VERSION" \
        "Database     $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME ($db_note)" \
        "DHCP server  $INSTALL_DHCP${DHCP_IFACE:+ (fallback iface $DHCP_IFACE)}" \
        "Boot apply   $BOOT_APPLY" \
        "nginx        $([[ "$CONFIGURE_NGINX" == yes ]] && echo "configure TLS site" || echo "leave untouched")" \
        "DB backup    $([[ "$SKIP_BACKUP" == true || "$FRESH" == true ]] && echo "no" || echo "yes → $BACKUP_DIR")" \
        "Packages     $([[ "$SKIP_PACKAGES" == true ]] && echo "check only" || echo "apt-get what's missing")"
    legacy=$(legacy_layout_dirs)
    if [[ -n "$legacy" ]]; then
        warn "legacy dirs stay in place but the units stop using them:"
        sed "s/^/       ${C_DIM}/;s/\$/${C_OFF}/" <<< "$legacy"
    fi
    return 0
}

# ─────────────────────────────── steps ───────────────────────────────

install_packages() {
    step "Packages"
    local wanted=(ca-certificates curl openssl nftables iproute2 conntrack iputils-ping
                  postgresql-client tcpdump traceroute wireguard-tools)
    is_local_db && wanted+=(postgresql)
    [[ "$CONFIGURE_NGINX" == yes ]] && wanted+=(nginx)

    if ! has_apt; then
        local c
        for c in curl openssl nft ip psql pg_dump; do
            command -v "$c" >/dev/null 2>&1 && ok "$c" || warn "$c not found — install it with your package manager"
        done
        return 0
    fi

    # The self-contained runtime still needs the system ICU (globalization).
    if ! ldconfig -p 2>/dev/null | grep -q 'libicuuc\.so'; then
        local icu
        icu=$(apt-cache search --names-only '^libicu[0-9]+$' 2>/dev/null | awk '{print $1}' | sort -V | tail -1)
        [[ -n "$icu" ]] && wanted+=("$icu")
    fi

    local missing=() p
    for p in "${wanted[@]}"; do pkg_installed "$p" || missing+=("$p"); done
    if [[ ${#missing[@]} -eq 0 ]]; then
        ok "all ${#wanted[@]} required packages present"
        return 0
    fi
    if [[ "$SKIP_PACKAGES" == true ]]; then
        warn "missing (not installed, --skip-packages): ${missing[*]}"
        return 0
    fi
    ok "$(( ${#wanted[@]} - ${#missing[@]} )) of ${#wanted[@]} already present"
    export DEBIAN_FRONTEND=noninteractive
    MUST_HINT="apt-get update failed — check the network / sources.list" \
        must "Refreshing the package index…" "package index refreshed" apt-get update -q
    MUST_HINT="apt-get install failed — see the log lines above" \
        must "Installing ${missing[*]}…" "installed ${missing[*]}" \
        apt-get install -y -q --no-install-recommends "${missing[@]}"
}

ensure_accounts_and_dirs() {
    step "Accounts and directories"
    getent group "$GROUP_NAME" >/dev/null || groupadd --system "$GROUP_NAME"
    if ! getent passwd "$WEB_USER" >/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin \
                --gid "$GROUP_NAME" --home "$STATE_DIR/web" "$WEB_USER"
        ok "created system user $WEB_USER"
    else
        usermod -aG "$GROUP_NAME" "$WEB_USER" 2>/dev/null || true
    fi
    WEB_UID=$(id -u "$WEB_USER")
    ok "user $WEB_USER (uid $WEB_UID) in group $GROUP_NAME"

    install -d -m 0755 -o root -g root                 "$PREFIX" "$RELEASES_DIR"
    install -d -m 0750 -o root -g "$GROUP_NAME"        "$ETC_DIR"
    # The parents are group netfirewall so the Web user can traverse to its own
    # web/ subdir; the daemon's and DHCP's stay root-only.
    install -d -m 0750 -o root -g "$GROUP_NAME"        "$STATE_DIR" "$LOG_DIR"
    install -d -m 0750 -o root -g root                 "$STATE_DIR/daemon" "$STATE_DIR/daemon/captures"
    install -d -m 0750 -o "$WEB_USER" -g "$GROUP_NAME" "$STATE_DIR/web"
    install -d -m 0750 -o root -g root                 "$LOG_DIR/daemon" "$LOG_DIR/dhcp"
    install -d -m 0750 -o "$WEB_USER" -g "$GROUP_NAME" "$LOG_DIR/web"
    ok "$PREFIX · $ETC_DIR · $STATE_DIR · $LOG_DIR"

    # /run/netfirewall must be root:netfirewall so the Web can reach the socket;
    # RuntimeDirectory= can't set the group, tmpfiles.d can.
    install -Dm 0644 "$BUNDLE_DEPLOY/tmpfiles/netfirewall.conf" /etc/tmpfiles.d/netfirewall.conf
    systemd-tmpfiles --create /etc/tmpfiles.d/netfirewall.conf 2>/dev/null \
        || install -d -m 0750 -o root -g "$GROUP_NAME" "$RUN_DIR"
    ok "$RUN_DIR (tmpfiles.d, root:$GROUP_NAME 0750)"
}

# As postgres, from / — the bundle usually sits under /root, which postgres can't enter.
as_postgres() { (cd / && runuser -u postgres -- "$@"); }
pg_ready() { as_postgres psql -tAc 'SELECT 1' >/dev/null 2>&1; }
wait_pg()  { local i; for ((i = 0; i < 30; i++)); do pg_ready && return 0; sleep 1; done; return 1; }

provision_local_db() {
    step "PostgreSQL"
    if ! is_local_db; then
        skip "remote database $DB_HOST:$DB_PORT — nothing to provision here"
        return 0
    fi
    if ! command -v pg_lsclusters >/dev/null 2>&1 && ! systemctl cat postgresql.service >/dev/null 2>&1; then
        fail "PostgreSQL is not installed locally (run without --skip-packages, or install it)"
    fi
    systemctl enable --now postgresql.service >/dev/null 2>&1 || true
    MUST_HINT="local PostgreSQL is not accepting connections as the postgres superuser" \
        must "Waiting for PostgreSQL…" "PostgreSQL accepting connections" wait_pg
    ok "server $(as_postgres psql -tAc 'SHOW server_version' 2>/dev/null | cut -d' ' -f1)"

    local psql=(as_postgres psql -v ON_ERROR_STOP=1 -qtA)
    local role_exists db_exists
    role_exists=$("${psql[@]}" -v r="$DB_USER" <<< "SELECT 1 FROM pg_roles WHERE rolname = :'r';")
    if [[ -z "$role_exists" ]]; then
        "${psql[@]}" -v r="$DB_USER" -v pw="$DB_PASSWORD" <<< 'CREATE ROLE :"r" LOGIN PASSWORD :'"'pw'"';'
        ok "role $DB_USER created"
    elif [[ "$DB_PASSWORD_GENERATED" == true || "$DB_EXPLICIT" == true ]]; then
        # A password we just minted (or the operator just passed) must become the role's.
        "${psql[@]}" -v r="$DB_USER" -v pw="$DB_PASSWORD" <<< 'ALTER ROLE :"r" WITH LOGIN PASSWORD :'"'pw'"';'
        ok "role $DB_USER password set"
    else
        ok "role $DB_USER exists"
    fi
    db_exists=$("${psql[@]}" -v d="$DB_NAME" <<< "SELECT 1 FROM pg_database WHERE datname = :'d';")
    if [[ -z "$db_exists" ]]; then
        "${psql[@]}" -v d="$DB_NAME" -v r="$DB_USER" <<< 'CREATE DATABASE :"d" OWNER :"r";'
        ok "database $DB_NAME created"
    else
        ok "database $DB_NAME exists"
    fi
}

dump_db() {   # file — PGPASSWORD comes from the environment
    pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" --no-owner | gzip -c > "$1"
}

backup_db() {
    step "Database backup"
    if [[ "$SKIP_BACKUP" == true ]]; then skip "skipped (--skip-backup)"; return 0; fi
    if [[ "$FRESH" == true ]]; then skip "fresh install — nothing to back up"; return 0; fi
    command -v pg_dump >/dev/null 2>&1 || fail "pg_dump not found (postgresql-client) — install it, or pass --skip-backup"
    install -d -m 0700 -o root -g root "$BACKUP_DIR"
    local file="$BACKUP_DIR/net_firewall-before-$BUNDLE_VERSION-$(date +%Y%m%d-%H%M%S).sql.gz"
    PGPASSWORD="$DB_PASSWORD" MUST_HINT="pg_dump failed — fix the cause, or pass --skip-backup to upgrade without a copy" \
        must "Dumping $DB_NAME…" "dumped $DB_NAME" dump_db "$file"
    chmod 0600 "$file"
    ok "$(du -h "$file" | cut -f1) → $file"
    local pruned
    pruned=$(ls -1t "$BACKUP_DIR"/net_firewall-before-*.sql.gz 2>/dev/null | tail -n +$((BACKUP_KEEP + 1)))
    if [[ -n "$pruned" ]]; then
        xargs -r rm -f <<< "$pruned"
        skip "pruned $(wc -l <<< "$pruned") old dump(s), keeping $BACKUP_KEEP"
    fi
}

copy_release() { cp -a "$BUNDLE_APP" "$1" && chown -R root:root "$1" && chmod 0755 "$1"; }

stage_release() {
    step "Release $BUNDLE_VERSION"
    TARGET="$RELEASES_DIR/$BUNDLE_VERSION"
    local staging="$RELEASES_DIR/.staging-$BUNDLE_VERSION-$$"
    rm -rf "$staging"
    # -a keeps the hard links build-bundle.sh made between the components' runtimes.
    must "Copying binaries…" "binaries copied ($(du -sh "$BUNDLE_APP" | cut -f1))" copy_release "$staging"

    # Per-release config (no secrets). rm first: never write through a hard link.
    rm -f "$staging/daemon/appsettings.Production.json" "$staging/web/appsettings.Production.json" \
          "$staging/tui/appsettings.json"
    install -m 0640 -o root -g "$GROUP_NAME" "$BUNDLE_DEPLOY/config/daemon.json.template" \
        "$staging/daemon/appsettings.Production.json"
    install -m 0640 -o root -g "$GROUP_NAME" "$BUNDLE_DEPLOY/config/web.json.template" \
        "$staging/web/appsettings.Production.json"
    cat > "$staging/tui/appsettings.json" <<EOF
{
  "Daemon": {
    "SocketPath": "$SOCKET",
    "SessionHeader": "X-NetFw-Session",
    "Timeout": "00:00:10"
  },
  "Logging": { "LogLevel": { "Default": "Warning" } }
}
EOF
    chmod 0644 "$staging/tui/appsettings.json"
    chown -R "$WEB_USER:$GROUP_NAME" "$staging/web/wwwroot" 2>/dev/null || true
    ok "appsettings.Production.json for daemon + web, TUI socket config"

    OLD_SAME=""
    if [[ -d "$TARGET" ]]; then
        # Reinstalling the active version: running processes keep their (now
        # unlinked) files; the directory swap itself is two renames.
        OLD_SAME="$RELEASES_DIR/.replaced-$BUNDLE_VERSION-$$"
        mv "$TARGET" "$OLD_SAME"
    fi
    mv "$staging" "$TARGET"
    ok "staged at $TARGET"
}

# A release that never went live: drop it (a reinstall gets its previous copy back).
discard_staged() {
    rm -rf "${TARGET:?}"
    if [[ -n "${OLD_SAME:-}" ]]; then mv "$OLD_SAME" "$TARGET"; fi
    skip "discarded the staged release"
}

apply_seed() { psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 -q -f "$1"; }

run_migrations() {
    step "Database migrations"
    # The NEW release's runner, BEFORE the switch: new binaries never start against
    # an old schema (the 42703/42P01 incidents). Forward-only — a rollback later
    # does not undo these.
    if ! NETFIREWALL_CONN="$(conn_string)" \
        run "Applying migrations…" "schema up to date ($(ls "$TARGET/migrations/sql/migrations/"*.sql | wc -l | tr -d ' ') migrations)" \
        "$TARGET/migrations/netfirewall-migrate" up --dir "$TARGET/migrations/sql/migrations"; then
        log_tail
        discard_staged
        fail "migrations failed — nothing was switched; ${PREV_VERSION:-the previous installation} is still active"
    fi

    if [[ "$APPLY_SEEDS" != true ]]; then
        skip "seeds not applied (--apply-seeds to apply deploy/seeds/)"
        return 0
    fi
    local f
    for f in "$BUNDLE_DEPLOY/seeds/"*.sql; do
        [[ -f "$f" ]] || continue
        PGPASSWORD="$DB_PASSWORD" run "Seed $(basename "$f")…" "seed $(basename "$f")" apply_seed "$f" \
            || warn "seed $(basename "$f") failed — continuing"
    done
}

# ── env files ──
# New file → rendered from the template. Existing file → kept as is; only keys
# the template has and the file lacks are appended, and the connection string is
# rewritten when --db-* was passed. Operator edits survive upgrades.

render_template() {   # template → stdout
    local line
    while IFS= read -r line || [[ -n "$line" ]]; do
        line=${line//"Password=__REPLACE__"/"Password=$DB_PASSWORD"}
        line=${line//"Daemon__AcceptedPeerUids__0=__REPLACE__"/"Daemon__AcceptedPeerUids__0=$WEB_UID"}
        line=${line//"NETFIREWALL_MASTER_KEY=__REPLACE_MASTER_KEY__"/"NETFIREWALL_MASTER_KEY=$MASTER_KEY"}
        line=${line//"__REPLACE_DHCP_IFACE__"/"${DHCP_IFACE:-eth0}"}
        line=${line//"Host=127.0.0.1;Port=5432"/"Host=$DB_HOST;Port=$DB_PORT"}
        line=${line//"Username=netfirewall;"/"Username=$DB_USER;"}
        line=${line//"Database=net_firewall;"/"Database=$DB_NAME;"}
        printf '%s\n' "$line"
    done < "$1"
}

write_env() {   # template target mode group
    local tpl="$1" target="$2" mode="$3" group="$4" tmp="$2.tmp.$$"
    if [[ ! -f "$target" ]]; then
        render_template "$tpl" > "$tmp"
        ok "created $target"
    else
        cp -p "$target" "$tmp"
        local key line added=()
        while IFS= read -r line; do
            [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)= ]] || continue
            key="${BASH_REMATCH[1]}"
            if ! grep -q "^$key=" "$tmp"; then printf '%s\n' "$line" >> "$tmp"; added+=("$key"); fi
        done < <(render_template "$tpl")
        if [[ "$DB_EXPLICIT" == true || "$DB_PASSWORD_GENERATED" == true ]]; then
            local conn new
            conn=$(env_get ConnectionStrings__DefaultConnection "$tmp")
            new=$(conn_with_ours "$conn")
            if [[ "$conn" != "$new" ]]; then
                grep -v '^ConnectionStrings__DefaultConnection=' "$tmp" > "$tmp.2"
                printf 'ConnectionStrings__DefaultConnection=%s\n' "$new" >> "$tmp.2"
                mv "$tmp.2" "$tmp"
                added+=("ConnectionStrings(updated)")
            fi
        fi
        if [[ ${#added[@]} -gt 0 ]]; then info "updated $target: ${added[*]}"; else ok "kept $target"; fi
    fi
    if grep -qE '__REPLACE(_MASTER_KEY|_DHCP_IFACE)?__' "$tmp"; then
        rm -f "$tmp"
        fail "a placeholder survived in $target — fix the file by hand, then re-run"
    fi
    chown "root:$group" "$tmp"
    chmod "$mode" "$tmp"
    mv -f "$tmp" "$target"
}

resolve_master_key() {
    # The daemon and the Web MUST hold the byte-identical key (docs/master-key.md).
    # Never rotate on upgrade: that invalidates every TOTP enrollment.
    local d w
    d=$(env_get NETFIREWALL_MASTER_KEY "$DAEMON_ENV")
    w=$(env_get NETFIREWALL_MASTER_KEY "$WEB_ENV")
    [[ "$d" =~ ^(__REPLACE__|__REPLACE_MASTER_KEY__|placeholder)?$ ]] && d=""
    [[ "$w" =~ ^(__REPLACE__|__REPLACE_MASTER_KEY__|placeholder)?$ ]] && w=""
    if [[ -n "$d" && -n "$w" && "$d" != "$w" ]]; then
        fail "NETFIREWALL_MASTER_KEY differs between $DAEMON_ENV and $WEB_ENV — decide which one the TOTP
     enrollments were made with, put it in both files, and re-run (see docs/master-key.md)"
    fi
    MASTER_KEY="${w:-$d}"
    MASTER_KEY_NEW=false
    if [[ -z "$MASTER_KEY" ]]; then
        MASTER_KEY=$(openssl rand -base64 32)
        MASTER_KEY_NEW=true
    fi
}

set_env_key() {   # file key value — replace or append one key, keeping owner/mode
    local f="$1" k="$2" v="$3"
    if grep -q "^$k=" "$f"; then
        grep -v "^$k=" "$f" > "$f.tmp.$$"
        printf '%s=%s\n' "$k" "$v" >> "$f.tmp.$$"
        cat "$f.tmp.$$" > "$f"
        rm -f "$f.tmp.$$"
    else
        printf '%s=%s\n' "$k" "$v" >> "$f"
    fi
}

write_env_files() {
    step "Configuration and secrets"
    resolve_master_key
    write_env "$BUNDLE_DEPLOY/env/daemon.env.template" "$DAEMON_ENV" 0600 root
    write_env "$BUNDLE_DEPLOY/env/web.env.template"    "$WEB_ENV"    0640 "$GROUP_NAME"

    # A file that existed without a key got the template's line appended; make
    # sure that line carries the shared key, not a fresh one per file.
    set_env_key "$DAEMON_ENV" NETFIREWALL_MASTER_KEY "$MASTER_KEY"
    set_env_key "$WEB_ENV"    NETFIREWALL_MASTER_KEY "$MASTER_KEY"
    [[ "$(env_get NETFIREWALL_MASTER_KEY "$DAEMON_ENV")" == "$(env_get NETFIREWALL_MASTER_KEY "$WEB_ENV")" ]] \
        || fail "master key differs between $DAEMON_ENV and $WEB_ENV after writing — daemon TOTP would fail"
    if [[ "$MASTER_KEY_NEW" == true ]]; then
        ok "new AES-256 master key, identical in daemon.env and web.env"
    else
        ok "master key preserved, identical in daemon.env and web.env"
    fi

    if [[ "$INSTALL_DHCP" == yes ]]; then
        [[ -n "$DHCP_IFACE" ]] || DHCP_IFACE=$(ls /sys/class/net 2>/dev/null \
            | grep -vE '^(lo|wg|tun|tap|docker|veth|br-)' | head -1 || true)
        write_env "$BUNDLE_DEPLOY/env/dhcp.env.template" "$DHCP_ENV" 0640 root
        if [[ "$DHCP_IFACE_EXPLICIT" == true ]]; then
            set_env_key "$DHCP_ENV" DHCP__Interface "$DHCP_IFACE"
            ok "DHCP fallback interface: $DHCP_IFACE"
        fi
    fi
}

render_unit() {   # name
    sed "s|@PREFIX@|$PREFIX|g" "$BUNDLE_DEPLOY/systemd/$1" > "$UNIT_DIR/$1.tmp"
    chmod 0644 "$UNIT_DIR/$1.tmp"
    mv -f "$UNIT_DIR/$1.tmp" "$UNIT_DIR/$1"
}

install_system_files() {
    step "systemd and system files"
    render_unit netfirewall-daemon.service
    render_unit netfirewall-web.service
    local units="daemon, web"
    if [[ "$INSTALL_DHCP" == yes ]]; then
        render_unit netfirewall-dhcp.service; units+=", dhcp"
    elif unit_installed netfirewall-dhcp.service; then
        systemctl disable --now netfirewall-dhcp.service >/dev/null 2>&1 || true
        rm -f "$UNIT_DIR/netfirewall-dhcp.service"
        info "DHCP unit stopped and removed (--without-dhcp)"
    fi
    if [[ "$BOOT_APPLY" == yes ]]; then
        render_unit netfirewall-bootstrap.service; units+=", bootstrap"
    elif unit_installed netfirewall-bootstrap.service; then
        systemctl disable netfirewall-bootstrap.service >/dev/null 2>&1 || true
        rm -f "$UNIT_DIR/netfirewall-bootstrap.service"
        info "boot-apply unit removed (--without-boot-apply)"
    fi
    systemctl daemon-reload
    ok "units ($units) → $CURRENT_LINK"

    # Kernel tunables. The sysctl drop-in alone doesn't survive a reboot for
    # nf_conntrack_acct (systemd-sysctl runs before the module loads), hence the
    # modprobe.d default and the modules-load.d entry. Applying them is additive;
    # nothing here touches nftables or routes.
    # -D: a minimal host without kmod has no /etc/modprobe.d yet.
    install -Dm 0644 "$BUNDLE_DEPLOY/sysctl/netfirewall.conf"         /etc/sysctl.d/netfirewall.conf
    install -Dm 0644 "$BUNDLE_DEPLOY/modprobe.d/netfirewall.conf"     /etc/modprobe.d/netfirewall.conf
    install -Dm 0644 "$BUNDLE_DEPLOY/modules-load.d/netfirewall.conf" /etc/modules-load.d/netfirewall.conf
    modprobe nf_conntrack 2>/dev/null || true
    if sysctl --quiet --load=/etc/sysctl.d/netfirewall.conf >/dev/null 2>&1; then
        ok "sysctl, modprobe.d and modules-load.d drop-ins applied"
    else
        warn "sysctl --load failed; run 'sysctl --system' or reboot"
    fi

    # Console tools on PATH, through `current` so they follow upgrades.
    ln -sfn "$CURRENT_LINK/tui/netfirewall-tui"            /usr/local/bin/netfirewall-tui
    ln -sfn "$CURRENT_LINK/doctor/netfirewall-doctor"      /usr/local/bin/netfirewall-doctor
    # The runner needs a connection string: the wrapper reads the daemon's, so
    # `netfirewall-migrate status` just works for root on the console.
    rm -f /usr/local/bin/netfirewall-migrate
    cat > /usr/local/bin/netfirewall-migrate <<EOF
#!/bin/sh
# Installed by NetFirewall setup.sh — the active release's migration runner,
# using the daemon's connection string unless NETFIREWALL_CONN is already set.
if [ -z "\$NETFIREWALL_CONN" ] && [ -r $DAEMON_ENV ]; then
    NETFIREWALL_CONN=\$(sed -n 's/^ConnectionStrings__DefaultConnection=//p' $DAEMON_ENV | head -n 1)
    export NETFIREWALL_CONN
fi
exec $CURRENT_LINK/migrations/netfirewall-migrate "\$@"
EOF
    chmod 0755 /usr/local/bin/netfirewall-migrate
    install -d /usr/local/share/man/man1
    install -m 0644 "$BUNDLE_DEPLOY/man/netfirewall-tui.1" /usr/local/share/man/man1/netfirewall-tui.1
    if [[ -d /etc/bash_completion.d ]]; then
        install -m 0644 "$BUNDLE_DEPLOY/completion/netfirewall-tui" /etc/bash_completion.d/netfirewall-tui
    fi
    ok "netfirewall-tui · netfirewall-doctor · netfirewall-migrate in /usr/local/bin"
}

make_cert() {   # cert key
    local sans="DNS:$(hostname -f 2>/dev/null || hostname),DNS:localhost,IP:127.0.0.1" ip
    for ip in $(ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1); do
        sans+=",IP:$ip"
    done
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$2" -out "$1" -days 3650 \
        -subj "/CN=$(hostname)" -addext "subjectAltName=$sans"
}

configure_nginx() {
    step "Reverse proxy (nginx)"
    if [[ "$CONFIGURE_NGINX" != yes ]]; then
        skip "left untouched (automatic only on a fresh install; --configure-nginx to force)"
        return 0
    fi
    command -v nginx >/dev/null 2>&1 || { warn "nginx not installed — skipped"; return 0; }
    local cert="$TLS_CERT" key="$TLS_KEY"
    install -d -m 0750 -o root -g "$GROUP_NAME" "$TLS_DIR"
    if [[ -z "$cert" ]]; then
        cert="$TLS_DIR/netfirewall.crt"; key="$TLS_DIR/netfirewall.key"
        if [[ ! -s "$cert" || ! -s "$key" ]]; then
            run "Generating a self-signed certificate…" "self-signed certificate $cert" make_cert "$cert" "$key" \
                || { warn "openssl could not create a certificate — nginx skipped"; return 0; }
            chmod 0640 "$key"; chgrp "$GROUP_NAME" "$key"; chmod 0644 "$cert"
        else
            ok "keeping certificate $cert"
        fi
    else
        ok "certificate $cert"
    fi
    local had_default=false backup=""
    [[ -L /etc/nginx/sites-enabled/default ]] && had_default=true
    if [[ -f "$NGINX_SITE" ]]; then backup="$NGINX_SITE.bak.$(date +%s)"; cp -p "$NGINX_SITE" "$backup"; fi
    sed -e "s|__TLS_CERT__|$cert|g" -e "s|__TLS_KEY__|$key|g" \
        "$BUNDLE_DEPLOY/nginx/netfirewall-appliance.conf.template" > "$NGINX_SITE"
    # `http2 on;` exists from nginx 1.25.1 (Debian 13); older ones (Debian 12 has
    # 1.22) take the flag on the listen line instead.
    local nginx_ver
    nginx_ver=$(nginx -v 2>&1 | sed -n 's|.*nginx/\([0-9.]*\).*|\1|p')
    if [[ -n "$nginx_ver" ]] && [[ "$(printf '%s\n1.25.1\n' "$nginx_ver" | sort -V | head -1)" != "1.25.1" ]]; then
        sed -i -e '/^[[:space:]]*http2 on;/d' -e 's/\(listen .*443 ssl\)/\1 http2/' "$NGINX_SITE"
    fi
    chmod 0644 "$NGINX_SITE"
    rm -f /etc/nginx/sites-enabled/default
    ln -sfn "$NGINX_SITE" "$NGINX_ENABLED"
    if nginx -t >> "$SETUP_LOG" 2>&1; then
        systemctl enable nginx.service >/dev/null 2>&1 || true
        systemctl reload nginx.service 2>/dev/null || systemctl restart nginx.service
        ok "nginx serving https on :443 → $WEB_URL"
    else
        # Put things back exactly as they were: a broken nginx is worse than none.
        if [[ -n "$backup" ]]; then mv -f "$backup" "$NGINX_SITE"; else rm -f "$NGINX_SITE" "$NGINX_ENABLED"; fi
        if [[ "$had_default" == true ]]; then ln -sfn /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default; fi
        warn "nginx -t rejected the site (another default_server on :80/:443?) — reverted; see deploy/nginx/"
    fi
}

restart_unit() {   # unit seconds
    systemctl restart "$1" || return 1
    wait_active "$1" "$2"
}

restart_services() {   # → 0 healthy, 1 not
    systemctl enable netfirewall-daemon.service netfirewall-web.service >/dev/null 2>&1
    run "Restarting netfirewall-daemon…" "netfirewall-daemon active" restart_unit netfirewall-daemon.service 45 \
        || return 1
    run "Restarting netfirewall-web…" "netfirewall-web active" restart_unit netfirewall-web.service 30 \
        || return 1
    run "Waiting for the Web on $WEB_URL…" "Web answering on $WEB_URL" wait_web 60 || return 1
    if [[ "$BOOT_APPLY" == yes ]]; then
        systemctl enable netfirewall-bootstrap.service >/dev/null 2>&1 || true
    fi
    if [[ "$INSTALL_DHCP" == yes ]]; then
        systemctl enable netfirewall-dhcp.service >/dev/null 2>&1
        # DHCP failing is reported, not rolled back: the firewall itself is up.
        run "Restarting netfirewall-dhcp…" "netfirewall-dhcp active" restart_unit netfirewall-dhcp.service 20 \
            || warn "netfirewall-dhcp did not become active — journalctl -u netfirewall-dhcp"
    fi
    return 0
}

switch_and_restart() {
    step "Switch and restart"
    local old_previous
    old_previous=$(cat "$PREVIOUS_FILE" 2>/dev/null || true)
    switch_current "$BUNDLE_VERSION"
    if [[ -n "$PREV_VERSION" && "$PREV_VERSION" != "$BUNDLE_VERSION" ]]; then echo "$PREV_VERSION" > "$PREVIOUS_FILE"; fi
    ok "$CURRENT_LINK → releases/$BUNDLE_VERSION"

    if restart_services; then
        local v
        v=$(daemon_health_version)
        if [[ -n "$v" && "$v" != "${BUNDLE_VERSION#v}" ]]; then
            warn "daemon reports version $v, expected $BUNDLE_VERSION"
        elif [[ -n "$v" ]]; then
            ok "daemon /health reports $v"
        fi
        if [[ -n "${OLD_SAME:-}" ]]; then rm -rf "$OLD_SAME"; fi
        return 0
    fi

    journalctl -u netfirewall-daemon -u netfirewall-web -n 20 --no-pager 2>/dev/null \
        | sed "s/^/     ${C_DIM}│${C_OFF} /" >&2 || true
    if [[ -n "$PREV_VERSION" && -d "$RELEASES_DIR/$PREV_VERSION" && "$PREV_VERSION" != "$BUNDLE_VERSION" ]]; then
        warn "automatic rollback to $PREV_VERSION"
        switch_current "$PREV_VERSION"
        # Back to where we were: .previous must not point at the release now active.
        if [[ -n "$old_previous" ]]; then echo "$old_previous" > "$PREVIOUS_FILE"; else rm -f "$PREVIOUS_FILE"; fi
        restart_services || true
        fail "$BUNDLE_VERSION did not start; back on $PREV_VERSION. Migrations stay applied (forward-only).
     journalctl -u netfirewall-daemon -u netfirewall-web for the full story."
    elif [[ -n "${OLD_SAME:-}" ]]; then
        warn "restoring the previous copy of $BUNDLE_VERSION"
        rm -rf "$TARGET"; mv "$OLD_SAME" "$TARGET"
        restart_services || true
        fail "reinstall of $BUNDLE_VERSION did not start; previous copy restored"
    fi
    fail "services did not start (no previous release to roll back to) — journalctl -u netfirewall-daemon -u netfirewall-web"
}

prune_releases() {
    local keep_cur keep_prev r n=0
    keep_cur=$(current_version || true)
    keep_prev=$(cat "$PREVIOUS_FILE" 2>/dev/null || true)
    while IFS= read -r r; do
        r=$(basename "$r")
        n=$((n + 1))
        [[ "$r" == "$keep_cur" || "$r" == "$keep_prev" ]] && continue
        if (( n > KEEP_RELEASES )); then
            rm -rf "${RELEASES_DIR:?}/$r"
            skip "pruned release $r"
        fi
    done < <(ls -1dt "$RELEASES_DIR"/*/ 2>/dev/null)
    rm -rf "$RELEASES_DIR"/.staging-* "$RELEASES_DIR"/.replaced-* 2>/dev/null || true
    ok "$(ls -1d "$RELEASES_DIR"/*/ 2>/dev/null | wc -l) release(s) on disk (keeping up to $KEEP_RELEASES)"
}

save_options() {
    local k
    declare -A defaults=([PREFIX]=/opt/tekium [DB_HOST]=127.0.0.1 [DB_PORT]=5432 [DB_NAME]=net_firewall
                         [DB_USER]=netfirewall [INSTALL_DHCP]=no [DHCP_IFACE]="" [BOOT_APPLY]=no
                         [SKIP_PACKAGES]=false [BACKUP_DIR]=/var/backups/netfirewall [BACKUP_KEEP]=10
                         [KEEP_RELEASES]=3)
    {
        echo "# Written by setup.sh $BUNDLE_VERSION on $(date -u '+%Y-%m-%dT%H:%M:%SZ')."
        echo "# Options that differ from the defaults; the next ./setup.sh starts from these."
        echo "# Command-line flags override them; --forget-options ignores this file."
        for k in "${SAVED_KEYS[@]}"; do
            if [[ "${!k}" != "${defaults[$k]}" ]]; then printf '%s="%s"\n' "$k" "${!k}"; fi
        done
    } > "$SETUP_CONF.tmp"
    chmod 0640 "$SETUP_CONF.tmp"
    mv -f "$SETUP_CONF.tmp" "$SETUP_CONF"
    ok "options saved to $SETUP_CONF"
}

finish_up() {
    step "Cleanup"
    save_options
    prune_releases
}

run_doctor() {
    step "Verification"
    if [[ "$SKIP_DOCTOR" == true ]]; then skip "skipped (--skip-doctor)"; return 0; fi
    sleep 2
    echo
    if "$CURRENT_LINK/doctor/netfirewall-doctor" --prefix "$CURRENT_LINK" --etc "$ETC_DIR"; then
        ok "netfirewall-doctor: no failures"
    else
        warn "netfirewall-doctor reported problems above — review them before going live"
    fi
}

print_summary() {
    # Optional fragments computed up front: inside an assignment, a failing $(…)
    # becomes the statement's exit status and set -e would end the run here.
    local dhcp_unit="" https_url=""
    if [[ "$INSTALL_DHCP" == yes ]]; then dhcp_unit=" · netfirewall-dhcp"; fi
    if [[ "$CONFIGURE_NGINX" == yes ]]; then https_url="  ·  https://$(hostname -f 2>/dev/null || hostname)/"; fi
    local lines=(
        "✓ NetFirewall $BUNDLE_VERSION is running   ($(elapsed $((SECONDS - SETUP_START))), $WARNINGS warning(s))"
        ""
        "Release   $CURRENT_LINK → releases/$BUNDLE_VERSION"
    )
    if [[ -n "$PREV_VERSION" && "$PREV_VERSION" != "$BUNDLE_VERSION" ]]; then
        lines+=("Previous  $PREV_VERSION   (./setup.sh --rollback)")
    fi
    lines+=(
        "Services  netfirewall-daemon · netfirewall-web$dhcp_unit"
        "Web       $WEB_URL$https_url"
        "Console   netfirewall-tui · netfirewall-doctor · netfirewall-migrate status"
        "Config    $ETC_DIR/*.env · $SETUP_CONF"
        "Log       $SETUP_LOG"
    )
    boxed "$C_OK" "${lines[@]}"

    if [[ "$MASTER_KEY_NEW" == true ]]; then
        boxed "$C_WARN" \
            "New master key — back it up somewhere safe." \
            "Losing it invalidates every TOTP enrollment." \
            "" \
            "NETFIREWALL_MASTER_KEY=$MASTER_KEY"
    fi
    if [[ "$FRESH" == true ]]; then
        printf '\n  %sNext steps%s\n' "$C_BOLD" "$C_OFF"
        printf '   %s1.%s Open the Web UI. With no users yet it logs a one-time bootstrap link:\n' "$C_ACCENT" "$C_OFF"
        printf '        %sjournalctl -u netfirewall-web | grep -i bootstrap%s\n' "$C_DIM" "$C_OFF"
        printf '   %s2.%s Create the first admin, enroll TOTP, walk through the setup wizard.\n' "$C_ACCENT" "$C_OFF"
        printf '   %s3.%s Replace the self-signed certificate: ./setup.sh --tls-cert … --tls-key …\n' "$C_ACCENT" "$C_OFF"
    fi
    local legacy
    legacy=$(legacy_layout_dirs)
    if [[ -n "$legacy" ]]; then
        printf '\n  %sThe units no longer use these legacy directories; remove them when satisfied:%s\n' "$C_DIM" "$C_OFF"
        sed "s/^/    ${C_DIM}rm -rf /;s/\$/${C_OFF}/" <<< "$legacy"
    fi
    echo
}

# ─────────────────────────────── modes ───────────────────────────────

mode_list() {
    local cur prev r marker color
    cur=$(current_version || true)
    prev=$(cat "$PREVIOUS_FILE" 2>/dev/null || true)
    banner "releases under $RELEASES_DIR"
    echo
    if ! compgen -G "$RELEASES_DIR/*/" >/dev/null; then skip "no releases installed"; return 0; fi
    while IFS= read -r r; do
        r=$(basename "$r"); marker="  "; color="$C_DIM"
        if [[ "$r" == "$cur" ]]; then marker="● "; color="$C_OK"; fi
        if [[ "$r" == "$prev" ]]; then marker="↩ "; color="$C_INFO"; fi
        printf '   %s%s%-40s%s %s%s%s\n' "$color" "$marker" "$r" "$C_OFF" "$C_DIM" \
            "$(stat -c '%y' "$RELEASES_DIR/$r" 2>/dev/null | cut -d. -f1)" "$C_OFF"
    done < <(ls -1dt "$RELEASES_DIR"/*/ 2>/dev/null)
    printf '\n   %s● active   ↩ previous (target of --rollback)%s\n\n' "$C_DIM" "$C_OFF"
}

mode_rollback() {
    require_root
    local cur target
    cur=$(current_version || true)
    target="${ROLLBACK_TO:-$(cat "$PREVIOUS_FILE" 2>/dev/null || true)}"
    banner "rollback"
    [[ -n "$target" ]] || fail "no previous release recorded — pass the version: --rollback <VERSION> (see --list-releases)"
    [[ -d "$RELEASES_DIR/$target" ]] || fail "release $target is not under $RELEASES_DIR"
    [[ "$target" != "$cur" ]] || fail "$target is already active"
    boxed "$C_WARN" \
        "Rollback ${cur:-?} → $target" \
        "" \
        "The database schema is NOT rolled back (migrations are forward-only)." \
        "Additive migrations are fine for older binaries; if ${cur:-the newer release} dropped" \
        "or renamed something, restore its pre-upgrade dump from $BACKUP_DIR first."
    confirm "Switch to $target and restart the services?" || fail "aborted, nothing changed"
    INSTALL_DHCP=no; if unit_installed netfirewall-dhcp.service; then INSTALL_DHCP=yes; fi
    BOOT_APPLY=no
    step "Switch and restart"   # not-install
    switch_current "$target"
    echo "$cur" > "$PREVIOUS_FILE"
    ok "$CURRENT_LINK → releases/$target"
    if restart_services; then
        boxed "$C_OK" "✓ back on $target" "" "previous is now $cur — ./setup.sh --rollback returns to it"
        echo
    else
        fail "$target did not start either — journalctl -u netfirewall-daemon -u netfirewall-web"
    fi
}

mode_preflight() {
    banner "preflight — nothing will be changed"
    local errors=0 rc=0
    step "Bundle"   # not-install
    check_bundle
    step "Host"   # not-install
    check_host || rc=$?; errors=$((errors + rc))
    check_disk || errors=$((errors + 1))
    if [[ $EUID -ne 0 ]]; then
        warn "not root — the real run must be, and the plan below needs root to read $ETC_DIR"
        errors=$((errors + 1))
    else
        resolve_state
        step "Database"   # not-install
        if [[ "$DB_PASSWORD_GENERATED" == true ]]; then
            skip "new local database — will be created"
        elif NETFIREWALL_CONN="$(conn_string)" \
                run "Connecting to $DB_HOST:$DB_PORT/$DB_NAME…" "database reachable as $DB_USER" \
                "$BUNDLE_APP/migrations/netfirewall-migrate" status --dir "$BUNDLE_APP/migrations/sql/migrations"; then
            :
        else
            warn "can't reach $DB_USER@$DB_HOST:$DB_PORT/$DB_NAME with the configured credentials"
            errors=$((errors + 1))
        fi
        print_plan
    fi
    echo
    if (( errors > 0 )); then fail "$errors problem(s) found"; fi
    boxed "$C_OK" "✓ ready — run ./setup.sh to proceed"
    echo
}

mode_install() {
    require_root
    exec 9>/run/netfirewall-setup.lock
    flock -n 9 || fail "another setup.sh is running"
    install -d -m 0750 "$LOG_DIR"
    SETUP_LOG="$LOG_DIR/setup-$(date +%Y%m%d-%H%M%S).log"
    : > "$SETUP_LOG"; chmod 0600 "$SETUP_LOG"
    tolog "NetFirewall setup $BUNDLE_VERSION (commit ${BUNDLE_COMMIT:-?}) started $(date -u '+%Y-%m-%dT%H:%M:%SZ')"

    banner "installer · log $SETUP_LOG"
    # Counted from this file so the bar never drifts when a step is added; the
    # sections only preflight/rollback use are tagged and left out.
    STEP_TOTAL=$(grep '^[[:space:]]*step "' "${BASH_SOURCE[0]}" | grep -vc '# not-install')

    step "Host and bundle"
    check_bundle
    local rc=0
    check_host || rc=$?
    (( rc == 0 )) || fail "host checks failed (see above)"
    check_disk || fail "not enough disk space"
    resolve_state
    print_plan
    confirm "Proceed?" || fail "aborted, nothing changed"

    if [[ "$DB_PASSWORD_GENERATED" == true ]]; then DB_PASSWORD=$(openssl rand -hex 24); fi

    install_packages
    ensure_accounts_and_dirs
    provision_local_db
    backup_db
    stage_release
    run_migrations
    write_env_files
    install_system_files
    configure_nginx
    switch_and_restart
    finish_up
    run_doctor
    print_summary
}

case "$MODE" in
    list)      mode_list ;;
    rollback)  mode_rollback ;;
    preflight) mode_preflight ;;
    install)   mode_install ;;
esac
