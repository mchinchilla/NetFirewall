#!/usr/bin/env bash
#
# Builds the NetFirewall release bundle: one tar.gz with every binary published
# self-contained for linux-x64, the SQL migrations, the systemd units and config
# templates, and setup.sh — the script that installs it AND upgrades a running
# firewall from it.
#
# Runs on a dev machine or in CI (needs the .NET 10 SDK and the standalone
# tailwindcss binary on PATH), never on the firewall. The result is copied to the
# host, extracted, and `./setup.sh` does the rest.
#
#   deploy/build-bundle.sh [--version 1.4.0] [--output dist/]
#
# Without --version the version comes from `git describe --tags --always --dirty`
# (v1.4.0, v1.4.0-3-g97f88aa, 97f88aa-dirty), so every bundle names the exact
# commit it was built from. The same string is stamped into the assemblies'
# InformationalVersion (shown in the Web, the daemon's /health and Doctor) and
# written to VERSION inside the bundle.
#
set -euo pipefail

readonly REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly RID="linux-x64"

VERSION=""
OUTPUT_DIR="$REPO_ROOT/dist"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --output)  OUTPUT_DIR="$2"; shift 2 ;;
        -h|--help) sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

log()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m✗\033[0m  %s\n' "$*" >&2; exit 1; }

command -v dotnet      >/dev/null 2>&1 || fail "dotnet SDK not on PATH"
# The Web's BuildTailwindCss target shells out to it (project rule #1: no npm).
command -v tailwindcss >/dev/null 2>&1 || fail "standalone tailwindcss binary not on PATH"

if [[ -z "$VERSION" ]]; then
    VERSION="$(git -C "$REPO_ROOT" describe --tags --always --dirty 2>/dev/null || echo "dev")"
fi
VERSION="${VERSION#v}"
# Release dirs and file names carry the version: keep it to a safe charset.
[[ "$VERSION" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]] || fail "version '$VERSION' has characters unsafe for a path"

COMMIT="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "unknown")"

# AssemblyVersion must be numeric: the x.y.z of the last tag, else 0.0.0.
NUMERIC_VERSION="0.0.0"
if [[ "$VERSION" =~ ^([0-9]+\.[0-9]+\.[0-9]+) ]]; then
    NUMERIC_VERSION="${BASH_REMATCH[1]}"
fi

readonly NAME="netfirewall-$VERSION"
readonly STAGE="$OUTPUT_DIR/$NAME"
readonly APP="$STAGE/app"

log "NetFirewall bundle $VERSION (commit ${COMMIT:0:12}, assembly $NUMERIC_VERSION)"
rm -rf "$STAGE" "$OUTPUT_DIR/$NAME.tar.gz" "$OUTPUT_DIR/$NAME.tar.gz.sha256"
mkdir -p "$APP" "$STAGE/deploy"

# Self-contained: the .NET runtime travels in the bundle, so the firewall needs no
# Microsoft apt feed and a rollback also rolls back the runtime. Not trimmed and not
# single-file — RepoDb, config binding and MVC rely on reflection, and the units
# ExecStart each project's apphost.
publish() {
    local project="$1" out="$2"
    log "Publishing $project → app/$out"
    dotnet publish "$REPO_ROOT/$project/$project.csproj" \
        -c Release -r "$RID" --self-contained true \
        -p:DebugType=none -p:DebugSymbols=false \
        -p:Version="$NUMERIC_VERSION" \
        -p:InformationalVersion="$VERSION" \
        -p:IncludeSourceRevisionInInformationalVersion=false \
        -o "$APP/$out" --nologo -v q
}

publish NetFirewall.Daemon     daemon
publish NetFirewall.Web        web
publish NetFirewall.Migrations migrations
publish NetFirewall.Tui        tui
publish NetFirewall.Doctor     doctor
# Always shipped; setup.sh installs its unit only with --with-dhcp (UDP/67).
publish NetFirewall.DhcpServer dhcp-server

log "Copying SQL migrations"
mkdir -p "$APP/migrations/sql/migrations"
cp "$REPO_ROOT/NetFirewall.Services/sql/migrations/"*.sql "$APP/migrations/sql/migrations/"

# Native libraries for other platforms are dead weight on a Debian box.
find "$APP" -type d -path '*/runtimes/*' \
    \( -name 'win-*' -o -name 'osx*' -o -name 'linux-arm*' -o -name 'linux-musl-*' \) \
    -prune -exec rm -rf {} +

# Six self-contained publishes = six copies of the same runtime (~100 MB each).
# Identical files at the same relative path become hard links: tar stores a link
# once, extraction recreates it, and setup.sh copies the release with `cp -a`,
# which keeps it — so each release costs one runtime on disk, not six. JSON is
# excluded: setup.sh writes per-component appsettings and must never edit a file
# that another component shares.
log "Hard-linking identical runtime files across components"
linked=0
components=(daemon web migrations tui doctor dhcp-server)
for ((i = 1; i < ${#components[@]}; i++)); do
    comp="${components[$i]}"
    while IFS= read -r -d '' file; do
        rel="${file#"$APP/$comp/"}"
        for ((j = 0; j < i; j++)); do
            ref="$APP/${components[$j]}/$rel"
            if [[ -f "$ref" ]] && cmp -s "$ref" "$file"; then
                ln -f "$ref" "$file"
                linked=$((linked + 1))
                break
            fi
        done
    done < <(find "$APP/$comp" -type f ! -name '*.json' -print0)
done
log "  $linked files linked ($(du -sh "$APP" | cut -f1) on disk)"

log "Copying deployment assets"
for dir in systemd config env nginx sysctl modprobe.d modules-load.d tmpfiles man completion seeds; do
    cp -R "$REPO_ROOT/deploy/$dir" "$STAGE/deploy/$dir"
done
mkdir -p "$APP/bin"
install -m 0755 "$REPO_ROOT/deploy/bootstrap/netfirewall-bootstrap" "$APP/bin/netfirewall-bootstrap"
install -m 0755 "$REPO_ROOT/deploy/setup.sh"     "$STAGE/setup.sh"
install -m 0755 "$REPO_ROOT/deploy/uninstall.sh" "$STAGE/uninstall.sh"
install -m 0644 "$REPO_ROOT/deploy/README.txt"   "$STAGE/README.txt"
cp "$REPO_ROOT/deploy/README.txt" "$APP/README.txt"

# VERSION goes in both places: next to setup.sh (what is about to be installed)
# and inside app/ (what a release dir is — Doctor reads it from $PREFIX/current).
echo "$VERSION" > "$STAGE/VERSION"
echo "$VERSION" > "$APP/VERSION"
cat > "$STAGE/BUILD_INFO" <<EOF
version=$VERSION
assembly_version=$NUMERIC_VERSION
commit=$COMMIT
built_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
runtime=$RID (self-contained)
EOF
cp "$STAGE/BUILD_INFO" "$APP/BUILD_INFO"

# Secrets never travel in a bundle: the env templates must still be tokenized.
for t in daemon web dhcp; do
    grep -q '__REPLACE__' "$STAGE/deploy/env/$t.env.template" \
        || fail "deploy/env/$t.env.template lost its __REPLACE__ placeholder"
done
if grep -rlE --include='*.template' --include='*.env' --include='appsettings*.json' \
        '^NETFIREWALL_MASTER_KEY=[A-Za-z0-9+/]{40,}={0,2}$' "$STAGE" >/dev/null 2>&1; then
    fail "a real master key ended up in the bundle"
fi

# Each binary the units and wrappers execute must exist.
for bin in daemon/netfirewall-daemon web/NetFirewall.Web dhcp-server/NetFirewall.DhcpServer \
           migrations/netfirewall-migrate tui/netfirewall-tui doctor/netfirewall-doctor; do
    [[ -f "$APP/$bin" ]] || fail "missing app/$bin after publish (assembly name changed?)"
done

log "Packing"
# GNU tar on CI; bsdtar on macOS needs --no-xattrs/--no-mac-metadata to keep the
# archive free of AppleDouble (._*) files that confuse the Linux side.
tar_flags=()
for flag in --no-xattrs --no-mac-metadata; do
    if tar "$flag" --version >/dev/null 2>&1; then tar_flags+=("$flag"); fi
done
COPYFILE_DISABLE=1 tar "${tar_flags[@]}" -C "$OUTPUT_DIR" -czf "$OUTPUT_DIR/$NAME.tar.gz" "$NAME"

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$OUTPUT_DIR" && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
else
    (cd "$OUTPUT_DIR" && shasum -a 256 "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
fi
rm -rf "$STAGE"

log "Done: $OUTPUT_DIR/$NAME.tar.gz ($(du -h "$OUTPUT_DIR/$NAME.tar.gz" | cut -f1))"
cat <<EOF

  On the firewall (as root):
    tar xzf $NAME.tar.gz && cd $NAME
    ./setup.sh --preflight          # check the host, change nothing
    ./setup.sh [options]            # install, or upgrade in place
EOF
