NetFirewall — production deployment
====================================

NetFirewall ships as a release bundle: netfirewall-<version>.tar.gz, built by
deploy/build-bundle.sh (locally or by .github/workflows/release.yml on every
push to master, which tags the next version). It holds every binary published self-contained for linux-x64 (no .NET
on the host), the SQL migrations, the systemd units, config templates and
setup.sh — which installs a new firewall AND upgrades a running one.

Full reference (every option, every step, failure modes): docs/setup.md

Bundle layout
-------------

  setup.sh                       Install / upgrade / --rollback / --preflight
  uninstall.sh                   Reverse setup (keeps data unless --purge)
  VERSION, BUILD_INFO            git-describe version + commit + build date
  app/                           Copied to <prefix>/releases/<version>
    daemon/ web/ dhcp-server/ tui/ doctor/ migrations/ bin/
  deploy/
    systemd/                     Units (@PREFIX@ rendered by setup.sh)
      netfirewall-daemon.service   Privileged daemon (root, restricted CAPs)
      netfirewall-web.service      Unprivileged Web (netfirewall-web user)
      netfirewall-dhcp.service     DHCP server — opt-in (--with-dhcp)
      netfirewall-bootstrap.service  Boot-time apply — on for new installs
    config/                      Production appsettings (no secrets)
    env/                         daemon/web/dhcp env templates (tokenized)
    nginx/                       TLS site (self-signed on fresh installs) + LE example
    sysctl/ modprobe.d/ modules-load.d/ tmpfiles/
    man/ completion/ seeds/

Requirements
------------

* Debian 12/13 or Ubuntu 22.04+, x86_64, systemd running, root.
* Nothing else: setup.sh apt-installs what is missing (PostgreSQL when the DB
  is local, nginx on a fresh install, nftables/conntrack/tcpdump/… tools).

Install
-------

  tar xzf netfirewall-1.4.0.tar.gz && cd netfirewall-1.4.0
  ./setup.sh --preflight        # checks only, changes nothing
  ./setup.sh                    # installs

A fresh install provisions a local PostgreSQL role + database with a random
password, generates the AES-256 master key (written identically to daemon.env
and web.env), configures nginx with a self-signed certificate, starts the
services and runs netfirewall-doctor.

setup.sh prints the master key on completion. **Save it somewhere secure**
(password manager). Losing it permanently invalidates every TOTP enrollment —
users would have to re-enroll from scratch.

After install
-------------

1. `systemctl status netfirewall-daemon netfirewall-web` — both active.

2. `journalctl -u netfirewall-web | grep -i bootstrap` — the one-time token
   to create the first admin user.

3. Replace the self-signed certificate:
   `./setup.sh --tls-cert /path/fullchain.pem --tls-key /path/privkey.pem`
   NOTE: the web terminal (admin-only root shell) uses a WebSocket at
   /terminal/ws. The shipped nginx configs support it via the
   `map $http_upgrade $connection_upgrade` block + a dedicated
   `location = /terminal/ws` with a long proxy_read_timeout. If you use a
   different proxy, it MUST forward the Upgrade/Connection headers and NOT
   apply a short read timeout to that path, or live terminals get dropped.

4. Create the admin → enroll TOTP → run the setup wizard.

Upgrading
---------

Extract the newer bundle and run ./setup.sh — options are remembered in
/etc/netfirewall/setup.conf. It backs up the DB (pg_dump), stages the release,
migrates with the NEW binaries BEFORE switching, flips <prefix>/current,
restarts and health-checks; if the daemon or Web don't come back it rolls back
automatically. Master key, DB password and env-file edits are preserved.

  ./setup.sh --list-releases
  ./setup.sh --rollback [VERSION]   # schema is NOT rolled back (forward-only)

Removing
--------

  ./uninstall.sh           # stops + removes units, releases, tools
  ./uninstall.sh --purge   # also wipes config, secrets, logs, users

The PostgreSQL database is NEVER touched automatically. Drop it manually if
you want a clean slate.

Hardening notes
---------------

The daemon and web services are configured with extensive systemd sandboxing
(see the .service files for the full list). Highlights:

  * Daemon runs as root, but CapabilityBoundingSet limits it to
    CAP_NET_ADMIN + CAP_DAC_OVERRIDE + CAP_NET_RAW. Everything else
    (CAP_SYS_ADMIN, CAP_SYS_MODULE, etc.) is unavailable.

  * Web runs as `netfirewall-web` (member of `netfirewall` group, no caps).
    Only filesystem path it can write is /var/lib/netfirewall/web.

  * ProtectSystem=strict + ReadWritePaths makes /usr /boot /efi read-only.

  * PrivateTmp, PrivateDevices, ProtectHome, ProtectKernelTunables,
    ProtectControlGroups, NoNewPrivileges, RestrictNamespaces and friends
    are all enabled.

  * MemoryDenyWriteExecute is intentionally OFF — it would crash the .NET
    JIT. Switch to ReadyToRun or NativeAOT publish to enable it.

The TOTP master key lives in /etc/netfirewall/daemon.env (0600 root) and
web.env (0640 root:netfirewall); with Daemon:UseForTotp=true the Web proxies
crypto to the daemon. See docs/master-key.md.

Troubleshooting
---------------

* `Permission denied` on the socket → check the netfirewall-web user is in
  the netfirewall group: `id netfirewall-web`. If not: `usermod -aG
  netfirewall netfirewall-web`, then re-login the service: `systemctl
  restart netfirewall-web`.

* `nmcli`/`ifup` calls fail → check the daemon's CapabilityBoundingSet
  hasn't been pruned by a third party (some kernel hardening removes
  CAP_NET_ADMIN globally). `getpcaps $(pgrep netfirewall-daemon)`.

* Web complains "NETFIREWALL_MASTER_KEY missing" → the env file isn't
  loaded. Check `sudo systemctl cat netfirewall-web` mentions
  `EnvironmentFile=/etc/netfirewall/web.env` and the file exists with
  mode 0640.

* Terminal "The daemon cannot verify TOTP — it is missing
  NETFIREWALL_MASTER_KEY" (or daemon-side /v1/crypto fails) → the DAEMON's
  env file lacks the key, or it differs from the Web's. The daemon and Web
  MUST hold the identical key. Fix:
      grep '^NETFIREWALL_MASTER_KEY=' /etc/netfirewall/web.env \
        >> /etc/netfirewall/daemon.env
      chmod 0600 /etc/netfirewall/daemon.env
      systemctl restart netfirewall-daemon
  Full reference: docs/master-key.md. setup.sh writes the same key to both
  files and asserts they match; this only bites hand-edited hosts.

* TOTP codes always rejected after restart → the master key was regenerated
  (the env file was wiped or replaced) OR the daemon's key drifted from the
  Web's. Restore the original key from backup into BOTH env files, or have
  every user re-enroll. See docs/master-key.md.

------------------------------------------------------------------------
Validating a deployment (netfirewall-doctor)
------------------------------------------------------------------------
`netfirewall-doctor` checks env vars, master-key sync, paths, systemd
units, the daemon socket, and the database — one table, with a remedy per
problem. setup.sh runs it as the final step; re-run it anytime:

    netfirewall-doctor                 # full check, human-readable
    netfirewall-doctor --json          # for CI / scripts (exit 1 on failure)
    netfirewall-doctor --prefix /opt/tekium/current   # explicit release dir

Full reference: docs/doctor.md.

------------------------------------------------------------------------
Master key (NETFIREWALL_MASTER_KEY)
------------------------------------------------------------------------
The AES-256 key that encrypts TOTP secrets. The daemon AND the Web must
hold the byte-for-byte identical key (both decrypt the same secrets). The
setup.sh generates it once and writes it to both /etc/netfirewall/web.env
and /etc/netfirewall/daemon.env, then verifies they match. Losing it
invalidates every TOTP enrollment — keep a secure backup. Full rules and
diagnostics: docs/master-key.md.
