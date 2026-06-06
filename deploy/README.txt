NetFirewall — production deployment
====================================

This directory contains everything needed to deploy NetFirewall on a
systemd-based Linux host (Debian 12+, Ubuntu 22.04+, Rocky/Alma 9+,
openSUSE Leap 15.5+).

Layout
------

  systemd/
    netfirewall-daemon.service   Privileged daemon (root, restricted CAPs)
    netfirewall-web.service      Unprivileged Web (netfirewall-web user)

  config/
    daemon.json.template         Production appsettings for the daemon
    web.json.template            Production appsettings for the Web

  env/
    daemon.env.template          DB password + peer UID (mode 0600 root)
    web.env.template             DB password + master key (mode 0640 root:netfirewall-web)

  nginx/
    netfirewall.conf             Reverse-proxy example for TLS termination

  install.sh                     Build + install + enable everything
  uninstall.sh                   Reverse install (preserves data unless --purge)

Prerequisites
-------------

* PostgreSQL 14+ running on the host (or reachable via network)
* .NET 10 SDK installed (used to publish the projects)
* `psql` client + `openssl` on PATH
* systemd 250+ (for RuntimeDirectory, StateDirectory, etc.)
* nginx, caddy or traefik for TLS termination (optional but strongly recommended)

PostgreSQL setup (one-time)
---------------------------

  sudo -u postgres psql <<SQL
    CREATE ROLE netfirewall WITH LOGIN PASSWORD 'CHANGEME';
    CREATE DATABASE net_firewall OWNER netfirewall;
    GRANT ALL PRIVILEGES ON DATABASE net_firewall TO netfirewall;
  SQL

Then run the installer.

Installation
------------

From a checked-out repo on the target server:

  sudo deploy/install.sh

The installer prompts for the PostgreSQL password (use what you set above),
publishes both projects to /opt/netfirewall, applies migrations, generates
an AES-256 master key for TOTP encryption, writes config + env files with
correct ownership/perms, installs systemd units and starts everything.

The installer prints the master key on completion. **Save it somewhere
secure** (password manager). Losing it permanently invalidates every TOTP
enrollment — users would have to re-enroll from scratch.

After install
-------------

1. `sudo systemctl status netfirewall-daemon netfirewall-web`
   Both should be `active (running)`.

2. `sudo journalctl -u netfirewall-web` — look for the bootstrap banner with
   the one-time token to create the first admin user.

3. Configure your reverse proxy (see nginx/netfirewall.conf for nginx).
   NOTE: the web terminal (admin-only root shell) uses a WebSocket at
   /terminal/ws. The shipped nginx config supports it via the
   `map $http_upgrade $connection_upgrade` block + a dedicated
   `location = /terminal/ws` with a long proxy_read_timeout. If you use a
   different proxy, it MUST forward the Upgrade/Connection headers and NOT
   apply a short read timeout to that path, or live terminals get dropped.
   No systemd unit change is needed for the terminal: PTY allocation
   (openpty + posix_spawn) was verified to work under the daemon's existing
   hardened sandbox (PrivateDevices=yes + the SystemCallFilter) — see the
   Phase 3a spike. The terminal runs in the daemon (root); the Web only
   proxies bytes.

4. Browse to https://your-host/setup/bootstrap?token=<...>

5. Create the admin → enroll TOTP → run the setup wizard.

Upgrading
---------

Pull the latest code, then:

  sudo deploy/install.sh --skip-publish=false

The installer is idempotent. It re-publishes binaries, re-applies missing
migrations, and reuses the existing master key + connection password. TOTP
enrollments and sessions survive.

Removing
--------

  sudo deploy/uninstall.sh           # stops + removes binaries + units
  sudo deploy/uninstall.sh --purge   # also wipes config, secrets, logs, users

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

The TOTP master key currently lives in /etc/netfirewall/web.env (mode 0640,
root + netfirewall-web). A future version will move it into the daemon
(rule: only root reads the key, Web requests TOTP verification via socket).

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

* TOTP codes always rejected after restart → the master key was regenerated
  (the env file was wiped or replaced). Restore the original key from
  backup, or have every user re-enroll.
