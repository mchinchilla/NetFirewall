# NetFirewall — Tekium deploy handoff

Mid-deployment state of `fw.tekium.net` (server 192.168.99.1 / 154.12.104.135).
Resume from here when continuing the deploy — covers what was done, what
broke, what was fixed, and what's still pending. Last touched 2026-05-17.

## Session-end snapshot (2026-05-17 00:36 CST)

- Apply nftables **successfully ran** against production. The live ruleset
  (`nft list ruleset`, 89 lines) was regenerated from `fw_*` tables.
- Backups in `/var/lib/netfirewall/backups/` (timestamped before each apply).
- Internet reachability + masquerade NAT verified (`ping 8.8.8.8` from WAN OK).
- Policy routing (ip rule, table wan1/wan2/202) still working — the `firewall.sh`
  legacy script's iproute2 state persists across restarts.
- QoS via `Apply tc` works (tc HTB + classes).
- Known gap: the generator can't emit `tcp flags syn ... drop` (anti-MSS) yet
  because `fw_filter_rules` lacks tcp_flags / tcp_options columns. The legacy
  rules of this kind are NOT in the live ruleset now.
- Known gap: `chain output` ICMP echo accept on WAN — also not emitted.

## Operator preferences (apply to every shell command you suggest)

1. **Never use `sudo`** — the user works as root.
2. **Use `vi`, not `nano`.** Or better, use `cat > file <<EOF` / `tee` / `sed -i`
   for mechanical edits to avoid opening an editor at all.
3. The user is on macOS (Mac). The target is a Debian 13 server.

## Server layout (NOT the default `/opt/netfirewall/`)

```
/opt/tekium/
├── daemon/                 # netfirewall-daemon binary + dlls
├── webui/                  # NetFirewall.Web binary + dlls + wwwroot
├── dhcp_server/            # NetFirewall.DhcpServer (not yet deployed/started)
├── wan_monitor/            # NetFirewall.WanMonitor (not yet wired up)
└── Migrations/             # netfirewall-migrate + sql/migrations/
```

Config + secrets:
```
/etc/netfirewall/daemon.env   (0600 root:root)   — DB pw, peer UIDs, SocketGroup=netfirewall
/etc/netfirewall/web.env      (0640 root:netfirewall) — DB pw, master key, ASPNETCORE_URLS=http://127.0.0.1:5000
/opt/tekium/daemon/appsettings.Production.json   (0640 root:netfirewall)
/opt/tekium/webui/appsettings.Production.json    (0640 root:netfirewall)
```

Runtime:
```
/run/netfirewall/control.sock  (srw-rw---- root:netfirewall) — created by tmpfiles.d
/etc/tmpfiles.d/netfirewall.conf  → d /run/netfirewall 0750 root netfirewall -
/var/log/netfirewall/{daemon,web}/
```

Users/groups:
- group `netfirewall` (gid 996)
- user `netfirewall-web` (uid 999, gid 996, nologin) — runs the Web
- Daemon runs as `root` clamped by CapabilityBoundingSet

## Master key (KEEP BACKED UP)

```
NETFIREWALL_MASTER_KEY=VE+HSXBmGUj3AEKiIIvTxg9qnHTPca5mmA2SiLCv7WE=
```

Lives in `/etc/netfirewall/web.env`. Losing it invalidates every TOTP
enrollment. The user already enrolled with Cisco Duo against this key.

## PostgreSQL

- Host: `127.0.0.1:5432`
- Database: `net_firewall`
- User: `netfirewall` / pw `1Nframund0` (shared in chat — should be rotated)
- All 20 migrations applied (verified via `netfirewall-migrate status`)
- Seed `deploy/seeds/seed_tekium.sql` applied — populates fw_traffic_marks,
  fw_port_forwards, fw_nat_rules, fw_filter_rules, fw_mangle_rules,
  fw_static_routes, fw_qos_config, fw_qos_classes with the rules currently
  enforced by the legacy `/etc/nftables.conf` and `/root/firewall.sh`.

## nginx + TLS

- Cert: `/etc/letsencrypt/live/fw.tekium.net/{fullchain,privkey}.pem`
  (Let's Encrypt, renews via certbot timer, valid through 2026-08-15)
- Site: `/etc/nginx/sites-available/netfirewall.conf` → `sites-enabled/`
- Proxies `https://fw.tekium.net/` → `http://127.0.0.1:5000` (Kestrel)
- Loopback-only bind on Kestrel side (intentional)

## What's deployed and verified working

- **Daemon** running, `sd_notify(READY=1)` reaches systemd, socket OK.
- **Web** running, login + TOTP enrollment + `/Network/Interfaces` listing
  all functional. Cisco Duo enrolled against the master key.
- **Re-detect** (first click) reconciles `fw_interfaces` with `/sys/class/net`
  via the daemon's `POST /v1/network/interfaces/redetect` endpoint. IPs/MACs
  match `ip addr` output.

## What's BROKEN (current focus)

### Bug: second click on "Re-detect" logs the user out

Symptom: First click works, table re-renders, toast shows "X updated". Second
click returns the page "This page isn't working" and the user lands on /login.

What I tried (didn't fix it):
- `[IgnoreAntiforgeryToken]` on `Redetect` action → user reports it's still
  broken after redeploy. Hypothesis: binary may not actually be the new one
  on disk. Verify with:
  ```
  md5sum /opt/tekium/webui/NetFirewall.Web.dll
  ```
  Compare against the Mac publish output's md5.

What to check next:
1. Confirm the deployed dll is current. The user wasn't able to confirm.
2. While reproducing, watch `journalctl -u netfirewall-web -f`. Look for:
   - 400 → antiforgery still wins → fix didn't ship or there's a global filter
   - 200 with weird payload → something else
   - 500 → look for exception
3. From a logged-in browser, grab the session cookie (DevTools → Application →
   Cookies → `__Host-NetFw` or whatever name), then curl the endpoint twice
   in a row with that cookie + `HX-Request: true`. If the second curl works,
   the bug is browser-side (HTMX swap of partial losing CSRF token in DOM).
   If it fails the same way, server-side.
4. Look at `wwwroot/js/site.js` around the `htmx:responseError` handler
   (~line 891) — it bounces the user to /login on certain error responses.
   It might be over-eagerly redirecting on a 400 that should be silenced.

Relevant code paths:
- `NetFirewall.Web/Controllers/NetworkController.cs` → `Redetect` action
- `NetFirewall.Web/Views/Network/Interfaces.cshtml` → button at line ~18,
  `hx-post="/Network/Redetect"`, no `hx-headers` for CSRF because there's a
  global `htmx:configRequest` handler in `wwwroot/js/site.js` that injects
  `RequestVerificationToken` from a meta tag.

## What's pending (after the bug above)

1. **DataProtection persistent keys** — both daemon and Web warn
   `Using an in-memory repository. Keys will not be persisted to storage.`
   Result: every restart of the Web invalidates session cookies. Fix:
   register `IDataProtectionBuilder.PersistKeysToFileSystem(new DirectoryInfo("/var/lib/netfirewall/web/keys"))`
   in `NetFirewall.Web/Program.cs`. Same treatment for daemon → its own
   dir under `/var/lib/netfirewall/daemon/keys`.

2. **Bootstrap token to disk** — Web logs
   `Read-only file system : '/opt/tekium/webui/logs'` when trying to write
   `logs/bootstrap-token.txt`. The path should be `/var/log/netfirewall/web/`
   (writable thanks to `ReadWritePaths=` in the unit). Fix in
   `NetFirewall.Web/Auth/Bootstrap/BootstrapTokenIssuer.cs` — the path it
   writes to is hardcoded; thread it through `IHostEnvironment.ContentRootPath`
   or use an `IOptions` setting. Not blocking — token also goes to journal.

3. **Daemon never regenerates `/etc/nftables.conf`** — the seed is in the DB
   but the legacy `/etc/nftables.conf` + `/root/firewall.sh` are still the
   operative source of truth. Building the regeneration path (DB → nftables
   ruleset → `nft -f` via daemon's `INftApplyService`) is a substantial
   piece of work. **Do NOT** run it against production until the user
   explicitly approves — would replace the live ruleset.

4. **DhcpServer not deployed** — exists at `/opt/tekium/dhcp_server/`?
   user said the folder is there. Not running, no systemd unit installed
   yet. Pending decision whether to use it (would replace whatever DHCP
   server currently serves the 192.168.99.0/24 LAN).

5. **WanMonitor not deployed as systemd unit yet.** Was building from
   `NetFirewall.WanMonitor` earlier. Folder exists at `/opt/tekium/wan_monitor`.

6. **Test suite** — 70 CA1416 warnings in NetFirewall.Tests from the
   `[SupportedOSPlatform("linux")]` cascade we added earlier. Not blocking
   deploy. Either annotate the test assembly the same way, or split out
   tests that hit Linux-only services. The user explicitly said to keep
   the Tests warnings for later.

## Repo changes already pushed locally to the Mac (NOT yet committed)

If the user wants to commit progress, this is what's been touched (paths
relative to repo root):

- `deploy/systemd/netfirewall-daemon.service` — added CAP_CHOWN, removed
  RuntimeDirectory= for /run/netfirewall (replaced by tmpfiles.d),
  optional ReadWritePaths with `-` prefix
- `deploy/tmpfiles/netfirewall.conf` — NEW; declares /run/netfirewall
  group ownership
- `deploy/seeds/seed_tekium.sql` — NEW; tekium-specific rule seed
- `NetFirewall.Daemon/Program.cs` — `[assembly: SupportedOSPlatform("linux")]`,
  `UseSystemd()`, fixed ApplySocketMode timing via
  `Lifetime.ApplicationStarted.Register`, P/Invoke chown to group
- `NetFirewall.Daemon/NativeMethods.cs` — NEW; libc chown + getgrnam P/Invoke
- `NetFirewall.Daemon/DaemonOptions.cs` — added `SocketGroup` property
- `NetFirewall.Daemon/Endpoints/NetworkEndpoints.cs` — new
  `POST /v1/network/interfaces/redetect` + `ParseMaskFromCidr` helper
- `NetFirewall.Daemon/NetFirewall.Daemon.csproj` — added Microsoft.Extensions.Hosting.Systemd
- `NetFirewall.Services/Daemon/IDaemonClient.cs` — added `RedetectInterfacesAsync`
- `NetFirewall.Services/Daemon/DaemonClient.cs` — impl
- `NetFirewall.Services/Daemon/NullDaemonClient.cs` — impl stub
- `NetFirewall.Services/Firewall/FirewallService.cs` — added `IPAddressJsonConverter`
  + audit JsonSerializerOptions to stop IPv6 link-local crash on audit
- `NetFirewall.Services/Firewall/TcApplyService.cs` — `[SupportedOSPlatform("linux")]`
- `NetFirewall.Services/Vpn/WireGuardApplyService.cs` — same
- `NetFirewall.Services/Monitoring/SystemMonitorService.cs` — pragma local CA1416
- `NetFirewall.Services/Dhcp/DhcpAdminService.cs` — cidr→IPNetwork read fix,
  null coalesce for CS8604, IPNetwork.Parse for cidr writes
- `NetFirewall.Services/Dhcp/DhcpSubnetService.cs` — null coalesce
- `NetFirewall.Models/NetFirewall.Models.csproj` — removed System.Text.RegularExpressions
- `NetFirewall.Models/System/RedetectResult.cs` — NEW
- `NetFirewall.Models/Dhcp/Dhcp{Config,Option,MacReservation,Lease,Reponse,Request}.cs`
  — added zero-alloc defaults to 90 properties to clear CS8618
- `NetFirewall.WanMonitor/WanMonitorService.cs` — cleaned warnings,
  `Process? process = null`
- `NetFirewall.WanMonitor/NetFirewall.WanMonitor.csproj` — disabled AOT
  (RepoDb incompatibility)
- `NetFirewall.DhcpServer/NetFirewall.DhcpServer.csproj` — removed
  System.Text.RegularExpressions
- `NetFirewall.Web/Program.cs` — `UseSystemd()`, `UseForwardedHeaders()`
  + `Configure<ForwardedHeadersOptions>` so X-Forwarded-For from nginx
  populates `Connection.RemoteIpAddress`
- `NetFirewall.Web/Auth/Bootstrap/BootstrapTokenIssuer.cs` — pragma CA1416
- `NetFirewall.Web/Controllers/AuthController.cs` — removed class-level
  `[AllowAnonymous]`, marked the 4 login actions individually (security fix:
  Elevate/Logout now actually require auth as the existing `[Authorize]`
  intended)
- `NetFirewall.Web/Controllers/NetworkController.cs` — injected IDaemonClient,
  added `Redetect` action, currently with `[IgnoreAntiforgeryToken]` (this
  is the path of the bug above)
- `NetFirewall.Web/Views/Network/Interfaces.cshtml` — button now `hx-post`
- `NetFirewall.Web/Views/Network/_InterfaceForm.cshtml` — fixed Guid.ToString
  format string crash (`"\"D\""` → `$"\"{...:D}\""`)
- `NetFirewall.Web/Views/FwTrafficMarks/_TrafficMarksTable.cshtml` — Razor
  parser fix: `0x@(m.MarkValue.ToString("X"))`
- `NetFirewall.Web/NetFirewall.Web.csproj` — added Microsoft.Extensions.Hosting.Systemd

## Publish/deploy commands the user has been using

From the Mac (publish outputs):
```bash
dotnet publish NetFirewall.Daemon/NetFirewall.Daemon.csproj      -c Release -r linux-x64 --self-contained false -o /Users/mchinchilla/Downloads/Deployments/NetFirewall/Daemon
dotnet publish NetFirewall.Web/NetFirewall.Web.csproj            -c Release -r linux-x64 --self-contained false -o /Users/mchinchilla/Downloads/Deployments/NetFirewall/WebUI
dotnet publish NetFirewall.Migrations/NetFirewall.Migrations.csproj -c Release -r linux-x64 --self-contained false -o /Users/mchinchilla/Downloads/Deployments/NetFirewall/Migrations
dotnet publish NetFirewall.WanMonitor/NetFirewall.WanMonitor.csproj -c Release -r linux-x64 --self-contained false -o /Users/mchinchilla/Downloads/Deployments/NetFirewall/WanMonitor
```

Then to the server:
```bash
rsync -avz --delete /Users/mchinchilla/Downloads/Deployments/NetFirewall/Daemon/ root@192.168.99.1:/opt/tekium/daemon/
rsync -avz --delete /Users/mchinchilla/Downloads/Deployments/NetFirewall/WebUI/  root@192.168.99.1:/opt/tekium/webui/
# Then on the server:
chmod 0755 /opt/tekium/daemon/netfirewall-daemon /opt/tekium/webui/NetFirewall.Web
systemctl restart netfirewall-daemon netfirewall-web
```

(`rsync --delete` is intentional: ensures stale dlls don't linger. The
`appsettings.Production.json` is on the server only — exclude it if needed.)

## Verification one-liners

```bash
# Daemon socket health
ls -la /run/netfirewall/control.sock
journalctl -u netfirewall-daemon -n 20 --no-pager
su -s /bin/sh -c 'ls -la /run/netfirewall/control.sock' netfirewall-web

# Web health
systemctl status netfirewall-web --no-pager
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5000/login
curl -sS -o /dev/null -w "%{http_code}\n" https://fw.tekium.net/login

# Migration status
NETFIREWALL_CONN="Host=127.0.0.1;Port=5432;Username=netfirewall;Password=1Nframund0;Database=net_firewall" \
    /opt/tekium/Migrations/netfirewall-migrate status --dir /opt/tekium/Migrations/sql/migrations
```

## Live legacy firewall (DO NOT MODIFY until daemon regeneration is wired)

- `/etc/nftables.conf` — the live ruleset (NAT, port forwards, filter, mangle, QoS netdev tables)
- `/root/firewall.sh` — the script that loads iproute2 tables (wan1, wan2, table 202 for wg0),
  policy rules, tc HTB hierarchies, and finally `nft -f /etc/nftables.conf`
- WANs: ens192 (154.12.104.135 / .254 gw, 800 Mbps), ens224 (190.107.150.161 / .1 gw, 500 Mbps)
- LAN: ens256 (192.168.99.1/24)
- VPN: wg0 (192.168.3.2 / point-to-point 192.168.3.2)
- The seed in `deploy/seeds/seed_tekium.sql` mirrors all of this in the DB
