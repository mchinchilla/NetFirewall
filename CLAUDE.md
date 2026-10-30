# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NetFirewall is a personal firewall system built with C# / .NET 10.0 and PostgreSQL. .NET Aspire orchestrates the dev-time topology. The WAN Monitor is production-ready; the DHCP Server is the active focus of development; the Web UI is currently a default MVC scaffold pending re-implementation.

## Project rules (non-negotiable)

These are hard constraints. Do not deviate without explicit user approval.

1. **No npm / Node tooling, ever.** All client-side dependencies are vendored under `wwwroot/lib/` (HTMX, Alpine.js) and Tailwind CSS is compiled with the **standalone `tailwindcss` binary** (must be on `PATH`). Do not add `package.json`, `node_modules`, `npx` calls, MSBuild targets that shell out to npm, or CDN-only dependencies that imply a Node build step.
2. **Async/await everywhere.** All I/O — C# server code (controllers, services, repositories, hosted services) and JavaScript browser code (HTMX hooks, Alpine components, `fetch` calls) — must use `async`/`await`. No `.Result`, no `.Wait()`, no `.GetAwaiter().GetResult()`, no synchronous DB or HTTP calls, no `.then()` chains in JS.
3. **One CSS file, one JS file.** All styles live in `NetFirewall.Web/Styles/site.css` (compiled to `wwwroot/css/site.css`); all custom JavaScript lives in `NetFirewall.Web/wwwroot/js/site.js`. Do not create per-page `.css`/`.js` files, do not use `<style>` blocks in views, and do not use Razor scoped CSS (`*.cshtml.css`). Use Tailwind utility classes for styling and Alpine `x-data` (inline) for tiny interactions; anything bigger goes in `site.js`.
4. **Validate every input on both sides.** Any form, query string, or JSON body that accepts user input must be validated **client-side** (Tailwind-styled error states + HTML5 constraints + Alpine logic where needed) **and** server-side (`ModelState` / DataAnnotations / FluentValidation in controllers + service-layer guards). Never trust client validation alone.
5. **Generics + typed contracts.** Backend → UI returns must use `ServiceResponse<T>` (`NetFirewall.Models/ServiceResponse.cs` — `Success`, `Message`, `Data`, `Timestamp`). Prefer interfaces (`IFooService`) and generic helpers (`Repository<T>`, `Result<T>`, etc.) over concrete duplication. Controllers/endpoints must surface `Success` + `Message` from the response so the UI can act on them uniformly.
6. **Always show user feedback.** Every backend operation triggered from the UI must produce a visible outcome — toast, decorated alert banner, inline form error, or status pill — for both success and failure paths. There is a single shared toast/alert component in the layout; reuse it via HTMX response headers (e.g. `HX-Trigger: showToast`) or Alpine store events. Silent successes and silent failures are bugs.
7. **Decompose into partials/components, always.** Every recurring or self-contained piece of UI lives in its own `_PartialName.cshtml` (or typed view component) under `Views/Shared/` (cross-cutting) or alongside the feature view (one-off). Reusable interactive primitives (`_ConfirmDialog`, `_Toasts`, `_FormField`, `_Pagination`, `_StatusBadge`, etc.) take a typed model and are invoked via `Html.PartialAsync` / `Component.InvokeAsync`. `_Layout.cshtml` itself must only **compose** partials — no inline `<style>`, no inline business markup, no duplicated chrome. If you find yourself copy-pasting markup between views or pages, stop and extract a partial first. Backend equivalent: prefer small interfaces + generic helpers over duplicated controller/service code.
8. **Every process is a DI-registered service.** Any unit of business logic, IO, integration, or stateful work lives behind an `IFooBar` interface, with its concrete `FooBar` registered in `Program.cs`. Controllers, views, and other services depend on the **interface**, never on a concrete or a `new FooBar()`. This includes anything that touches the database, filesystem, network, external processes, time, randomness, or other services. Allowed exceptions (still, prefer DI when in doubt): pure-data POCOs / DTOs / view models, pure-function utilities with zero state and no IO (e.g., a CIDR parser), Razor-side `IHtmlHelper` extensions that wrap framework concerns. **Not** allowed: static "manager" / "helper" / "util" classes that hold business logic, controller-private methods that should be reused across controllers, `Process.Start(...)` outside an injected runner. The goal: every operation can be mocked, replaced, decorated, or scoped (Singleton/Scoped/Transient) at composition time.
9. **All UI styling flows through the theme system.** Every color, border, surface, accent, feedback hue, and spacing rule used by views, partials, and components must reference the **semantic tokens** defined in `Styles/site.css` (`--surface-bg`, `--surface-fg`, `--surface-elevated`, `--surface-muted`, `--surface-border`, `--surface-fg-muted`, `--sidebar-*`, `--accent`, `--accent-fg`, `--accent-soft`, `--feedback-{success,danger,warning,info}-{bg,fg,bd}`) — exposed as Tailwind utilities (`bg-surface`, `text-surface-fg`, `bg-accent`, `text-accent`, ...) or via `style="color: var(--…);"`. **Never** use raw palette names (`var(--boulder-700)`, `var(--magic-mint-500)`) directly in views — those exist only inside `site.css` to compose tokens. **Never** hardcode hex literals (`#fff`, `#b94545`) or Tailwind palette utilities (`bg-red-500`, `text-slate-700`). For new semantic colors, add a token to `site.css` first and reference that token. Same rule for spacing/radii/shadows/animations: prefer Tailwind utilities or define a token rather than hard-coding.
10. **No SQL or data access in controllers.** Controllers are thin orchestrators that compose injected services and shape responses. **Never** put `NpgsqlCommand`, `dataSource.OpenConnectionAsync`, raw SQL strings, RepoDb queries, file reads, `Process.Start`, HTTP calls, or in-memory caching inside a controller action. The right path: define / extend a service interface (`IFooService`), implement the IO inside the concrete service, register it in `Program.cs`, inject the interface. Controller bodies should read like a one-paragraph summary of the use case (`var x = await service.DoThing(...); return this.ToHtmxResponse(envelope);`). Same rule for view components, Razor pages, and tag helpers — they delegate to services. Backend equivalent: services don't copy-paste each other's SQL — extract a shared method or repository service. The contract is **controllers compose, services do**.

## Build Commands

```bash
# Build / test
dotnet build
dotnet build -c Release
dotnet test
dotnet test --filter "FullyQualifiedName~TestMethodName"

# Run the orchestrated dev environment (Aspire)
dotnet run --project NetFirewall.AppHost

# Release bundle for Linux deployment (self-contained linux-x64 tar.gz → dist/)
deploy/build-bundle.sh                     # version = git describe --tags --always --dirty
deploy/build-bundle.sh --version 1.5.0-rc1
```

## Production deployment

Production ships as a **release bundle** and is installed/upgraded by
**`deploy/setup.sh`**. Full operator reference (every option, every step,
failure modes, migrating from the old layout): **`docs/setup.md`**.

```
deploy/
  build-bundle.sh                       builds dist/netfirewall-<version>.tar.gz (dev box / CI)
  setup.sh                              install + upgrade + --rollback + --preflight (runs ON the firewall)
  uninstall.sh                          reverse setup (--purge wipes config/state/users, never the DB)
  systemd/                              hardened units; @PREFIX@ is rendered by setup.sh
  config/{daemon,web}.json.template     prod appsettings (no secrets) → per-release appsettings.Production.json
  env/{daemon,web,dhcp}.env.template    tokenized (__REPLACE__) — secrets are minted on the host, never bundled
  nginx/                                netfirewall-appliance.conf.template (self-signed, fresh installs) + LE example
  bootstrap/netfirewall-bootstrap       boot-time apply script (netfirewall-bootstrap.service)
  sysctl/ modprobe.d/ modules-load.d/ tmpfiles/ man/ completion/ seeds/
```

**Bundle** (`build-bundle.sh`): publishes daemon, web, dhcp-server, migrations
(+ `sql/migrations/*.sql`), tui, doctor **self-contained** for linux-x64 (no .NET
on the host; libicu still needed), hard-links the identical runtime files across
the six components (tar stores them once; `cp -a` keeps the links — so never write
through a file in a release dir: `rm` then create, and JSON is excluded from
linking). Version = `git describe` (leading `v` stripped), stamped as
`-p:InformationalVersion` and written to `VERSION`/`BUILD_INFO`;
`BuildVersionText.Of(assembly)` (`NetFirewall.Models/System`) is the one place
that turns it into display text (Web *System info*, daemon `/health`). The build
fails if an env template lost its placeholder or a real master key slipped in.

**CI**: `.github/workflows/ci.yml` (build + tests on every push/PR) and
`release.yml` (tag `v*` → tests + bundle + GitHub Release with `.sha256`; push to
`master` → bundle as a 14-day artifact). Both exclude the one known-failing test
via `KNOWN_FAILING` — remove it there once fixed.

**On the host** (`setup.sh`, as root, from the extracted bundle):

- Layout: `<PREFIX>/releases/<version>/`, `<PREFIX>/current` → active release
  (what the units' `WorkingDirectory`/`ExecStart` point at), `<PREFIX>/.previous`.
  Default `PREFIX=/opt/tekium`. Config in `/etc/netfirewall/` (`daemon.env` 0600,
  `web.env` 0640 root:netfirewall, `dhcp.env`, `setup.conf`), state
  `/var/lib/netfirewall/`, logs `/var/log/netfirewall/` (+ `setup-*.log` per run),
  pre-upgrade dumps `/var/backups/netfirewall/`. `/usr/local/bin/netfirewall-{tui,doctor,migrate}`
  link through `current`.
- Upgrade order is fixed: **pg_dump → stage release → migrate with the NEW
  runner → env/units → flip `current` → restart daemon → web (→ dhcp) →
  health-check** (unit active, Web answers on :5000, daemon `/health` reports the
  bundle version). Daemon/Web not healthy ⇒ **automatic rollback** of the symlink.
  Migration failure stops *before* the switch. Never reorder this — the
  42703/42P01 incidents were binaries ahead of the schema.
- **Env files are never rewritten wholesale**: a missing file is rendered from its
  template; an existing one keeps every line and only gets template keys it lacks
  appended (connection string rewritten only with `--db-*`). DB password is read
  back from the env files on upgrade.
- **Master key** resolve-once-write-both: reuse whichever file has it, copy to the
  other, never rotate; both present and different ⇒ stop. Full reference
  **`docs/master-key.md`**. Daemon and Web MUST hold the identical key (both
  decrypt `user_totp_secrets`; drift silently rejects every TOTP code). With
  `Daemon:UseForTotp=true` (prod default) the Web proxies crypto to the daemon
  (`POST /v1/crypto/{encrypt,decrypt}`, `DaemonTotpSecretCipher`); the daemon also
  needs the key for the web terminal's TOTP gate (`/v1/terminal/open`). `false`
  (dev without daemon) keeps the key in the Web's `NETFIREWALL_MASTER_KEY`. If
  `UseForTotp=true` and the daemon is down, TOTP enrollment/verification fail
  loudly.
- `auto` defaults preserve what is installed: DHCP unit (UDP/67, opt-in with
  `--with-dhcp`) is never removed unless `--without-dhcp`; boot-apply
  (`netfirewall-bootstrap.service`, `PartOf=` the daemon → a daemon restart
  re-applies DB state) is on for fresh installs only; nginx is written only on a
  fresh install or with `--configure-nginx`/`--tls-cert`, and reverted if
  `nginx -t` fails. Local DB (`127.0.0.1`/`localhost`/`::1`) is provisioned (role +
  DB); remote is only connected to.
- setup.sh never touches the live nftables ruleset, routes, WireGuard or network
  config, and only removes NetFirewall's own pieces under the prefix (it may be
  shared, e.g. `/opt/tekium`).
- Daemon's `Daemon__AcceptedPeerUids` = Web UID **and** `0` (so
  `netfirewall-tui` as root reaches the socket). The legacy single
  `Daemon__ExpectedPeerUid` is still honored — `PeerCredentialMiddleware` accepts
  a peer matching either gate.
- Doctor finds the release from its own location (`<release>/doctor/` → parent);
  its `ReleaseCheck` reads `VERSION` and warns on a non-bundle layout.

**Hardening highlights** (full list in the unit files):
- Daemon runs as `root` but `CapabilityBoundingSet=CAP_NET_ADMIN
  CAP_DAC_OVERRIDE CAP_NET_RAW` — no `CAP_SYS_ADMIN`, no `CAP_SYS_MODULE`,
  no ptrace, no audit, etc. `ProtectSystem=strict` + tight `ReadWritePaths`.
- Web runs as `netfirewall-web` with **zero capabilities**, only writable
  path is `/var/lib/netfirewall/web`. Member of `netfirewall` group so it
  can connect to the daemon's Unix socket (mode 0660 root:netfirewall;
  `/run/netfirewall` comes from tmpfiles.d because `RuntimeDirectory=` can't set
  the group).
- Both: `NoNewPrivileges`, `PrivateTmp`, `PrivateDevices`, `ProtectHome`,
  `ProtectKernelTunables/Modules/Logs/ControlGroups/Clock/Hostname`,
  `LockPersonality`, `RestrictNamespaces`, `RestrictAddressFamilies`,
  curated `SystemCallFilter` (denies `@mount @swap @reboot @raw-io
  @cpu-emulation @privileged`).
- **`MemoryDenyWriteExecute` is intentionally OFF** — would crash the .NET
  JIT. Switch to `dotnet publish --publish-ready-to-run` or NativeAOT to
  enable it; documented as future work.

The `.deb` + Debian 13 live-build ISO appliance and `deploy/install.sh`
(compile-on-server) were **removed** in favour of the bundle: upgrading a
running appliance was the hard part, and the bundle gives versioning + rollback.

## Database migrations

Schema is managed by **`NetFirewall.Migrations`** — a tiny console runner that
tracks applied files in a `__migrations` table with SHA-256 drift detection.
Migration files live in `NetFirewall.Services/sql/migrations/` named
`NNNNN_description.sql` (5-digit prefix, applied in filename order).

```bash
bin/db.sh status      # list applied / pending / drifted
bin/db.sh up          # apply all pending (each in its own transaction)
bin/db.sh reset       # DROP SCHEMA public CASCADE then up — DEV ONLY, asks for "reset" confirmation
bin/db.sh reset --yes # skip the prompt
bin/db.sh seed        # apply NetFirewall.Services/sql/seeds/demo_interfaces.sql via psql (idempotent ON CONFLICT)
```

Connection string priority (handled inside the CLI):

1. `--connection "Host=..."` flag.
2. `NETFIREWALL_CONN` env var.
3. `ConnectionStrings:DefaultConnection` from `NetFirewall.Web/appsettings.json`.

**Forward-only**, no down-migrations on purpose. To revert a schema change,
write a NEW migration that undoes it. **Never edit a migration that has
already been applied** — the runner detects checksum drift and refuses to
proceed until you write a new file instead.

`NetFirewall.Services/sql/Schema.sql.reference` is the previous all-in-one
dump kept for human reference only. Do NOT apply it directly; use the runner.

The DHCP Server binds UDP/67 and requires root (or `CAP_NET_BIND_SERVICE` + `CAP_NET_RAW`) when run outside the Aspire dev host. WAN Monitor mutates routing tables and similarly requires root in production.

Note: `NetFirewall.WanMonitor` is **not** registered in `NetFirewall.AppHost/Program.cs` — it's a standalone systemd worker. Only `ApiService`, `Web`, and `DhcpServer` come up under Aspire.

## Architecture

### Service projects

- **NetFirewall.Migrations** — standalone console (`netfirewall-migrate`) that applies / tracks / drift-checks the SQL files in `NetFirewall.Services/sql/migrations/`. NOT registered with Aspire — invoked via `bin/db.sh` or `dotnet run --project NetFirewall.Migrations`.
- **NetFirewall.Doctor** — Spectre.Console requirements validator (`netfirewall-doctor` binary). Cross-platform (NO `[assembly: SupportedOSPlatform]`); Linux-only checks Skip off Linux. Validates env vars, **master-key sync between daemon.env and web.env**, paths, **installed release (`VERSION`)**, systemd units, daemon socket, **DHCP server (deployment, config, configured-interface-exists, UDP/67 listener, its own DB connection)**, and **PostgreSQL (reachable, ≥ 14, `__migrations` + core tables present, pending/drifted migrations)**. DHCP is treated as **optional** (unit installed only with `setup.sh --with-dhcp`) so its absence Warns, not Fails. Each check is an `ICheck` returning `CheckResult` (Pass/Warn/Fail/Skip + remedy); fail-soft (never throws). `--service web|daemon|dhcp|all` filters; `--json` + exit code for CI; every release bundle ships it and `setup.sh` runs it as the final verification step. See `docs/doctor.md`. Pure check logic tested in `NetFirewall.Tests/Doctor/`.
- **NetFirewall.AppHost** — Aspire orchestrator (ApiService + Web + DhcpServer).
- **NetFirewall.Tui** — Console UI built on Spectre.Console (`netfirewall-tui` binary). Talks to the same daemon Unix socket the Web does, via the lifted `IDaemonClient` in `NetFirewall.Services/Daemon/`. Auth: single-step login flow (username + password + TOTP/recovery in one screen) via `POST /v1/auth/login` on the daemon, token stored in-memory by `TuiSessionTokenProvider`. **TUI sessions are born elevated** (login already proved TOTP + operator is at console), so destructive endpoints don't re-prompt. Peer-cred middleware on the daemon (`SO_PEERCRED` Linux / `LOCAL_PEERCRED` macOS) gates the socket connection itself. Phases 0-3 shipped: skeleton + daemon ping + login/logout + **NetworkInterfacesScreen** (list, edit IP/mask/gateway/MAC/MTU, add new from physically-detected NICs, apply via daemon) + **RecoveryScreen** (break-glass: reset password, disable TOTP, clear lockout — root-peer-only via `[DaemonRequireRootPeerAttribute]`, no session needed; reachable when a user is locked out of the Web).
- **NetFirewall.WanMonitor** — Background worker for dual-WAN monitoring/failover. Pings configured IPs through each interface (see `WanMonitorService`) and runs the bash commands listed in `appsettings.json` → `BashCommands.ExtraPrimaryCommands` / `ExtraSecondaryCommands` on state changes. Runs under systemd via `UseSystemd()`.
- **NetFirewall.DhcpServer** — RFC 2131 server with PXE boot support. Standalone host (not ASP.NET) using `Host.CreateDefaultBuilder` + `UseSystemd`. See "DHCP Server internals" below.
- **NetFirewall.Web** — ASP.NET Core MVC (`AddControllersWithViews`) using **Tailwind CSS 4** (compiled from `Styles/site.css`), **HTMX** and **Alpine.js** (vendored under `wwwroot/lib/{htmx,alpinejs}/`). Logging uses **Serilog** read from `appsettings.json` (`UseSerilog` + `UseSerilogRequestLogging`). Bootstrap and jQuery were removed; do not reintroduce them. The MSBuild target `BuildTailwindCss` invokes the **standalone `tailwindcss` CLI** (must be on `PATH`) during every `dotnet build`, producing `wwwroot/css/site.css` (gitignored). Manual rebuild / watch: `tailwindcss -i Styles/site.css -o wwwroot/css/site.css --minify` (add `--watch` for live rebuild).
- **NetFirewall.ApiService** — Minimal APIs + OpenAPI surface (intended consumer for the Web UI).

### Shared libraries

- **NetFirewall.Models** — POCOs grouped by domain:
  - `Dhcp/`: DhcpConfig, DhcpRequest, DhcpResponse (note misspelled file `DhcpReponse.cs`), DhcpLease, DhcpMacReservation, DhcpOption(+Code, +Extensions), DhcpMessageType, DhcpSubnet, DhcpPool, DhcpClass, DhcpStaticRoute, DdnsConfig, FailoverPeer, FailoverState
  - `Firewall/`: Fw{Interface,PortForward,FilterRule,NatRule,MangleRule,TrafficMark,QosConfig,QosClass,StaticRoute,AuditLog}
  - `WanMonitor/`: NetworkInterfaceConfig, BashCommandsConfig
  - `Setup/`: SetupWizardState
  - `Wol/`: WolDevice, WolWakeRequest/Result, MagicPacket, MacAddressText (pure MAC parser shared by Web + daemon)
  - `System/`: InterfaceSuggestion, LinuxDistroInfo, NetworkApplyResult
  - `ServiceResponse.cs` — common result envelope
- **NetFirewall.Services** — business logic + data access (Npgsql + RepoDb ORM, `UsePostgreSql()` global config). Subsystems:
  - `Dhcp/`: DhcpServerService, DhcpLeasesService, DhcpSubnetService, DhcpAdminService, DdnsService, FailoverService, **LeaseCache**
  - `Firewall/`: FirewallService, NftApplyService (writes/loads nftables config)
  - `Network/`: LinuxDistroService, DebianInterfacesConfigService, NetplanConfigService (distro-aware interface config writers)
  - `Monitoring/`: SystemMonitorService, MetricsCollectorService, MetricsQueryService
  - `Diagnostics/`: daemon-executed, read-only tools behind `IDiagnosticRunner` (gate slot → `diag_runs` row → time budget): PingProbeService (fwmark/iface), RouteOracleService (`ip -j route get|rule|route`), ConntrackLookupService, DropLogService (`journalctl -k`; `dmesg` is blocked by `ProtectKernelLogs`), InterfaceHealthService, SysctlSanityService, WgLiveReader, and `Doctors/` — four checklists on one engine (`IDoctorCheck<TContext>` + `DoctorRunner`: bounded fan-out, per-check deadline, overrun ⇒ Skip): `Vpn/` (VPN doctor + data-plane probe + issued-config compare), `Doctors/Wan` (uplinks, failover config/verdict, per-WAN marks, default-route owner, ping by mark), `Doctors/Dhcp` (unit, UDP/67, scopes vs their interface, pool pressure, lease activity), `Doctors/Dns` (resolver unit, listeners, raw-UDP query locally and per LAN address, upstreams). Invasive tools (Admin + TOTP, one at a time via `IDiagnosticJobRegistry`): `Trace/` **flow inspector** — owns the table `ip netfw_diag` at the raw hook and deletes it in a `finally` plus a startup sweep, never edits the operator's chains — `Capture/` bounded tcpdump to `/var/lib/netfirewall/daemon/captures` (needs `AF_PACKET` in the daemon unit), and `SpeedTest/` **WAN speed test** — parallel HTTP/1.1 downloads pinned to one WAN by `SO_MARK` = its `probe_fwmark` (never by interface), optional kept payload under `/var/lib/netfirewall/daemon/speedtests` deleted after 24 h by `SpeedTestFileSweeperService`. Tools MUST spawn via the ArgumentList overload of `IProcessRunner` (enforced by `NoInterpolatedProcessArgsTest`) and validate through `IDiagnosticInputValidator` on both sides. See `docs/diagnostics.md`.
  - `Wol/`: Wake-on-LAN — `WakeOnLanService` + `UdpWolPacketSender` run in the **daemon** (`POST /v1/wol/wake`; socket bound to the LAN link with `SO_BINDTODEVICE`, limited broadcast ×3; WAN/VPN/lo/down links refused; link picked from the request or from the subnet holding an IP hint). `WolDeviceService` is the Web-side CRUD over `wol_devices` (migration 00042, joined to DHCP by MAC, in global search); `WolDeviceWakeService` wakes one / the ticked / all saved devices (4 in parallel, explicit `scope` so a lost selection is refused, never widened). UI: Network → Wake-on-LAN, plus a Wake button on DHCP reservation and lease rows (shared `_WakeButton`). See `docs/wake-on-lan.md`.
  - `Setup/`: SetupWizardService, **RuleTemplateService** (wizard "starting rule set" generator: base archetype Gateway/Router/Bastion + capability toggles → network objects + tagged fw_* rows, idempotent, DB-only; rules reference NetworkObjects by name, never raw CIDRs)
- **NetFirewall.ServiceDefaults** — Aspire-shared OpenTelemetry, service discovery, resilience pipelines.
- **NetFirewall.Tests** — xUnit + Moq + `Aspire.Hosting.Testing`. Currently covers `Dhcp/DhcpLeasesServiceTests` and `DhcpServerServiceTests`.

### Database

PostgreSQL database `net_firewall`. Connection string is in each service's `appsettings.json` under `ConnectionStrings:DefaultConnection`. Schema is in `NetFirewall.Services/sql/Schema.sql` and seed data in `SeedData.sql`. The schema *drops and recreates* the DHCP tables on apply — do not run it against an environment with live leases.

Table groupings (current):
- **DHCP core**: `dhcp_config`, `dhcp_subnets`, `dhcp_pools`, `dhcp_exclusions`, `dhcp_leases`, `dhcp_mac_reservations`, `dhcp_classes`, `dhcp_pool_classes`, `dhcp_custom_options`, `dhcp_relay_agents`
- **DHCP failover (RFC 3074-style peer state)**: `dhcp_failover_peers`, `dhcp_failover_state`, `dhcp_failover_bindings`
- **DHCP DDNS / events**: `dhcp_ddns_config`, `dhcp_ddns_log`, `dhcp_events`
- **Firewall**: `fw_interfaces`, `fw_port_forwards`, `fw_filter_rules`, `fw_nat_rules`, `fw_mangle_rules`, `fw_traffic_marks`, `fw_qos_config`, `fw_qos_classes`, `fw_static_routes`, `fw_audit_log`
- **Setup**: `setup_wizard_state`

## DHCP Server internals

Read `docs/PerformanceAnalysis.md` before changing the hot path — it documents the per-stage latency budget and the explicit no-allocation rules (Span/stackalloc/ArrayPool) for packet parsing and serialization. Validate empirically with `dotnet run --project NetFirewall.Benchmarks -c Release` (see `NetFirewall.Benchmarks/README.md` — `Allocated: -` is the regression gate).

- **Packet pipeline**: `DhcpWorker` uses a bounded `System.Threading.Channels.Channel<DhcpPacketContext>` (capacity 1024, `DropOldest` on overflow), not TPL Dataflow. Producer is the UDP receive loop; consumer(s) parse, dispatch, and reply. Backpressure surfaces via `PendingPacketCount` (also in the periodic stats log) — sustained values near capacity mean inbound packets are being dropped silently and clients are timing out.
- **Lease cache**: `LeaseCache` is a singleton, warmed on startup before `DhcpWorker` starts (`await leaseCache.WarmupAsync()` in `Program.cs`). Treat it as the source of truth for hot reads; writes go through it (write-through to PostgreSQL).
- **Subnet service**: `IDhcpSubnetService` is a singleton specifically to keep the subnet/pool cache alive across scoped requests. Don't switch it to scoped.
- **Failover**: `IFailoverService` is a singleton; `await failoverService.StartAsync()` runs in `Program.cs` *before* `host.RunAsync()` — it must be reachable on the peer for failover state to converge.
- **DI lifetimes** (in `NetFirewall.DhcpServer/Program.cs`): scoped services are `DhcpServerService`, `DdnsService`, `DhcpLeasesService`. Singletons are `NpgsqlDataSource`, `LeaseCache`, `IDhcpSubnetService`, `IFailoverService`, plus the `DhcpWorker` hosted service.
- **Concurrency safety**: lease management uses `NpgsqlDataSource` pooling, parameterized queries, and database transactions to prevent races. New write paths must follow the same pattern.

## Bash / nftables integration

`/Bash/` contains the production scripts the firewall is being modeled after:
- `firewall.sh` — main script the WAN Monitor's `ExtraPrimaryCommands` invokes
- `nftables.conf`, `nftables-basic-no-qos.conf` — nftables rulesets
- `rt_table.txt` — `/etc/iproute2/rt_tables` reference for policy routing

`NetFirewall.Services/Firewall/NftApplyService` is the C# side that should ultimately replace direct script execution.

## Logging & configuration

- Serilog (Console + rolling File) configured per-service in `appsettings.json`. DHCP logs go to `logs/dhcp_server-.log`; default level is Debug.
- Each service (DhcpServer, WanMonitor, ApiService, Web) has independent `appsettings.json` / `appsettings.Development.json`. There's no shared config file — keep connection strings and interface names in sync manually.
