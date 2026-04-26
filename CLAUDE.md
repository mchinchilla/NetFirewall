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

# Publish for Linux deployment
dotnet publish -c Release -r linux-x64 -o /opt/netfirewall/wanmonitor  NetFirewall.WanMonitor
dotnet publish -c Release -r linux-x64 -o /opt/netfirewall/dhcpserver NetFirewall.DhcpServer
```

## Production deployment

Production is two systemd units (`netfirewall-daemon`, `netfirewall-web`)
behind a TLS-terminating reverse proxy. Everything lives under `deploy/`:

```
deploy/
  systemd/                              hardened .service files
  config/{daemon,web}.json.template     prod appsettings (mode 0640)
  env/{daemon,web}.env.template         secrets — mode 0600/0640
  nginx/netfirewall.conf                reverse-proxy example with TLS
  install.sh                            idempotent installer
  uninstall.sh                          reverse install (--purge wipes data)
  README.txt                            operational handbook
```

**Install** on a Debian/Ubuntu/Rocky/Alma/openSUSE host with .NET 10 SDK,
PostgreSQL 14+ and systemd 250+:

```bash
sudo deploy/install.sh
```

The installer creates `netfirewall` group + `netfirewall-web` user (system,
nologin), lays out `/opt/netfirewall/{daemon,web,migrations}`, `/etc/netfirewall/`,
`/var/lib/netfirewall/{web,daemon}/`, `/var/log/netfirewall/` (with `/run/netfirewall/`
provided by systemd `RuntimeDirectory=`), publishes both projects + the migration
runner, generates an AES-256 master key for TOTP encryption, runs migrations,
installs and enables both unit files.

**Hardening highlights** (full list in the unit files):
- Daemon runs as `root` but `CapabilityBoundingSet=CAP_NET_ADMIN
  CAP_DAC_OVERRIDE CAP_NET_RAW` — no `CAP_SYS_ADMIN`, no `CAP_SYS_MODULE`,
  no ptrace, no audit, etc. `ProtectSystem=strict` + tight `ReadWritePaths`.
- Web runs as `netfirewall-web` with **zero capabilities**, only writable
  path is `/var/lib/netfirewall/web`. Member of `netfirewall` group so it
  can connect to the daemon's Unix socket (mode 0660 root:netfirewall).
- Both: `NoNewPrivileges`, `PrivateTmp`, `PrivateDevices`, `ProtectHome`,
  `ProtectKernelTunables/Modules/Logs/ControlGroups/Clock/Hostname`,
  `LockPersonality`, `RestrictNamespaces`, `RestrictAddressFamilies`,
  curated `SystemCallFilter` (denies `@mount @swap @reboot @raw-io
  @cpu-emulation @privileged`).
- **`MemoryDenyWriteExecute` is intentionally OFF** — would crash the .NET
  JIT. Switch to `dotnet publish --publish-ready-to-run` or NativeAOT to
  enable it; documented as future work.

**Master key (TOTP secrets cipher)** lives in `/etc/netfirewall/web.env`
mode 0640 root:netfirewall-web. The Web reads it via `EnvironmentFile=`.
Phase 2.3 will move this to the daemon so the Web doesn't hold the key —
meanwhile, a Web-process compromise can decrypt TOTP secrets.

**Upgrading**: re-run `sudo deploy/install.sh`. Idempotent — preserves
master key + connection password, re-publishes binaries, applies pending
migrations, restarts both services.

**Removing**: `sudo deploy/uninstall.sh` (keeps data) or
`sudo deploy/uninstall.sh --purge` (wipes config + state + users; the PG
database is NEVER touched automatically).

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
- **NetFirewall.AppHost** — Aspire orchestrator (ApiService + Web + DhcpServer).
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
  - `System/`: InterfaceSuggestion, LinuxDistroInfo, NetworkApplyResult
  - `ServiceResponse.cs` — common result envelope
- **NetFirewall.Services** — business logic + data access (Npgsql + RepoDb ORM, `UsePostgreSql()` global config). Subsystems:
  - `Dhcp/`: DhcpServerService, DhcpLeasesService, DhcpSubnetService, DhcpAdminService, DdnsService, FailoverService, **LeaseCache**
  - `Firewall/`: FirewallService, NftApplyService (writes/loads nftables config)
  - `Network/`: LinuxDistroService, DebianInterfacesConfigService, NetplanConfigService (distro-aware interface config writers)
  - `Monitoring/`: SystemMonitorService, MetricsCollectorService, MetricsQueryService
  - `Setup/`: SetupWizardService
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

Read `NetFirewall.Services/Dhcp/PerformanceAnalysis.md` before changing the hot path — it documents the per-stage latency budget and the explicit no-allocation rules (Span/stackalloc/ArrayPool) for packet parsing and serialization.

- **Packet pipeline**: `DhcpWorker` uses a bounded `System.Threading.Channels.Channel<DhcpPacketContext>` (capacity 100), not TPL Dataflow. Producer is the UDP receive loop; consumer(s) parse, dispatch, and reply.
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
