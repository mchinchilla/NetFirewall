# NetFirewall

> Firewall personal para uso doméstico y SOHO, hecho desde cero con **C# / .NET 10** y **PostgreSQL**.
> Personal home/SOHO firewall, built from scratch with **C# / .NET 10** and **PostgreSQL**.

He usado durante años pfSense, OPNsense, IPCop, Zentyal, ClearOS, VyOS, IPFire, Endian — cada uno con sus pros y contras. NetFirewall es el intento de tener exactamente lo que quiero, en un stack que conozco a fondo, sin dependencias de plataformas históricas (PHP / FreeBSD) y con una WebUI moderna.

I've used pfSense, OPNsense, IPCop, Zentyal, ClearOS, VyOS, IPFire, Endian for years — each with its pros and cons. NetFirewall is an attempt to get exactly what I want, on a stack I know deeply, without legacy platform dependencies and with a modern WebUI.

> **Estado / Status:** alpha. Apto para experimentar y co-desarrollar; **no** apto aún para reemplazar tu firewall de producción.

---

## Tabla de contenidos

- [Estado por subsistema](#estado-por-subsistema)
- [Stack técnico](#stack-técnico)
- [Reglas del proyecto (no negociables)](#reglas-del-proyecto-no-negociables)
- [Arquitectura](#arquitectura)
- [Base de datos y migraciones](#base-de-datos-y-migraciones)
- [Build y desarrollo](#build-y-desarrollo)
- [Tests y cobertura](#tests-y-cobertura)
- [Despliegue en producción](#despliegue-en-producción)
- [DHCP — notas RFC 2131](#dhcp--notas-rfc-2131)
- [Contribuir](#contribuir)

---

## Estado por subsistema

| Subsistema | Estado | Notas |
|---|---|---|
| **WAN Monitor** | Producción | Failover dual-WAN funcional, corre en mi casa hace meses bajo systemd. |
| **DHCP Server** | Beta | Pipeline RFC 2131 + opciones + clases + reservaciones + DDNS + failover básico (RFC 3074-style). Hot-path zero-allocation (Span/stackalloc/ArrayPool). |
| **Firewall (nftables)** | Beta | CRUD de filter rules, NAT, port forwards, mangle/marks, QoS (HTB), static routes, audit log. Apply real con backup/rollback. |
| **Schedules** | Beta | Reglas con ventanas horarias y timezone; daemon watcher re-aplica al cambiar estado. |
| **VPN (WireGuard)** | Alpha | Peers + config render + apply. |
| **Network Objects / Services** | Beta | Aliases reusables (host/CIDR/range/FQDN/grupo) y catálogo de ~70 servicios well-known. |
| **Auth (sesión + TOTP)** | Beta | Argon2id + sesiones server-side + MFA TOTP + códigos de recuperación + bootstrap token de primer arranque. |
| **Setup wizard** | Beta | 5 pasos guiados, persistencia por paso, re-run. |
| **Búsqueda full-text** | Beta | tsvector + GIN, sync por triggers, autocomplete debounced en el header. |
| **Monitoreo** | Alpha | Métricas de sistema + dashboards live (HTMX polling). |
| **WebUI** | Beta | ASP.NET Core MVC + Tailwind 4 + HTMX + Alpine, sin npm. Tema con tokens semánticos. |

---

## Stack técnico

- **Backend:** C# / .NET 10, ASP.NET Core MVC + Minimal APIs, .NET Aspire (orquestación dev), Serilog.
- **Datos:** PostgreSQL 14+, Npgsql, RepoDb (micro-ORM), tsvector + GIN para búsqueda.
- **Frontend:** Tailwind CSS 4 (binario standalone, **sin Node**), HTMX, Alpine.js — todo vendoreado bajo `wwwroot/lib/`.
- **Sistema:** nftables, iproute2, tc (HTB), Linux raw sockets para DHCP, WireGuard CLI.
- **Tests:** xUnit + Moq + `Aspire.Hosting.Testing`.
- **Despliegue:** systemd (dos units: `netfirewall-daemon` con caps mínimas, `netfirewall-web` sin caps), nginx con TLS, instalador idempotente.

---

## Reglas del proyecto (no negociables)

Reglas duras del repo, documentadas en [`CLAUDE.md`](./CLAUDE.md). Resumen:

1. **Nada de npm / Node.** Tailwind se compila con el binario standalone, dependencias JS vendoreadas.
2. **Async/await en todo I/O** (server y browser). Cero `.Result`, `.Wait()`, `.then()` chains.
3. **Un solo CSS y un solo JS:** `Styles/site.css` → `wwwroot/css/site.css`, y `wwwroot/js/site.js`. Sin `<style>` inline ni scoped CSS.
4. **Validación en ambos lados** (cliente con Tailwind + HTML5 + Alpine; servidor con DataAnnotations / FluentValidation).
5. **Contratos tipados** con `ServiceResponse<T>` y genéricos.
6. **Feedback visible siempre** — toast, banner o inline error tras cada operación, éxito y error.
7. **Decomponer en partials/componentes** — `_Layout.cshtml` solo compone, no contiene markup de negocio.
8. **Cada proceso es un servicio DI-registrado** detrás de una interfaz. Cero estáticos "manager"/"helper" con lógica.
9. **Estilos vía tokens semánticos** del theme (`bg-surface`, `text-accent`, `var(--feedback-*)`...). Cero hex literales ni `bg-red-500`.
10. **Sin SQL ni acceso a datos en controllers.** Controllers componen; services hacen.

---

## Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                  NetFirewall.AppHost (Aspire)                   │
│   orquesta dev: ApiService + Web + DhcpServer                   │
└─────────────────────────────────────────────────────────────────┘
        │                  │                  │
        ▼                  ▼                  ▼
┌──────────────┐   ┌──────────────┐   ┌──────────────────┐
│ ApiService   │   │ Web (MVC)    │   │ DhcpServer       │
│ Minimal APIs │   │ HTMX+Alpine  │   │ UDP/67, RFC 2131 │
│ + OpenAPI    │   │ + Tailwind   │   │ Channel pipeline │
└──────────────┘   └──────────────┘   └──────────────────┘
        │                  │                  │
        └──────────────────┴──────────────────┘
                           │
                           ▼
              ┌──────────────────────────┐
              │ NetFirewall.Services     │  ← lógica de negocio + acceso a datos
              │ (Auth, Dhcp, Firewall,   │     (Npgsql + RepoDb)
              │  Network, Vpn, Search,   │
              │  Monitoring, Setup, ...) │
              └──────────────────────────┘
                           │
                           ▼
                   ┌──────────────┐
                   │ PostgreSQL   │
                   └──────────────┘

Aparte (no bajo Aspire):
  • NetFirewall.WanMonitor  → systemd worker, dual-WAN failover
  • NetFirewall.Migrations  → console runner, schema forward-only
```

### Proyectos

| Proyecto | Rol |
|---|---|
| `NetFirewall.AppHost` | Orquestador Aspire (dev). |
| `NetFirewall.Web` | WebUI MVC. Tailwind, HTMX, Alpine. Sin npm. |
| `NetFirewall.ApiService` | Minimal APIs + OpenAPI (consumido por la UI). |
| `NetFirewall.DhcpServer` | Servidor DHCP standalone (Host genérico + systemd). |
| `NetFirewall.WanMonitor` | Background worker de failover dual-WAN. |
| `NetFirewall.Services` | Lógica de negocio + acceso a datos (Npgsql + RepoDb). |
| `NetFirewall.Models` | POCOs/DTOs por dominio + `ServiceResponse<T>`. |
| `NetFirewall.Migrations` | Runner forward-only con SHA-256 drift detection. |
| `NetFirewall.ServiceDefaults` | Aspire-shared OpenTelemetry, service discovery, resilience. |
| `NetFirewall.Tests` | xUnit + Moq + `Aspire.Hosting.Testing`. |

---

## Base de datos y migraciones

Schema gestionado por **`NetFirewall.Migrations`** — runner que aplica archivos de `NetFirewall.Services/sql/migrations/` (formato `NNNNN_descripcion.sql`) y los registra en `__migrations` con checksum SHA-256 para detectar drift.

```bash
bin/db.sh status      # listar aplicadas / pendientes / con drift
bin/db.sh up          # aplicar pendientes (cada una en su propia transacción)
bin/db.sh reset       # DROP SCHEMA + up — DEV ONLY, pide confirmación
bin/db.sh seed        # seed idempotente (demo_interfaces.sql)
```

Resolución del connection string:

1. Flag `--connection "Host=..."`.
2. Variable `NETFIREWALL_CONN`.
3. `ConnectionStrings:DefaultConnection` de `NetFirewall.Web/appsettings.json`.

> **Forward-only por diseño.** Para revertir un cambio, escribe una migración nueva. Editar una ya aplicada hace que el runner detecte drift y rechace continuar.

---

## Build y desarrollo

### Prerrequisitos

- .NET 10 SDK
- PostgreSQL 14+
- Binario standalone de **`tailwindcss`** en `PATH` (descarga desde https://github.com/tailwindlabs/tailwindcss/releases — pin a v4.x)
- Linux para correr el daemon DHCP / firewall en serio (UDP/67, nftables, raw sockets). En macOS/Windows la WebUI funciona bien para desarrollo pero las apply-ops son no-op.

### Build & test

```bash
dotnet build
dotnet build -c Release
dotnet test
dotnet test --filter "FullyQualifiedName~DhcpLeasesServiceTests"
```

El target MSBuild `BuildTailwindCss` invoca el CLI standalone en cada `dotnet build` y produce `wwwroot/css/site.css` (gitignored). Para watch:

```bash
tailwindcss -i NetFirewall.Web/Styles/site.css -o NetFirewall.Web/wwwroot/css/site.css --watch
```

### Correr el entorno orquestado (Aspire)

```bash
dotnet run --project NetFirewall.AppHost
```

Aspire levanta el dashboard, ApiService, Web y DhcpServer. El primer login lo guía el setup wizard (bootstrap token impreso en consola).

> **Nota:** `NetFirewall.WanMonitor` **no** está registrado en AppHost — corre como systemd worker independiente.

---

## Tests y cobertura

Estado actual: **2 archivos de test, ~11 métodos, ~99% del código de negocio sin cobertura.** El proyecto necesita una inversión seria aquí.

### Lo que ya está cubierto

```
NetFirewall.Tests/Dhcp/
├── DhcpLeasesServiceTests.cs     ← lifecycle de leases
└── DhcpServerServiceTests.cs     ← discover/offer/request/ack
```

### Gaps prioritarios (resumen)

| Prioridad | Áreas | Por qué importa |
|---|---|---|
| **P0 — crítico** | `DhcpSubnetService` (asignación IP, races), `LeaseCache`, `FailoverService`, `FirewallService` + `NftApplyService` (apply real con rollback), `TcApplyService`, `Argon2PasswordHasher`, `AesGcmTotpSecretCipher`, `TotpService`, `SessionService`, `SessionCookieAuthHandler`, `BootstrapTokenIssuer`, `DhcpWorker` (hot-path packet parsing), `LinuxRawSocket`, `MigrationRunner` | Seguridad, integridad de leases, integridad de schema, race conditions con consecuencias visibles para el usuario. |
| **P1 — importante** | `DdnsService`, `DhcpAdminService`, `DhcpCacheNotifier`, `ScheduleService`, `ScheduleWatcherService`, `LinuxDistroService`, `DebianInterfacesConfigService`, `NetplanConfigService`, `NetworkManagerConfigService`, `NetworkObjectResolver` (recursión + ciclos), `NetworkServiceResolver`, `StaticRouteApplicator`, `SystemMonitorService`, `MetricsCollectorService`, `MetricsQueryService`, `SearchService`, `SetupWizardService`, `AppSettingsService`, `ProcessRunner`, `WireGuardConfigService` + `WireGuardApplyService`, `UserService`, `UserTotpService`, `RecoveryCodeService`, `AuthAuditService`, `DaemonClient` + decorators del Web | Lógica de negocio, parsing distro-aware, máquinas de estado, generación de configs. |
| **P2 — nice to have** | Controllers (la mayoría son thin orchestrators, pero `FwApplyController`, `SetupWizardController`, `AuthController`, `DhcpSubnetsController` tienen lógica que vale la pena), `AuditPrunerService`, helpers de view, utilidades de modelo (`User.EffectiveDisplayName`, `Initials`, etc.), `RequireElevatedAttribute`, `ValidationToServiceResponseFilter`. | Comportamiento UI, formateo, validación de inputs. |

### Inventario aproximado de unidades testeable

```
NetFirewall.Services       →  ~57 servicios (Auth: 9, Dhcp: 8, Firewall: 6,
                              Network: 10, Monitoring: 4, Setup: 1,
                              Search: 1, Settings: 1, Vpn: 3, Processes: 1)
NetFirewall.Web            →  34 controllers + 7 auth helpers + 5 daemon
                              clients + 2 filters + 1 helper extension
NetFirewall.DhcpServer     →  DhcpWorker + LinuxRawSocket
NetFirewall.WanMonitor     →  WanMonitorService
NetFirewall.Migrations     →  MigrationRunner
NetFirewall.Models         →  ~varios métodos con lógica (display name,
                              initials, validación de roles/tipos)
─────────────────────────────────────────────────────────────────
Total estimado             →  ~120-170 unidades testeables
Cubiertas                  →  2 (DhcpLeasesService, DhcpServerService)
Gap                        →  >98 %
```

### Estrategia sugerida (fases)

1. **Fase 1 — P0 in-memory** (rápido, sin infra): `Argon2PasswordHasher`, `AesGcmTotpSecretCipher`, `TotpService`, `SessionService` (con `INpgsqlDataSource` mockeado), `RecoveryCodeGenerator`, `NetworkObjectResolver` (recursión), `NetworkServiceResolver`. Win rápido, gran cobertura por LOC.
2. **Fase 2 — P0 con Postgres real** (testcontainers): `DhcpSubnetService` (asignación IP + exclusiones + cache coherence), `LeaseCache`, `MigrationRunner` (drift detection + rollback en transacción).
3. **Fase 3 — Apply-pipelines** (mock de `IProcessRunner`): `FirewallService` + `NftApplyService` (generación + backup/rollback), `TcApplyService`, `WireGuardApplyService`, `StaticRouteApplicator`, `DebianInterfacesConfigService` / `NetplanConfigService` (file I/O contra `tmpfs`).
4. **Fase 4 — Hot-path DHCP**: `DhcpWorker` (parser/serializer zero-alloc — propiedad: `Parse(Serialize(x)) == x` para todos los message types), tests de presión sobre el `Channel` bounded.
5. **Fase 5 — Integración WebUI** (`Aspire.Hosting.Testing`): flow MFA completo, setup wizard end-to-end, apply de regla con rollback observable en UI.

> Si arrancas por aquí: **`Argon2PasswordHasher` + `AesGcmTotpSecretCipher` + `TotpService`** son los tres mejores wins iniciales — pura CPU, sin infra, alto valor de seguridad, y guían el shape de los demás.

---

## Despliegue en producción

Producción son **dos units systemd** (`netfirewall-daemon` con `CAP_NET_ADMIN`/`CAP_DAC_OVERRIDE`/`CAP_NET_RAW` y nada más; `netfirewall-web` con cero capabilities) detrás de **nginx con TLS**. Toda la plomería vive bajo `deploy/`:

```
deploy/
  systemd/                              units endurecidos
  config/{daemon,web}.json.template     appsettings (modo 0640)
  env/{daemon,web}.env.template         secretos — modo 0600/0640
  nginx/netfirewall.conf                proxy reverso TLS
  install.sh                            instalador idempotente
  uninstall.sh                          inverso (--purge limpia datos)
  README.txt                            handbook operacional
```

Instalar en Debian/Ubuntu/Rocky/Alma/openSUSE con .NET 10 SDK + PostgreSQL 14+ + systemd 250+:

```bash
sudo deploy/install.sh
```

Para detalles de hardening (capabilities, `ProtectSystem`, `SystemCallFilter`, manejo de la master key AES-256 para cifrado de secretos TOTP, modelo de privilegios Web ↔ Daemon vía Unix socket): ver [`deploy/README.txt`](./deploy/README.txt) y [`CLAUDE.md`](./CLAUDE.md).

> **Nota sobre el ciclo Web/Daemon:** la master key vive **solo** en el proceso del daemon. El Web nunca la ve — para enrolar/verificar TOTP llama a `POST /v1/crypto/{encrypt,decrypt}` sobre el Unix socket. Un compromiso del Web ya no puede descifrar secretos TOTP almacenados.

---

## DHCP — notas RFC 2131

Resumen rápido del diálogo cliente↔servidor que el `DhcpServer` implementa:

1. **DHCPDISCOVER** — cliente broadcast (Option 53 = 1) con su MAC en Option 61.
2. **DHCPOFFER** — servidor responde (Option 53 = 2) con `yiaddr`, server identifier (Option 54), subnet/router/DNS/lease time.
3. **DHCPREQUEST** — cliente elige una offer (Option 53 = 3) e identifica al server elegido (Option 54).
4. **DHCPACK** — server confirma (Option 53 = 5) con lease time + T1 (renew) + T2 (rebind).
5. **DHCPNAK** — server niega si la IP ya no está disponible (Option 53 = 6).

Mensajes adicionales: **DHCPDECLINE** (cliente detecta IP duplicada), **DHCPRELEASE** (libera el lease), **DHCPINFORM** (cliente con IP estática pide solo opciones).

**Lease management:** los timers T1 y T2 controlan el renew y rebind. T1 → unicast al server original; T2 → broadcast a cualquiera.

**Antes de tocar el hot-path:** lee [`NetFirewall.Services/Dhcp/PerformanceAnalysis.md`](./NetFirewall.Services/Dhcp/PerformanceAnalysis.md). Las reglas zero-allocation (Span/stackalloc/ArrayPool) son obligatorias en el parser y serializer.

---

## Contribuir

Si te interesa colaborar, eres bienvenido. Antes de abrir un PR:

1. Lee [`CLAUDE.md`](./CLAUDE.md) — las 10 reglas no negociables aplican a todo el código.
2. Asegúrate de que `dotnet build` y `dotnet test` pasen verde.
3. Para cambios de schema: nueva migración, **nunca** edites una ya aplicada.
4. Para cambios de UI: usa los tokens semánticos del theme; cero hex literales, cero `<style>` inline.
5. Si tu cambio afecta la pipeline DHCP: corre el bench/profile manualmente y nota el impacto.

Issues, ideas y discusión: usa la pestaña Issues del repo. Para PRs grandes, abre primero un issue describiendo el approach.

---

## Licencia

Por definir. Hasta entonces, considera "todos los derechos reservados" pero siéntete libre de leer, fork-ear para experimentar, y abrir issues / PRs.
