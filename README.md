# NetFirewall

> Firewall multi-WAN, DHCP, VPN y router para uso doméstico y SOHO, hecho desde cero con **C# / .NET 10** y **PostgreSQL**.
> Multi-WAN firewall, DHCP, VPN and router for home/SOHO use, built from scratch with **C# / .NET 10** and **PostgreSQL**.

He usado durante años pfSense, OPNsense, IPCop, Zentyal, ClearOS, VyOS, IPFire, Endian — cada uno con sus pros y contras. NetFirewall es el intento de tener exactamente lo que quiero, en un stack que conozco a fondo, sin dependencias de plataformas históricas (PHP / FreeBSD) y con una WebUI moderna.

I've used pfSense, OPNsense, IPCop, Zentyal, ClearOS, VyOS, IPFire, Endian for years — each with its pros and cons. NetFirewall is an attempt to get exactly what I want, on a stack I know deeply, without legacy platform dependencies and with a modern WebUI.

> **Estado / Status:** alpha → beta. Apto para experimentar, co-desarrollar y desplegar en laboratorios; el Web UI y el daemon ya pueden gestionar producción acotada con TOTP step-up para operaciones destructivas.

---

## Visión: NetFirewall OS

El objetivo final del proyecto es una **distribución Linux basada en Debian** (ISO booteable) que se instala en una máquina y queda lista como appliance multi-WAN. Tres planos de control comparten exactamente la misma capa de servicios:

- **Web UI** — ASP.NET Core MVC + Tailwind 4 + HTMX + Alpine. Ejecuta sin privilegios; toda operación destructiva pasa por el daemon vía Unix socket autenticado y exige TOTP step-up.
- **TUI sobre TTY** — Spectre.Console para configuración inicial sin red, recovery, o admin local sobre consola serie. Llama el mismo socket que el Web; cero duplicación de lógica. **Funcional desde v0.4** (login + network + recovery).
- **ISO installer** — Debian-based con preseed unattended, primer boot que suelta el bootstrap token para enrolar el primer admin con TOTP. **En curso (v0.5, Fase 5)** — sources `live-build` bajo `deploy/iso/` que consumen el `.deb` desde `deploy/debian/`.

### Lo que pretende ofrecer "out of the box"

- **Multi-WAN failover** con WAN Monitor: ping-watchdog por interfaz, scripts pre/post-failover, métricas de latencia.
- **DHCP server propio** que vive directo sobre PostgreSQL (sin ISC dhcpd, sin Kea): pools, clases, reservaciones MAC, DDNS, failover RFC 3074-style, PXE boot, opciones por clase.
- **Firewall nftables world-class**: filter rules, NAT, port forwards, mangle/marks, QoS (HTB), static routes, schedules con timezone, audit log, dry-run + apply con rollback automático.
- **VPN WireGuard** integrada: peers, render de config, apply.
- **Configuración de interfaces de red completa**: IP/máscara/gateway, **MAC spoofing** (kernel-level, sobrevive reboots), bridges, VLANs, MTU. Distro-aware: detecta y escribe Netplan / NetworkManager / Debian `interfaces` según corresponda.
- **DNS resolver** (planned), **proxy/captive portal** (planned), **monitoring** con métricas live.
- **Auth con MFA real**: Argon2id + sesiones server-side + TOTP enrollment + códigos de recuperación + step-up para operaciones destructivas.
- **Búsqueda full-text** en toda la config: tsvector + GIN, autocomplete debounced en el header.

---

## Tabla de contenidos

- [Estado por subsistema](#estado-por-subsistema)
- [Stack técnico](#stack-técnico)
- [Modelo de seguridad](#modelo-de-seguridad)
- [Reglas del proyecto (no negociables)](#reglas-del-proyecto-no-negociables)
- [Arquitectura](#arquitectura)
- [Configuración de red e interfaces](#configuración-de-red-e-interfaces)
- [Base de datos y migraciones](#base-de-datos-y-migraciones)
- [Build y desarrollo](#build-y-desarrollo)
- [Tests y cobertura](#tests-y-cobertura)
- [Despliegue en producción](#despliegue-en-producción)
- [DHCP — notas RFC 2131 y performance](#dhcp--notas-rfc-2131-y-performance)
- [Roadmap](#roadmap)
- [Contribuir](#contribuir)

---

## Estado por subsistema

| Subsistema | Estado | Notas |
|---|---|---|
| **WAN Monitor** | Producción | Failover dual-WAN funcional, corre en producción doméstica hace meses bajo systemd. |
| **DHCP Server** | Beta | Pipeline RFC 2131 + opciones + clases + reservaciones + DDNS + failover básico (RFC 3074-style). Hot-path zero-allocation (Span/stackalloc/ArrayPool). LeaseCache singleton warmed at boot. PXE boot soportado. |
| **Firewall (nftables)** | Beta | CRUD de filter rules, NAT, port forwards, mangle/marks, QoS (HTB), static routes, audit log. Apply real con backup/rollback observable en UI. |
| **Schedules** | Beta | Reglas con ventanas horarias y timezone; daemon watcher re-aplica al cambiar estado. |
| **VPN (WireGuard)** | Alpha | Peers + config render + apply. Falta UI completa de QR para móviles. |
| **Network Objects / Services** | Beta | Aliases reusables (host/CIDR/range/FQDN/grupo) y catálogo de ~70 servicios well-known. Resolver con detección de ciclos. |
| **Network interfaces config** | Beta | Distro-aware (Netplan / NetworkManager / Debian interfaces). Escribe `/etc/network/interfaces` o YAML netplan + bring-up vía daemon. **MAC spoofing soportado**. |
| **Auth (sesión + TOTP)** | Beta | Argon2id + sesiones server-side + MFA TOTP + códigos de recuperación + bootstrap token de primer arranque. **Step-up TOTP** obligatorio para operaciones destructivas vía `[RequireElevated]`. |
| **Daemon Web ↔ root** | Beta | Unix socket autenticado (`X-NetFw-Session`), endpoints `/v1/{network,firewall,crypto,...}` con caps mínimas (`CAP_NET_ADMIN`/`CAP_DAC_OVERRIDE`/`CAP_NET_RAW`). |
| **Setup wizard** | Beta | 5 pasos guiados, persistencia por paso, re-run idempotente. |
| **Búsqueda full-text** | Beta | tsvector + GIN, sync por triggers, autocomplete debounced en el header. |
| **Monitoreo** | Alpha | Métricas de sistema + dashboards live (HTMX polling). |
| **WebUI** | Beta | ASP.NET Core MVC + Tailwind 4 + HTMX + Alpine, sin npm. Tema con tokens semánticos (`bg-surface`, `--accent`, `--feedback-*`). |
| **TUI** | Beta | Spectre.Console sobre el mismo daemon socket que el Web. Login single-step (user + pwd + TOTP/recovery), `NetworkInterfacesScreen` (list/edit/apply), `RecoveryScreen` (break-glass: reset password / disable TOTP, root-peer-only). Distribuido por `install.sh` como `/usr/local/bin/netfirewall-tui` con manpage + bash completion. |
| **`.deb` package** | En curso (v0.5) | `deploy/debian/` — debhelper sources que convierten `install.sh` en `apt install netfirewall`. Bakea las cinco unidades publish (daemon/web/tui/migrations/wanmonitor) más unidades systemd, manpage, completion y `postinst` para usuarios + master key + migraciones. |
| **ISO installer** | En curso (v0.5) | `deploy/iso/` — config `live-build` Debian-based con preseed unattended; consume el `.deb` vía `package-lists/`. Primer boot suelta el bootstrap token para enrolar al primer admin con TOTP. |

---

## Stack técnico

- **Backend:** C# / .NET 10, ASP.NET Core MVC + Minimal APIs, .NET Aspire (orquestación dev), Serilog.
- **Datos:** PostgreSQL 14+, Npgsql, RepoDb (micro-ORM), tsvector + GIN para búsqueda.
- **Frontend:** Tailwind CSS 4 (binario standalone, **sin Node**), HTMX, Alpine.js — todo vendoreado bajo `wwwroot/lib/`.
- **Sistema:** nftables, iproute2, tc (HTB), Linux raw sockets para DHCP, WireGuard CLI, Netplan / NetworkManager / `/etc/network/interfaces` autodetect.
- **Crypto:** Argon2id (passwords), AES-GCM (TOTP secret cipher, key vive solo en daemon), TOTP RFC 6238.
- **Tests:** xUnit + Moq + `Aspire.Hosting.Testing` + Testcontainers (Postgres real).
- **Despliegue:** systemd (dos units: `netfirewall-daemon` con caps mínimas, `netfirewall-web` sin caps), nginx con TLS, instalador idempotente.

---

## Modelo de seguridad

NetFirewall toma operaciones destructivas (cambiar reglas firewall, aplicar config de red, mutar usuarios) muy en serio. El modelo:

1. **Web sin privilegios.** El proceso `netfirewall-web` corre como usuario sistema sin capabilities, solo puede escribir en `/var/lib/netfirewall/web`.
2. **Daemon root con caps mínimas.** `netfirewall-daemon` tiene `CAP_NET_ADMIN` + `CAP_DAC_OVERRIDE` + `CAP_NET_RAW` (no `CAP_SYS_ADMIN`, no `CAP_SYS_MODULE`). Sandbox systemd: `ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`, `LockPersonality`, `RestrictNamespaces`, `SystemCallFilter` curado.
3. **Comunicación Web ↔ Daemon** sobre Unix socket (`/run/netfirewall/daemon.sock`, mode 0660 root:netfirewall) con header de sesión (`X-NetFw-Session`). El daemon valida la sesión contra Postgres antes de cualquier op.
4. **Master key para cifrado de TOTP secrets** vive **solo** en el daemon (`/etc/netfirewall/daemon.env`, mode 0600 root:root). El Web nunca la ve — para enrolar/verificar TOTP llama `POST /v1/crypto/{encrypt,decrypt}` sobre el socket. **Compromiso del Web no descifra secretos TOTP almacenados.**
5. **Step-up TOTP obligatorio** para operaciones destructivas (`[RequireElevated]` filter): el usuario debe verificar TOTP en los últimos 15 min. Si la sesión es básica, el filter retorna 401 con `HX-Trigger: showElevationModal` y el front-end muestra el modal de step-up que re-fire el request original tras verificar.
6. **Auth audit log** — toda operación de auth (login, logout, TOTP fail, lock, elevation) se persiste en `auth_audit_log` con IP + UA + detalle estructurado.
7. **`__Host-` cookie** — atributo `Secure`, `Path=/`, sin `Domain`, `SameSite=Lax`, `HttpOnly`. Resistente a sub-domain hijack.
8. **Argon2id** con salt + hash 32 bytes (defaults), `NeedsRehash` rotación automática al login si los parámetros suben.

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
        │                  │ ── unix sock ──► ┌──────────────┐
        │                  │                  │ Daemon (root)│
        │                  │                  │ caps mínimas │
        │                  │                  └──────────────┘
        │                  │                          │
        │                  │                          ▼
        │                  │           nftables / iproute2 /
        │                  │           tc / netplan / wg /
        │                  │           /etc/network/interfaces
        │                  │
        └──────────────────┴──────────────────┐
                           │                  │
                           ▼                  ▼
              ┌──────────────────────────┐  ┌──────────────────┐
              │ NetFirewall.Services     │  │ TUI (Spectre)    │
              │ (Auth, Dhcp, Firewall,   │  │ ── unix sock ──► │
              │  Network, Vpn, Search,   │  │ login + network  │
              │  Monitoring, Setup, ...) │  │ + recovery screen│
              └──────────────────────────┘  └──────────────────┘
                           │
                           ▼
                   ┌──────────────┐
                   │ PostgreSQL   │
                   └──────────────┘

Aparte (no bajo Aspire):
  • NetFirewall.WanMonitor  → systemd worker, dual-WAN failover
  • NetFirewall.Daemon      → systemd unit, root, Unix socket API
  • NetFirewall.Migrations  → console runner, schema forward-only
```

### Proyectos

| Proyecto | Rol |
|---|---|
| `NetFirewall.AppHost` | Orquestador Aspire (dev). |
| `NetFirewall.Web` | WebUI MVC. Tailwind, HTMX, Alpine. Sin npm. Sin caps. |
| `NetFirewall.ApiService` | Minimal APIs + OpenAPI (consumido por la UI). |
| `NetFirewall.DhcpServer` | Servidor DHCP standalone (Host genérico + systemd). |
| `NetFirewall.Daemon` | Daemon root con Unix socket: aplica nftables/red/wireguard/crypto. |
| `NetFirewall.WanMonitor` | Background worker de failover dual-WAN. |
| `NetFirewall.Tui` | Console UI (Spectre.Console). Habla el mismo daemon socket que el Web; recovery + admin local. |
| `NetFirewall.Services` | Lógica de negocio + acceso a datos (Npgsql + RepoDb). |
| `NetFirewall.Models` | POCOs/DTOs por dominio + `ServiceResponse<T>`. |
| `NetFirewall.Migrations` | Runner forward-only con SHA-256 drift detection. |
| `NetFirewall.ServiceDefaults` | Aspire-shared OpenTelemetry, service discovery, resilience. |
| `NetFirewall.Tests` | xUnit + Moq + `Aspire.Hosting.Testing` + Testcontainers. |

---

## Configuración de red e interfaces

NetFirewall puede gestionar **toda la configuración de red de la máquina** desde el Web UI (y eventualmente la TUI). El flujo:

1. **`LinuxDistroService`** detecta la distro y el stack de red activo (`netplan`, `NetworkManager`, o `/etc/network/interfaces`) examinando archivos en `/etc/`, `os-release`, y servicios systemd activos.
2. **`INetworkConfigService`** se resuelve a la implementación correcta:
   - `NetplanConfigService` — escribe YAML en `/etc/netplan/*.yaml`, ejecuta `netplan apply`.
   - `NetworkManagerConfigService` — escribe `*.nmconnection` en `/etc/NetworkManager/system-connections/`, recarga.
   - `DebianInterfacesConfigService` — escribe `/etc/network/interfaces.d/*.cfg`, `ifup/ifdown`.
3. **Endpoint `POST /v1/network/{id}/apply`** en el daemon recibe el ID de la interfaz, lee el modelo de Postgres, invoca el writer correcto, y devuelve `NetworkApplyResult` con stdout/stderr.
4. **Endpoint `POST /v1/network/restart`** — restart del subsistema entero (en caso de cambios masivos).

### Lo que se puede configurar

| Campo | Notas |
|---|---|
| **IP address** | IPv4 estático o DHCP. IPv6 planned. |
| **Subnet mask** | Notación CIDR o decimal. |
| **Gateway** | Per-interface o default. |
| **MAC address** | **Spoofing soportado** — kernel-level via writer de distro (`macaddress:` netplan, `cloned-mac-address=` NM, `hwaddress ether` Debian). Sobrevive reboots. |
| **MTU** | Por interfaz. |
| **VLAN ID** | 802.1Q tagging. |
| **Bridge / bond** | Planned para v0.6. |
| **Type** | WAN / LAN / DMZ / Management — dirige selección de subnet DHCP, reglas firewall, métricas. |

### Por qué pasa todo por el daemon

El Web corre sin capabilities — no puede escribir en `/etc/`, no puede ejecutar `netplan apply`, no puede hacer `ip link set`. Pasar por el daemon (con caps mínimas) significa que un compromiso del Web **no puede reconfigurar la red** sin antes comprometer el daemon o robar una sesión TOTP-elevated.

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
- Linux para correr el daemon DHCP / firewall en serio (UDP/67, nftables, raw sockets, network config). En macOS/Windows la WebUI funciona bien para desarrollo pero las apply-ops son no-op.
- Docker (opcional, para los tests con Testcontainers Postgres).

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

> **Nota:** `NetFirewall.WanMonitor`, `NetFirewall.Daemon` y `NetFirewall.Tui` **no** están registrados en AppHost — el WanMonitor y el daemon corren como systemd workers en producción, la TUI se invoca a demanda en consola. Para desarrollo local del daemon, lanzar manualmente con `dotnet run --project NetFirewall.Daemon` sobre Linux con caps adecuadas (o como root en una VM).

### Correr la TUI

Con el daemon arriba (vía Aspire o systemd), la TUI se invoca:

```bash
# Dev (apunta al socket que use Aspire o tu daemon local):
dotnet run --project NetFirewall.Tui

# Producción (instalado por install.sh):
sudo netfirewall-tui
```

El menú principal muestra estado del daemon y de la sesión, login single-step (user + pwd + TOTP/recovery), `NetworkInterfacesScreen` para list/edit/apply de interfaces, y `RecoveryScreen` (root-peer-only) para break-glass cuando un admin está locked out del Web. La TUI se autentica vía peer-cred (`SO_PEERCRED` en Linux, `LOCAL_PEERCRED` en macOS) — el daemon acepta el UID del Web **y** root.

---

## Tests y cobertura

**Estado actual: ~880 tests pasando, 1 skipped, 0 failing.** El proyecto pasó de tener cobertura mínima a una suite robusta cubriendo seguridad, lógica de negocio, hot-path DHCP, filtros web y la TUI.

### Lo que está cubierto

```
NetFirewall.Tests/
├── Auth/                    → password hashing, TOTP, recovery codes,
│                              session lifecycle, audit log
├── WebAuth/                 → SessionCookieAuthHandler, AuthController flow
│                              (login + TOTP + recovery + lock + step-up),
│                              AccountController (TOTP enrollment regression),
│                              RequireElevatedAttribute (4 outcomes),
│                              ValidationToServiceResponseFilter,
│                              HtmxResultExtensions (HX-Trigger merge),
│                              FwApplyController, SetupWizardController,
│                              DaemonClient (real Unix socket via Kestrel),
│                              DaemonTotpSecretCipher, DaemonStaticRouteApplicator,
│                              DaemonNetworkConfigService, DaemonResolverDecorator,
│                              BashScriptCatalog
├── Dhcp/                    → DhcpServerService (orchestration),
│                              DhcpLeasesService (lifecycle + real Postgres),
│                              DhcpSubnetService (selection chain + alloc),
│                              DhcpAdminService, DdnsService, FailoverService,
│                              LeaseCache, DhcpWorker parser (zero-alloc),
│                              DhcpWorker option parser edge cases (truncated,
│                              Pad/End, length-zero, multi-option),
│                              DhcpWorker ProcessSinglePacketAsync
│                              (counters request- y response-side, send seam)
├── Firewall/                → NftApplyService generation + rollback,
│                              TcApplyService, schedules, audit pruner
├── Network/                 → object resolver (recursion + cycles),
│                              service resolver, distro detection,
│                              netplan/NM/Debian writers
├── Tui/                     → RecoveryScreen label builder (locked/inactive/
│                              no-totp markers), NetworkInterfacesScreen
│                              validation/orchestration, TuiSessionState
│                              transitions, DaemonOptions binding (env var
│                              shape that install.sh writes)
├── Migrations/              → runner, drift detection, transaction rollback
├── Models/                  → User.EffectiveDisplayName, Initials, validation
└── Infra/                   → PostgresFixture (Testcontainers)
```

### Coverage por área (aproximado)

| Área | Cobertura | Notas |
|---|---|---|
| **Crypto / Auth** | Alta | Argon2, AES-GCM, TOTP, recovery codes, sessions, audit. |
| **DHCP hot path** | Alta | Parser + serializer zero-alloc verificados; counters; send seam. |
| **DHCP business logic** | Media-Alta | Subnet/lease/failover/DDNS con Postgres real (Testcontainers). |
| **Firewall apply** | Media | Generation + rollback. Falta más cobertura sobre QoS classes. |
| **Network config** | Media | Distro detection + writers. Falta integración real con `ip` cmd. |
| **Web filters / helpers** | Alta | RequireElevated, validation→ServiceResponse, HX-Trigger merge. |
| **Daemon API** | Media | Endpoints clave, integration con Web vía DaemonClient real. |
| **WAN monitor** | Baja | Pendiente sustituir bash watchdog por logic testeable. |
| **TUI** | Media | Label builder de RecoveryScreen, validación de NetworkInterfacesScreen, transiciones de UserSessionState, binding de `DaemonOptions.AcceptedPeerUids` (la pieza que install.sh escribe en daemon.env). El flujo Spectre interactivo no es unit-testeable sin TTY. |
| **`.deb` / ISO live-build** | N/A | Validación al integrarse en el builder Debian (Fase 5). |

### Estrategia de testing aplicada

- **Tier P0 (seguridad):** primero, cubierto. Argon2, AES-GCM, sessions, TOTP enrollment + verify, recovery codes, step-up, audit log.
- **Tier P1 (lógica de negocio + integración real):** mayoritariamente cubierto. Postgres real para servicios DB-heavy (no mocks de SQL); Unix socket real para DaemonClient; ArrayPool real para DhcpPacketContext.
- **Tier P2 (filtros web, helpers, controllers):** cubierto. Filtros validation, HX-Trigger merge, pipelines de respuesta HTMX.
- **Sin reflection ni Castle dynamic-mock-the-private-method:** el test seam se construye con `internal virtual` + `InternalsVisibleTo`, o subclase de prueba (`RecordingDhcpWorker`). Honesto y rápido.

> Antes de tocar el hot-path DHCP, lee [`docs/PerformanceAnalysis.md`](./docs/PerformanceAnalysis.md). Las reglas zero-allocation (Span/stackalloc/ArrayPool) son obligatorias.

---

## Despliegue en producción

Producción son **dos units systemd** (`netfirewall-daemon` con `CAP_NET_ADMIN`/`CAP_DAC_OVERRIDE`/`CAP_NET_RAW` y nada más; `netfirewall-web` con cero capabilities) detrás de **nginx con TLS**. Toda la plomería vive bajo `deploy/`:

```
deploy/
  systemd/                              units endurecidos
  config/{daemon,web}.json.template     appsettings (modo 0640)
  env/{daemon,web}.env.template         secretos — modo 0600/0640
  nginx/netfirewall.conf                proxy reverso TLS
  man/netfirewall-tui.1                 manpage de la TUI
  completion/netfirewall-tui            bash completion de la TUI
  install.sh                            instalador idempotente
  uninstall.sh                          inverso (--purge limpia datos)
  README.txt                            handbook operacional
  debian/                               (en curso) sources debhelper para .deb
  iso/                                  (en curso) config live-build para ISO
```

Instalar en Debian/Ubuntu/Rocky/Alma/openSUSE con .NET 10 SDK + PostgreSQL 14+ + systemd 250+:

```bash
sudo deploy/install.sh
```

`install.sh` publica los cinco binarios (daemon, web, **tui**, migrations, wanmonitor), crea el grupo `netfirewall` + el usuario `netfirewall-web`, genera la master key AES-256, escribe `daemon.env` con `Daemon__AcceptedPeerUids` poblado con el UID del Web **y** root (para que `sudo netfirewall-tui` desde consola alcance el socket), aplica migraciones, deja la TUI en `/usr/local/bin/netfirewall-tui` con manpage en `/usr/local/share/man/man1/` y completion en `/etc/bash_completion.d/`, y arranca ambas unidades systemd.

Para detalles de hardening (capabilities, `ProtectSystem`, `SystemCallFilter`, manejo de la master key AES-256 para cifrado de secretos TOTP, modelo de privilegios Web ↔ Daemon vía Unix socket): ver [`deploy/README.txt`](./deploy/README.txt) y [`CLAUDE.md`](./CLAUDE.md).

> **Próximo paso de despliegue (Fase 5 — NetFirewall OS, en curso):** dos capas que reemplazan al `install.sh` para entornos no desarrollables.
>
> 1. **`.deb` package** bajo `deploy/debian/` — `apt install netfirewall` instala las cinco unidades publish, las units systemd, manpage y completion; el `postinst` porta la lógica de creación de usuarios + master key + migraciones.
> 2. **`live-build` ISO** bajo `deploy/iso/` — bakea el `.deb` en una ISO Debian-based con preseed unattended; primer boot suelta el bootstrap token para enrolar al primer admin con TOTP. Snapshot LVM antes de cada apply queda como TODO de v0.6.
>
> Esta fase se desarrolla **sobre Debian 13 directamente** (no macOS) — el toolchain (`debuild`, `dpkg-buildpackage`, `lintian`, `live-build`, `debootstrap`) es Linux-only.

---

## DHCP — notas RFC 2131 y performance

Resumen rápido del diálogo cliente↔servidor que el `DhcpServer` implementa:

1. **DHCPDISCOVER** — cliente broadcast (Option 53 = 1) con su MAC en Option 61.
2. **DHCPOFFER** — servidor responde (Option 53 = 2) con `yiaddr`, server identifier (Option 54), subnet/router/DNS/lease time.
3. **DHCPREQUEST** — cliente elige una offer (Option 53 = 3) e identifica al server elegido (Option 54).
4. **DHCPACK** — server confirma (Option 53 = 5) con lease time + T1 (renew) + T2 (rebind).
5. **DHCPNAK** — server niega si la IP ya no está disponible (Option 53 = 6).

Mensajes adicionales: **DHCPDECLINE** (cliente detecta IP duplicada), **DHCPRELEASE** (libera el lease), **DHCPINFORM** (cliente con IP estática pide solo opciones).

**Lease management:** los timers T1 y T2 controlan el renew y rebind. T1 → unicast al server original; T2 → broadcast a cualquiera.

**Hot path optimization:**

- Pipeline: UDP receive → bounded `Channel<DhcpPacketContext>` (capacity 1024) → consumer parse + dispatch + reply.
- Parser usa `ReadOnlySpan<byte>` end-to-end; serializer rentea de `ArrayPool<byte>`.
- `LeaseCache` (singleton, write-through a Postgres) responde la mayoría de los lookups O(1) sin tocar DB.
- `DhcpSubnetService` (singleton) cachea subnets, pools, exclusiones, y CIDR pre-parseado para `FindSubnetContainingIp` zero-alloc.
- Counters per-message-type observables vía `internal long` properties (Discover/Request/Release inbound; Offer/Ack/Nak outbound) — el log periódico los reporta cada minuto.

**Antes de tocar el hot-path:** lee [`docs/PerformanceAnalysis.md`](./docs/PerformanceAnalysis.md). Documenta el budget de latencia per-stage (150-550µs/paquete, dominado por el DB round-trip) y las reglas zero-allocation obligatorias.

---

## Roadmap

### Shipped (hasta v0.4)
- [x] **TUI sobre TTY** — Spectre.Console + mismo daemon socket. Login single-step (user + pwd + TOTP/recovery), `NetworkInterfacesScreen` (list/edit/apply IP/máscara/gateway/MAC/MTU), `RecoveryScreen` (root-peer-only break-glass: reset password / disable TOTP / clear lockout), distribución por `install.sh` con manpage + bash completion + symlink + multi-UID peer-cred.
- [x] Buffer pool refactor en `IDhcpServerService` (`DhcpResponseBuffer`) — elimina el `new byte[offset]` por respuesta, validado por bench (`Allocated: -`).
- [x] Per-message-type counters en `DhcpWorker` para monitoreo.
- [x] FQDN support en network objects con DNS resolver + cache.
- [x] Schedules con timezone + watcher que re-aplica nft al cambiar estado.

### En curso (v0.5 — Fase 5: NetFirewall OS)
- [ ] **`.deb` package** bajo `deploy/debian/` — `apt install netfirewall` con `postinst` que porta `install.sh`. Hoy: `control`, `rules`, `changelog`, `compat` listos; falta `postinst` / `prerm` / `postrm` / `install` / `copyright` / `source/format`.
- [ ] **`live-build` ISO** bajo `deploy/iso/` — Debian-based con preseed unattended, consume el `.deb` vía `package-lists/`. Hoy: árbol de directorios listo; falta el contenido (`auto/{config,build}`, preseed, hooks, package-lists, `includes.chroot/etc/netfirewall/`).
- [ ] UI completa de WireGuard con QR para móviles.
- [ ] DNS resolver integrado (Unbound o BIND embebido).

### Medio plazo (v0.6)
- [ ] Bridges + bonds en network config.
- [ ] IPv6 first-class en DHCP (DHCPv6) y firewall (nft `ip6` family).
- [ ] Snapshot LVM/btrfs antes de cada apply destructivo.
- [ ] Tail/`journalctl` viewer dentro de la TUI (troubleshoot sin salir).
- [ ] TUI: ver/editar firewall rules (escala el use case más allá de network).
- [ ] E2E integration tests con Testcontainers Postgres + Kestrel-on-UDS para `IDaemonClient` real.

### Largo plazo (v1.0)
- [ ] Captive portal.
- [ ] Cluster HA (active/passive con keepalived + replicación logical Postgres).
- [ ] Plugin/marketplace para reglas comunitarias (block-lists, GeoIP).

---

## Contribuir

Si te interesa colaborar, eres bienvenido. Antes de abrir un PR:

1. Lee [`CLAUDE.md`](./CLAUDE.md) — las 10 reglas no negociables aplican a todo el código.
2. Asegúrate de que `dotnet build` y `dotnet test` pasen verde.
3. Para cambios de schema: nueva migración, **nunca** edites una ya aplicada.
4. Para cambios de UI: usa los tokens semánticos del theme; cero hex literales, cero `<style>` inline.
5. Si tu cambio afecta la pipeline DHCP: corre el bench/profile manualmente y nota el impacto en el PR.
6. Tests primero (TDD bienvenido). Si tu cambio afecta lógica, debe haber un test que falle antes y pase después.

Issues, ideas y discusión: usa la pestaña Issues del repo. Para PRs grandes, abre primero un issue describiendo el approach.

---

## Licencia

Por definir. Hasta entonces, considera "todos los derechos reservados" pero siéntete libre de leer, fork-ear para experimentar, y abrir issues / PRs.
