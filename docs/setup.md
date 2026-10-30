# Instalación y actualización — `setup.sh`

NetFirewall se distribuye como un **bundle de release**: un `tar.gz` con todos los
binarios ya compilados (self-contained, linux-x64), las migraciones SQL, las
unidades systemd, las plantillas de configuración y `setup.sh`. El mismo script
**instala** un firewall nuevo y **actualiza** uno que ya está corriendo.

```
  dev / CI                         firewall (root)
  ─────────                        ───────────────
  git tag v1.4.0                   tar xzf netfirewall-1.4.0.tar.gz
  deploy/build-bundle.sh   ──scp──▶ cd netfirewall-1.4.0
    → dist/netfirewall-1.4.0.tar.gz ./setup.sh --preflight
                                    ./setup.sh
```

Este método reemplaza a `deploy/install.sh` (que compilaba en el servidor) y al
`.deb` + ISO de appliance (eliminados).

---

## Índice

1. [Requisitos del host](#requisitos-del-host)
2. [Construir el bundle](#construir-el-bundle)
3. [Instalación nueva](#instalación-nueva)
4. [Actualizar](#actualizar)
5. [Rollback](#rollback)
6. [Referencia de parámetros](#referencia-de-parámetros)
7. [Qué hace cada paso](#qué-hace-cada-paso)
8. [Layout en disco](#layout-en-disco)
9. [Opciones guardadas — `setup.conf`](#opciones-guardadas--setupconf)
10. [Archivos de entorno y la master key](#archivos-de-entorno-y-la-master-key)
11. [Migrar desde `install.sh` (layout legacy)](#migrar-desde-installsh-layout-legacy)
12. [Qué hace si algo falla](#qué-hace-si-algo-falla)
13. [Lo que `setup.sh` nunca toca](#lo-que-setupsh-nunca-toca)
14. [Desinstalar](#desinstalar)
15. [Logs y diagnóstico](#logs-y-diagnóstico)

---

## Requisitos del host

| Requisito | Detalle |
|---|---|
| SO | Debian 12/13 o Ubuntu 22.04+ (otros con `--skip-packages`, sin garantía) |
| Arquitectura | x86_64 |
| Init | systemd corriendo (PID 1) |
| Usuario | `root` (sin `sudo`; el script lo exige) |
| Disco | ~125 MB por release bajo `--prefix` (se guardan 3 por defecto); el bundle pesa ~50 MB |
| Red | Acceso a los repos apt **solo** si faltan paquetes |

**No** necesita el SDK ni el runtime de .NET: el runtime viaja dentro del bundle.
`setup.sh` instala con `apt-get` lo que falte de esta lista (y nada si está todo):

`ca-certificates curl openssl nftables iproute2 conntrack iputils-ping postgresql-client tcpdump traceroute wireguard-tools libicuNN`
+ `postgresql` si la base es local + `nginx` si va a configurar el proxy.

---

## Construir el bundle

### En CI (lo normal)

Cada **tag `v*`** dispara `.github/workflows/release.yml`: compila, corre los
tests, arma el bundle y lo publica como **GitHub Release** con su `.sha256`.

```bash
git tag v1.4.0
git push origin v1.4.0
# → Releases: netfirewall-1.4.0.tar.gz + netfirewall-1.4.0.tar.gz.sha256
```

Cada push a `master` también arma un bundle y lo deja como *artifact* del run
(versión tipo `1.4.0-3-g97f88aa`), útil para probar antes de etiquetar.

### Local

Necesita el .NET 10 SDK y el binario standalone `tailwindcss` en el `PATH`.

```bash
deploy/build-bundle.sh                      # versión = git describe
deploy/build-bundle.sh --version 1.4.0-rc1  # versión explícita
deploy/build-bundle.sh --output /tmp/dist   # otro directorio de salida (default dist/)
```

### La versión

Sin `--version` sale de `git describe --tags --always --dirty`:

| Estado del repo | Versión |
|---|---|
| Justo en el tag `v1.4.0` | `1.4.0` |
| 3 commits después del tag | `1.4.0-3-g97f88aa` |
| Con cambios sin commitear | `1.4.0-3-g97f88aa-dirty` |
| Sin ningún tag | `97f88aa` |

Esa misma cadena queda en: el nombre del tar.gz, el archivo `VERSION`, el
directorio del release (`releases/1.4.0`), el `InformationalVersion` de los
ensamblados (tarjeta *System info* del login, `/health` del daemon) y `BUILD_INFO`
(con el commit completo y la fecha de build).

### Contenido del bundle

```
netfirewall-1.4.0/
├── setup.sh  uninstall.sh  README.txt  VERSION  BUILD_INFO
├── app/                         ← se copia tal cual a <prefix>/releases/1.4.0
│   ├── daemon/  web/  dhcp-server/  tui/  doctor/
│   ├── migrations/ (netfirewall-migrate + sql/migrations/*.sql)
│   ├── bin/netfirewall-bootstrap
│   └── VERSION  BUILD_INFO  README.txt
└── deploy/                      ← plantillas que setup.sh renderiza
    ├── systemd/  config/  env/  nginx/  seeds/  man/  completion/
    └── sysctl/  modprobe.d/  modules-load.d/  tmpfiles/
```

Los seis componentes comparten el runtime por **hard links** (el tar los guarda
una vez), así que cada release ocupa ~125 MB en disco en lugar de ~600 MB, y el
tar.gz pesa ~50 MB.

Ningún secreto viaja en el bundle: las plantillas `env/*.template` llevan
placeholders `__REPLACE__` y el build falla si encuentra una master key real.

---

## Instalación nueva

```bash
# copiar el bundle al firewall
scp dist/netfirewall-1.4.0.tar.gz root@firewall:/root/

# en el firewall, como root
tar xzf netfirewall-1.4.0.tar.gz
cd netfirewall-1.4.0
./setup.sh --preflight     # revisa host, bundle, disco y BD; no cambia nada
./setup.sh                 # instala
```

Con los valores por defecto, una instalación nueva:

- instala PostgreSQL local, crea el rol `netfirewall` y la base `net_firewall`
  con una contraseña aleatoria;
- genera la master key AES-256 y la escribe idéntica en `daemon.env` y `web.env`;
- habilita el *boot apply* (`netfirewall-bootstrap.service`);
- configura nginx con TLS (certificado autofirmado) en `:443` → `127.0.0.1:5000`;
- arranca daemon + web y corre `netfirewall-doctor`.

Al terminar muestra la master key nueva en un recuadro: **guárdala en un lugar
seguro**, perderla invalida todos los enrolamientos TOTP.

Primer acceso:

```bash
journalctl -u netfirewall-web | grep -i bootstrap   # link de un solo uso para el primer admin
```

### Ejemplos comunes

```bash
# Con el servidor DHCP escuchando en ens256
./setup.sh --with-dhcp --dhcp-iface ens256

# Base de datos remota (la contraseña es obligatoria la primera vez)
./setup.sh --db-host 10.0.0.5 --db-password 'S3cr3t0' --db-name net_firewall

# Certificado real en vez del autofirmado
./setup.sh --tls-cert /etc/letsencrypt/live/fw.ejemplo.com/fullchain.pem \
           --tls-key  /etc/letsencrypt/live/fw.ejemplo.com/privkey.pem

# Sin tocar nginx (tienes tu propio proxy) y sin instalar paquetes
./setup.sh --skip-nginx --skip-packages

# Desatendido (CI / Ansible): sin pregunta de confirmación
./setup.sh --yes
```

---

## Actualizar

```bash
tar xzf netfirewall-1.5.0.tar.gz && cd netfirewall-1.5.0
./setup.sh --preflight
./setup.sh
```

No hace falta repetir parámetros: los que difieren del default quedaron en
`/etc/netfirewall/setup.conf` y se reutilizan. Lo que pases en la línea de
comandos manda sobre lo guardado.

Una actualización hace, en este orden:

1. **Backup** de la base con `pg_dump` → `/var/backups/netfirewall/net_firewall-before-1.5.0-<fecha>.sql.gz`.
2. **Copia** el release a `<prefix>/releases/1.5.0` (el activo sigue corriendo).
3. **Migra** la base con el runner del release **nuevo**, *antes* de cambiar nada.
   Si falla, se detiene aquí y el release anterior sigue activo.
4. Actualiza env files (solo agrega claves nuevas), unidades systemd y drop-ins.
5. **Cambia el symlink** `current` → `releases/1.5.0` (atómico, `mv -T`).
6. **Reinicia** daemon → web (→ dhcp) y verifica: unidad activa, la Web responde
   en `:5000`, el daemon reporta la versión esperada en `/health`.
7. Si daemon o web **no levantan → rollback automático** al release anterior.
8. Guarda opciones, borra releases viejos (deja 3) y corre `netfirewall-doctor`.

Reinstalar la **misma** versión también funciona (útil para cambiar parámetros):
la copia vieja se conserva hasta que los servicios levantan con la nueva.

---

## Rollback

```bash
./setup.sh --list-releases          # ● activo   ↩ anterior
./setup.sh --rollback               # vuelve al anterior
./setup.sh --rollback 1.4.0         # vuelve a una versión concreta que esté en disco
```

El rollback cambia el symlink y reinicia los servicios; tarda segundos. Desde el
release al que volviste, `--rollback` otra vez regresa al que dejaste.

> **La base de datos NO se revierte.** Las migraciones son forward-only. Las
> migraciones aditivas (columnas/tablas nuevas) no molestan a binarios viejos. Si
> la versión nueva eliminó o renombró algo, restaura primero el dump previo:
>
> ```bash
> systemctl stop netfirewall-web netfirewall-daemon
> gunzip -c /var/backups/netfirewall/net_firewall-before-1.5.0-*.sql.gz \
>   | runuser -u postgres -- psql -d net_firewall
> ./setup.sh --rollback
> ```

`--rollback` y `--list-releases` se pueden correr desde **cualquier** bundle
extraído (no necesita ser el de la versión destino).

---

## Referencia de parámetros

**Guardado** = se escribe en `setup.conf` (si difiere del default) y se reutiliza
en la siguiente corrida.

### Modos

| Parámetro | Descripción |
|---|---|
| *(ninguno)* | Instala, o actualiza el release instalado. |
| `--preflight` | Revisa bundle, host, disco y conexión a la BD, y muestra el plan. **No cambia nada.** Sale con código ≠ 0 si encuentra problemas. |
| `--rollback [VERSIÓN]` | Activa el release anterior (o `VERSIÓN`) y reinicia. Pide confirmación. |
| `--list-releases` | Lista los releases en disco, cuál está activo y cuál es el anterior. |
| `-h`, `--help` | Ayuda resumida. |

### Layout

| Parámetro | Default | Guardado | Descripción |
|---|---|---|---|
| `--prefix DIR` | `/opt/tekium` | ✓ | Raíz de instalación. Releases en `DIR/releases/<versión>`, activo en `DIR/current`. Ruta absoluta, distinta de `/`. |
| `--keep-releases N` | `3` | ✓ | Releases que se conservan tras una actualización (mínimo 2; el activo y el anterior nunca se borran). |

### Base de datos

| Parámetro | Default | Guardado | Descripción |
|---|---|---|---|
| `--db-host HOST` | `127.0.0.1` | ✓ | `127.0.0.1`, `localhost` o `::1` = **local**: instala PostgreSQL si falta y crea rol + base. Cualquier otro = remota, solo se conecta. |
| `--db-port PORT` | `5432` | ✓ | |
| `--db-name NAME` | `net_firewall` | ✓ | Identificador simple (`[A-Za-z_][A-Za-z0-9_]*`). |
| `--db-user USER` | `netfirewall` | ✓ | Ídem. |
| `--db-password PASS` | — | ✗ (vive en los env) | Instalación nueva local: se genera si no la pasas. Remota nueva: **obligatoria**. Actualización: se lee de `web.env`/`daemon.env`. No puede contener `;`, comillas, `\` ni espacios. |

Pasar **cualquier** `--db-*` hace que se reescriba `ConnectionStrings__DefaultConnection`
en los env files (conservando opciones extra como `Pooling`, `MaxPoolSize`), y en
una base local con rol existente, que se le asigne la contraseña pasada.

Sin `--db-*`, en una actualización los env files mandan: host/puerto/usuario/base
se leen de su connection string.

### Servicios

| Parámetro | Default | Guardado | Descripción |
|---|---|---|---|
| `--with-dhcp` | auto | ✓ | Instala y habilita `netfirewall-dhcp.service` (escucha UDP/67). |
| `--without-dhcp` | auto | ✓ | Detiene y elimina la unidad DHCP. |
| `--dhcp-iface IF` | primera NIC | ✓ | Interfaz de respaldo en `dhcp.env` (`DHCP__Interface`). Las subredes habilitadas en la BD tienen prioridad en runtime. |
| `--with-boot-apply` | auto | ✓ | Instala `netfirewall-bootstrap.service`: en cada arranque empuja el estado de la BD al kernel (nftables, QoS, policy routing, WireGuard). |
| `--without-boot-apply` | auto | ✓ | Elimina esa unidad. |

**auto** = conservar lo que ya hay: DHCP queda como esté instalado (nunca apaga un
DHCP que está sirviendo por omisión); boot apply se activa en instalaciones nuevas
y se conserva tal cual en actualizaciones.

> Con boot apply activo, la unidad tiene `PartOf=netfirewall-daemon`, así que
> **reiniciar el daemon en una actualización vuelve a aplicar** el estado de la BD.
> Es el mismo estado que ya estaba aplicado; si la BD tiene cambios pendientes de
> aplicar, se aplicarán.

### Proxy inverso

| Parámetro | Default | Descripción |
|---|---|---|
| `--configure-nginx` | auto | Escribe `/etc/nginx/sites-available/netfirewall.conf` (TLS en `:443`, redirección desde `:80`, WebSocket para la terminal) y lo habilita. |
| `--skip-nginx` | | No toca nginx nunca. |
| `--tls-cert FILE` | autofirmado | Certificado para nginx. Implica `--configure-nginx`. |
| `--tls-key FILE` | | Llave del certificado (obligatoria con `--tls-cert`). |

**auto** = solo en una instalación nueva y si el sitio no existe. En una
actualización nginx **no se toca** salvo que pases `--configure-nginx` o `--tls-cert`.
Si `nginx -t` rechaza la configuración (por ejemplo, otro `default_server`), se
revierte todo a como estaba y se avisa.

El certificado autofirmado va en `/etc/netfirewall/tls/`, incluye como SAN el
hostname, `localhost` y todas las IPv4 globales del equipo, y dura 10 años.
Con nginx anterior a 1.25.1 (Debian 12) la plantilla se adapta sola: `http2`
va en la línea `listen` en vez de `http2 on;`.

### Otros

| Parámetro | Default | Guardado | Descripción |
|---|---|---|---|
| `--skip-packages` | off | ✓ | No ejecuta `apt-get`; solo avisa lo que falta. |
| `--apply-seeds` | off | ✗ | Aplica `deploy/seeds/*.sql` (idempotentes, `ON CONFLICT`). Son defaults específicos de un host; un fallo avisa y continúa. |
| `--skip-backup` | off | ✗ | Actualiza sin `pg_dump` previo. |
| `--backup-dir DIR` | `/var/backups/netfirewall` | ✓ | Destino de los dumps (modo 0700, archivos 0600). |
| `--backup-keep N` | `10` | ✓ | Dumps que se conservan. |
| `--skip-doctor` | off | ✗ | No corre `netfirewall-doctor` al final. |
| `--forget-options` | | ✗ | Ignora `setup.conf` en esta corrida (y lo reescribe con los valores actuales). |
| `-y`, `--yes` | | ✗ | Sin pregunta de confirmación. Si stdin no es una terminal, tampoco pregunta. |

### Variables de entorno

| Variable | Efecto |
|---|---|
| `NO_COLOR=1` | Salida sin colores, spinner ni cajas (igual que cuando la salida no es una terminal). |

---

## Qué hace cada paso

La barra `N/13` del instalador corresponde a estos pasos:

| # | Paso | Qué hace |
|---|---|---|
| 1 | Host and bundle | Verifica bundle completo, systemd, x86_64, SO, disco. Resuelve el estado (nuevo / actualización / legacy) y muestra el **plan**. Pide confirmación. |
| 2 | Packages | `apt-get install` de lo que falte (o solo avisa con `--skip-packages`). |
| 3 | Accounts and directories | Grupo `netfirewall`, usuario de sistema `netfirewall-web` (nologin), directorios en `/etc`, `/var/lib`, `/var/log`; `/run/netfirewall` vía tmpfiles.d. |
| 4 | PostgreSQL | Base local: arranca el cluster, crea rol y base si no existen. Remota: nada. |
| 5 | Database backup | `pg_dump` comprimido (no en instalaciones nuevas, ni con `--skip-backup`). |
| 6 | Release | Copia `app/` a `releases/<versión>`, escribe `appsettings.Production.json` y la config del TUI. |
| 7 | Database migrations | `netfirewall-migrate up` del release **nuevo**. `--apply-seeds` aquí. |
| 8 | Configuration and secrets | Env files (crea o completa), master key idéntica en daemon y web, `dhcp.env`. |
| 9 | systemd and system files | Unidades con `@PREFIX@` renderizado, sysctl/modprobe/modules-load, enlaces en `/usr/local/bin`, man page, bash completion. |
| 10 | Reverse proxy (nginx) | Solo si corresponde (ver arriba). |
| 11 | Switch and restart | Symlink `current`, reinicio y health checks; rollback automático si falla. |
| 12 | Cleanup | Guarda `setup.conf`, poda releases viejos. |
| 13 | Verification | `netfirewall-doctor` (sus fallos se reportan, no revierten). |

---

## Layout en disco

```
/opt/tekium/                         ← --prefix
├── current -> releases/1.5.0        ← lo que ejecutan las unidades
├── .previous                        ← "1.4.0" (destino de --rollback)
└── releases/
    ├── 1.4.0/
    └── 1.5.0/
        ├── daemon/  web/  dhcp-server/  tui/  doctor/  migrations/  bin/
        └── VERSION  BUILD_INFO  README.txt

/etc/netfirewall/
├── daemon.env        0600 root:root          DB + master key + peer UIDs
├── web.env           0640 root:netfirewall   DB + master key
├── dhcp.env          0640 root:root          (con --with-dhcp)
├── setup.conf        0640                    opciones guardadas
└── tls/              certificado autofirmado (si aplica)

/etc/systemd/system/netfirewall-{daemon,web[,dhcp][,bootstrap]}.service
/etc/sysctl.d/netfirewall.conf · /etc/modprobe.d/netfirewall.conf
/etc/modules-load.d/netfirewall.conf · /etc/tmpfiles.d/netfirewall.conf
/usr/local/bin/netfirewall-{tui,doctor,migrate} -> /opt/tekium/current/...
/var/lib/netfirewall/   estado (web, daemon, captures, speedtests)
/var/log/netfirewall/   logs + setup-<fecha>.log de cada corrida
/var/backups/netfirewall/  dumps previos a cada actualización
```

---

## Opciones guardadas — `setup.conf`

`/etc/netfirewall/setup.conf` guarda solo las opciones que difieren del default,
para que actualizar sea simplemente `./setup.sh`:

```bash
# Written by setup.sh 1.4.0 on 2026-10-30T22:10:00Z.
INSTALL_DHCP="yes"
DHCP_IFACE="ens256"
BOOT_APPLY="yes"
```

Claves posibles: `PREFIX DB_HOST DB_PORT DB_NAME DB_USER INSTALL_DHCP DHCP_IFACE
BOOT_APPLY SKIP_PACKAGES BACKUP_DIR BACKUP_KEEP KEEP_RELEASES`. Se **parsea**, no
se ejecuta: cualquier otra línea se ignora. Nunca contiene la contraseña.

Prioridad: línea de comandos > `setup.conf` > default. `--forget-options` ignora el archivo.

---

## Archivos de entorno y la master key

- **Archivo que no existe** → se genera desde `deploy/env/*.template`.
- **Archivo que ya existe** → **se conserva tal cual**. Solo se agregan al final
  las claves que la plantilla tiene y el archivo no (por ejemplo una variable
  nueva de una versión nueva). Tus ediciones a mano sobreviven las actualizaciones.
- Con `--db-*` se reescribe únicamente la línea `ConnectionStrings__DefaultConnection`.

**Master key** (`NETFIREWALL_MASTER_KEY`, ver [`master-key.md`](master-key.md)):

- Daemon y Web deben tener la **misma** clave byte a byte.
- Si existe en alguno de los dos archivos, se **preserva** y se copia al otro.
  **Nunca** se rota en una actualización.
- Si existe en ambos y **difiere**, `setup.sh` se detiene sin tocar nada: tienes
  que decidir cuál es la buena (la que se usó para enrolar TOTP) y ponerla en los dos.
- Solo si no existe en ninguno se genera una nueva (`openssl rand -base64 32`).

---

## Migrar desde `install.sh` (layout legacy)

Aplica al servidor actual (tekium), donde los binarios viven en
`/opt/tekium/{daemon,web,dhcp-server,Migrations,tui}` y las unidades apuntan ahí.

```bash
tar xzf netfirewall-1.4.0.tar.gz && cd netfirewall-1.4.0
./setup.sh --preflight
```

El plan dirá **"Install 1.4.0 over an existing config (legacy layout)"** y listará
los directorios legacy. Revisa que:

- **Database** muestre `existing` con el host/usuario correctos (se leen de `web.env`);
- **DHCP server** diga `yes` si hoy usas `netfirewall-dhcp.service`;
- **Boot apply** diga `no` si hoy no tienes `netfirewall-bootstrap.service`
  (agrega `--with-boot-apply` solo si lo quieres);
- **nginx** diga `leave untouched` (tu sitio con Let's Encrypt no se toca).

Después:

```bash
./setup.sh
```

Qué pasa con lo existente:

- `daemon.env` / `web.env` / `dhcp.env`: se conservan (master key y contraseña intactas).
- Las unidades systemd se **reemplazan** por las del bundle, apuntando a
  `/opt/tekium/current/...`. Si las editaste a mano, compáralas antes
  (`deploy/systemd/` del bundle).
- Los directorios legacy **no se borran**; el resumen final imprime los `rm -rf`
  para cuando confirmes que todo anda.
- Se hace backup de la base antes de migrar.

---

## Qué hace si algo falla

| Falla en… | Resultado |
|---|---|
| Preflight / plan | Nada cambió. |
| `apt-get` | Se detiene; nada del release se tocó todavía. |
| `pg_dump` | Se detiene (usa `--skip-backup` si lo asumes conscientemente). |
| Migraciones | Se detiene **antes** del cambio de symlink: el release anterior sigue activo y corriendo (sus servicios ni se reinician). El release a medio instalar se descarta. |
| Daemon o Web no levantan | **Rollback automático**: symlink al release anterior + reinicio; `.previous` vuelve a lo que era. Las migraciones quedan aplicadas. Muestra las últimas líneas del journal. El release fallido queda en disco (se poda en la siguiente actualización exitosa). |
| DHCP no levanta | Aviso, sin rollback (el firewall en sí está arriba). |
| nginx rechaza la config | Se revierte el sitio, aviso. |
| Doctor reporta fallos | Aviso; la instalación se considera completa. |

En una **instalación nueva** no hay a qué volver: se detiene con el journal a la vista.

Solo puede correr un `setup.sh` a la vez (lock en `/run/netfirewall-setup.lock`).
`Ctrl-C` detiene el spinner y restaura el cursor.

---

## Lo que `setup.sh` nunca toca

- El **ruleset nftables vivo**, rutas, reglas `ip rule`, WireGuard, la config de red
  (`/etc/network`, netplan, NetworkManager). Solo reinicia servicios NetFirewall
  (salvo el re-apply de boot apply descrito arriba).
- La master key y la contraseña de la BD existentes.
- Un sitio nginx existente en una actualización.
- La base de datos fuera de migraciones forward-only (nunca hace `DROP`).
- Archivos de otros productos bajo `--prefix` (p. ej. `/opt/tekium/` compartido).

---

## Desinstalar

```bash
./uninstall.sh            # detiene y quita unidades, releases y enlaces; conserva config, estado y BD
./uninstall.sh --purge    # además borra /etc/netfirewall, estado, logs y usuarios (pide escribir "purge")
```

La base de datos **nunca** se borra automáticamente; el script imprime los comandos.
Solo elimina `releases/`, `current` y `.previous` bajo el prefix; el directorio
del prefix se borra únicamente si queda vacío.

---

## Logs y diagnóstico

```bash
ls /var/log/netfirewall/setup-*.log        # log completo de cada corrida (apt, migraciones, etc.)
journalctl -u netfirewall-daemon -u netfirewall-web -e
netfirewall-doctor                         # validación completa (incluye "Installed release")
netfirewall-doctor --json | jq '.[] | select(.status != "pass")'
netfirewall-migrate status                 # aplicadas / pendientes / drift (usa la conexión de daemon.env)
curl -s --unix-socket /run/netfirewall/control.sock http://daemon/health   # versión del daemon
cat /opt/tekium/current/BUILD_INFO         # versión + commit exacto en producción
```

En pantalla solo se ve el resumen de cada comando; la salida completa va al log
de esa corrida, y cuando un comando falla se muestran sus últimas 15 líneas.
