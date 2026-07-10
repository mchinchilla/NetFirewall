# NetFirewall appliance: `.deb` + Debian 13 ISO

This document is the single source of truth for building NetFirewall as a
self-contained appliance — a real Debian package and a bootable/installable
Debian 13 (trixie) ISO, the pfSense/OPNsense-style deployment path. It
complements the manual `deploy/install.sh` flow (which targets a host that
already has .NET + PostgreSQL).

> **The #1 rule — never bake secrets into the image.** Per
> [`master-key.md`](master-key.md), the AES-256 master key and the DB password
> must NOT live in the image, or every flashed appliance shares one TOTP key +
> DB password. This is enforced architecturally (postinst is secret-free,
> firstboot mints per-appliance secrets), by a diff-assert, by Doctor's
> `MasterKeySyncCheck`, and by a CI assertion that greps the built squashfs.

## The three pieces

| Piece | Where | What it does |
|-------|-------|--------------|
| **`.deb`** | `deploy/debian/` | Self-contained .NET publish of all 7 binaries + maintainer scripts. Installs paths/units/templates with **no secrets**, **no DB**. |
| **firstboot** | `deploy/firstboot/`, `deploy/systemd/netfirewall-firstboot.service` | Runs once on first real boot: mints master key + DB password, inits local PG, creates role/DB, migrations, seeds, starts services, runs doctor. |
| **ISO** | `deploy/iso/` | Debian 13 live-build tree. Embeds the `.deb` + all OS deps for an **offline** install; bootable live appliance + bare-metal installer. |
| **CI** | `.github/workflows/build-iso.yml` | Builds the `.deb` (PRs), then the ISO (main/tags), with the secret-bake assertion. |

## Self-contained, on purpose

`deploy/debian/rules` publishes `--self-contained true -r linux-x64` (NOT
`PublishSingleFile`, NOT trimmed — reflection in RepoDb/MVC/config-binding would
break). The runtime travels inside the package, so the `.deb` / ISO does **not**
depend on `dotnet-runtime` / `aspnetcore-runtime` or the Microsoft APT repo. The
app does culture-aware work (no `InvariantGlobalization`), so **libicu** stays a
dependency (`libicu76 | libicu`).

Binaries shipped: `daemon, web, dhcp-server, tui, doctor, migrations,
wanmonitor` under `/opt/netfirewall/<name>/`.

## The provisioning split (why two halves)

```
postinst  (build/install time, incl. live-build chroot)   firstboot (first real boot)
─────────────────────────────────────────────────────    ───────────────────────────────
• group netfirewall + user netfirewall-web                • generate AES-256 master key
• dirs + modes (/etc,/var/lib,/var/log/netfirewall)       • generate random local DB password
• systemd units installed + enabled (NOT started)         • ensure local PG cluster up
• env files = TEMPLATES verbatim (__REPLACE__ tokens)     • CREATE ROLE + DATABASE (idempotent)
• appsettings.Production.json from templates              • render both env files, diff-assert key
• NO secret. NO DB. deterministic + idempotent.          • migrations + seeds
                                                          • start daemon/web/bootstrap
                                                          • doctor (logged, non-fatal)
                                                          • touch /var/lib/netfirewall/.provisioned
```

`netfirewall-firstboot.service` is `ConditionPathExists=!/var/lib/netfirewall/.provisioned`,
`Before=netfirewall-daemon/web/bootstrap`, `After=postgresql network-online`.

## Build the `.deb` (Debian 13 host/container, as root)

```bash
# debian/ must sit at the repo root for dpkg-buildpackage; ours lives in deploy/.
rsync -a deploy/debian/ debian/
chmod 0755 debian/rules debian/postinst debian/prerm debian/postrm
apt-get install -y dotnet-sdk-10.0 debhelper devscripts dpkg-dev lintian
dpkg-buildpackage -us -uc -b        # -> ../netfirewall_*.deb
```

Verify a fresh install does the right thing:

```bash
dpkg -i ../netfirewall_*.deb
# users/dirs/units exist; env files still tokenized; NO service started; NO DB.
grep __REPLACE_MASTER_KEY__ /etc/netfirewall/daemon.env   # must match
```

## Build the ISO

See [`deploy/iso/README.md`](../deploy/iso/README.md). Short version (root, on a
Debian 13 host or privileged container):

```bash
cp ../netfirewall_*.deb deploy/iso/config/packages.chroot/
apt-get install -y live-build debootstrap squashfs-tools xorriso \
    isolinux syslinux-common grub-pc-bin grub-efi-amd64-bin mtools dosfstools
cd deploy/iso && lb config && lb build      # -> live-image-amd64.hybrid.iso
```

The bare-metal installer is preseeded except for **two questions kept
interactive on purpose**: the target disk and the final wipe confirmation
(hardcoding `/dev/sda` caused wrong-disk installs — USB media often enumerates
as `sda`). The preseed also sets `grub-installer/force-efi-extra-removable` so
UEFI machines that lose/ignore NVRAM boot entries still boot from the fallback
`\EFI\BOOT\BOOTX64.EFI` path. Branding: `lb config` clones + patches the stock
isolinux theme (BIOS menu) and `config/bootloaders/grub-pc/config.cfg` styles
the EFI menu; both use `deploy/iso/branding/splash.png`. See
`deploy/iso/README.md` for the troubleshooting list ("installed but won't
boot") and unattended-install knobs.

Test in QEMU:

```bash
qemu-system-x86_64 -m 4096 -smp 2 -enable-kvm \
    -netdev user,id=n0 -device virtio-net,netdev=n0 \
    -cdrom deploy/iso/live-image-amd64.hybrid.iso
```

## First-boot reachability

NIC names are unknown at build time, so the image never hardcodes `eth0`/`ens256`:

1. `netfirewall-nic-bootstrap.service` (before networking) substitutes the real
   first physical NIC into `/etc/network/interfaces.d/00-netfirewall-bootstrap`
   (ifupdown DHCP) → the appliance gets a lease and is reachable.
2. `/etc/issue` shows the ASCII logo + acquired IP + web URL (refreshed by
   `netfirewall-issue-banner` via if-up.d/if-down.d hooks); after login,
   `/etc/update-motd.d/10-netfirewall` (shipped by the `.deb`) prints the same
   logo plus live unit states and the web URL.
3. The operator opens the web UI, logs in with the bootstrap token
   (`journalctl -u netfirewall-web | grep -i token`), and runs the SetupWizard,
   which writes the real per-NIC WAN/LAN config (via
   `DebianInterfacesConfigService`) and supersedes the bootstrap file.

The stack is **ifupdown**, not NetworkManager/netplan/cloud-init (all explicitly
excluded from the image).

## CI (`.github/workflows/build-iso.yml`)

- **`deb`** job (`container: debian:trixie`): stage `debian/`, build, assert env
  templates are tokenized + self-contained + firstboot present, lintian
  (non-blocking), upload `.deb`. Runs on PRs too.
- **`iso`** job (`needs: deb`, `--privileged`): drop the `.deb` into
  `packages.chroot/`, `lb config && lb build`, **secret-bake assertion** (mount
  the squashfs, grep `/etc/netfirewall/*.env` — fail if a real base64 key is
  present, the placeholder is missing, or the image is already `.provisioned`),
  upload ISO; on `v*` tags, attach ISO + `.deb` to the Release.

## Removal

```bash
apt remove netfirewall    # keeps /etc, /var/lib, /var/log, the DB
apt purge  netfirewall    # also wipes those + drops the LOCAL DB/role only
```

A remote/managed PostgreSQL is never dropped automatically.

## Relationship to `deploy/install.sh`

`install.sh` remains the manual path for an existing host (it only *connects* to
PostgreSQL; it never creates the role/DB). The appliance firstboot owns the local
cluster and *does* create them. The two share the same master-key
resolve-once-write-both + diff-assert contract. A future convergence (Phase 4.5)
would make `install.sh` an `apt install ./netfirewall_*.deb` wrapper so there is
a single source of provisioning truth.
