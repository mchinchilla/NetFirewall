# TOTP master key (`NETFIREWALL_MASTER_KEY`)

The master key is the AES-256-GCM secret that encrypts every user's TOTP secret
at rest (`user_totp_secrets.secret_encrypted`). Get it wrong and **every TOTP
code is rejected** — login, step-up elevation, and the web terminal all break.
This document is the single source of truth for where the key lives and the rules
around it.

## The one rule

> **The daemon and the Web must hold the byte-for-byte identical key.**

Both the `netfirewall-daemon` and `netfirewall-web` processes decrypt the *same*
ciphertext written by the Web at enrollment time. If their keys differ, decryption
silently produces garbage and verification fails for every valid code — with no
obvious error, just "Invalid TOTP code" forever.

## Where it lives

`AesGcmTotpSecretCipher` (`NetFirewall.Services/Auth/AesGcmTotpSecretCipher.cs`)
reads the key with this precedence:

1. Environment variable `NETFIREWALL_MASTER_KEY` (preferred in production)
2. Config `Auth:MasterKey` in `appsettings*.json` (fallback)
3. Development only: an **ephemeral** random key (lost on restart — fine for dev,
   fatal for prod, which is why the ctor *throws* in non-Development when 1 and 2
   are both absent).

In production the key is delivered as an env var via the systemd `EnvironmentFile`
of **each** unit:

| File | Owner / mode | Loaded by | Used for |
|------|--------------|-----------|----------|
| `/etc/netfirewall/daemon.env` | `root:root` `0600` | `netfirewall-daemon` | daemon-side TOTP: `/v1/crypto/{encrypt,decrypt}`, the web terminal's `/v1/terminal/open` TOTP gate |
| `/etc/netfirewall/web.env`    | `root:netfirewall` `0640` | `netfirewall-web` | Web-side TOTP when `Daemon:UseForTotp=false` (Web holds the key itself) |

> Note: `EnvironmentFile=-/etc/...` in the unit uses a leading `-` (optional load).
> A missing file or a missing `NETFIREWALL_MASTER_KEY=` line therefore does **not**
> fail startup — the daemon comes up keyless and only throws on first TOTP use.
> The daemon now logs a loud **warning at startup** if the key is absent
> (`Program.cs`), so check `journalctl -u netfirewall-daemon` after a deploy.

## Why both processes need it (and the two-cipher model)

The Web swaps its TOTP cipher based on `Daemon:UseForTotp`
(`NetFirewall.Web/Daemon/DaemonServiceCollectionExtensions.cs`):

- `Daemon:UseForTotp=true` (intended prod default): the Web proxies crypto to the
  daemon over the Unix socket (`DaemonTotpSecretCipher` → `/v1/crypto/*`). The
  **daemon** holds the key; a Web compromise can't decrypt TOTP secrets.
- `Daemon:UseForTotp=false`: the Web holds the key locally
  (`AesGcmTotpSecretCipher`) and never asks the daemon.

Either way the **daemon needs the key** the moment any daemon-side feature
verifies TOTP. The web terminal (`/v1/terminal/open`) is the first such feature,
so a host that had `UseForTotp=false` and never put the key in `daemon.env` will
appear healthy (login works via the Web's local cipher) until someone opens the
terminal — then `AesGcmTotpSecretCipher`'s ctor throws and the open fails.
See [[deploy/README.txt]] troubleshooting.

## How `setup.sh` keeps them in sync

`deploy/setup.sh` resolves the key **once** and writes the **same** value into
both env files, then asserts they match before going on:

1. Resolve: reuse an existing real key from either file — an upgrade **never**
   rotates the key (rotating invalidates all enrollments). If both files carry a
   key and they **differ**, setup stops without touching anything: pick the one
   the enrollments were made with and put it in both. Only when neither has one
   is a new key generated (`openssl rand -base64 32`).
2. A file that doesn't exist yet is rendered from its template, substituting the
   distinct token `__REPLACE_MASTER_KEY__`; an existing file is kept and only
   gets the key line set to the resolved value.
3. Post-condition: compare the `NETFIREWALL_MASTER_KEY=` line of both files and
   stop if they differ — so template/token drift can't ship a silent outage.

A distinct token (`__REPLACE_MASTER_KEY__`, not the generic `__REPLACE__` used for
the DB password) keeps the two substitutions independent. The release bundle
never carries a key: `build-bundle.sh` fails if one shows up in it.

## Operating the key

- **Back it up.** Losing it = every user must re-enroll TOTP. Store it in your
  secrets manager, not just on the host.
- **Rotating** is a breaking change: set the new key in *both* env files, restart
  *both* services, and have every user re-enroll. There is no re-encrypt-in-place
  path.
- **Upgrades** (`./setup.sh` from a newer bundle) preserve the existing key.

## Diagnosing a mismatch / absence on a live host (root)

```bash
# Both files should report 1 (the line exists):
grep -c '^NETFIREWALL_MASTER_KEY=' /etc/netfirewall/daemon.env
grep -c '^NETFIREWALL_MASTER_KEY=' /etc/netfirewall/web.env

# The two values must be identical (compares hashes, not the secret):
grep '^NETFIREWALL_MASTER_KEY=' /etc/netfirewall/daemon.env | sha256sum
grep '^NETFIREWALL_MASTER_KEY=' /etc/netfirewall/web.env    | sha256sum

# The running daemon must actually have it in its environment:
tr '\0' '\n' < /proc/$(pgrep -x netfirewall-daemon)/environ | grep -c NETFIREWALL_MASTER_KEY  # → 1
```

If `daemon.env` is missing the line, copy it verbatim from `web.env` (this is the
common case on hosts provisioned before the installer wrote the key to both):

```bash
grep '^NETFIREWALL_MASTER_KEY=' /etc/netfirewall/web.env >> /etc/netfirewall/daemon.env
chmod 0600 /etc/netfirewall/daemon.env
systemctl restart netfirewall-daemon
```

> Confirm the actual `EnvironmentFile` with `systemctl cat netfirewall-daemon`
> before editing (setup.sh installs `/etc/netfirewall/daemon.env`).

## Images and cloned hosts

The key must **never** be baked into a VM template or disk image — every clone
would share it. Install from the release bundle on each host (or run `./setup.sh`
on first boot of a clone that has no `/etc/netfirewall/*.env` yet): setup.sh
generates the key per host and writes the identical value to both env files.
