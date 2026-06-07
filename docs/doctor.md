# netfirewall-doctor (requirements validator)

A Spectre.Console CLI that validates a NetFirewall deployment end-to-end and tells
you, in one table, exactly what's wrong and how to fix it. Built to catch silent
deploy drift — the kind that "works at login but breaks the terminal" (a daemon
missing `NETFIREWALL_MASTER_KEY`). Project: `NetFirewall.Doctor/`.

## Running

```bash
netfirewall-doctor                     # validate everything (installed symlink)
netfirewall-doctor --service daemon    # only daemon-relevant checks
netfirewall-doctor --json              # machine-readable (CI / scripts)
netfirewall-doctor --prefix /opt/tekium --etc /etc/netfirewall   # non-default layout
```

From the repo: `dotnet run --project NetFirewall.Doctor -- --service all`.

The installer publishes it to `$PREFIX/doctor`, symlinks `/usr/local/bin/netfirewall-doctor`,
and runs it as the final post-install verification step.

## Flags

- `--service web|daemon|dhcp|tui|all` — filter checks by category/service (default `all`).
- `--json` — emit a JSON array of `{category, name, status, message, remedy, detail}`.
- `--prefix <path>` — install prefix (default `/opt/netfirewall`; tekium uses `/opt/tekium`).
- `--etc <path>` — config dir holding the env files (default `/etc/netfirewall`).

## Exit code

- `0` — all checks passed (warnings allowed).
- `1` — at least one check **failed**. Use in CI / install.sh.

## Checks

| Category | What it verifies |
|----------|------------------|
| Env | `daemon.env` + `web.env` exist (daemon.env should be 0600); each service's required keys are present and not placeholders. |
| Master key | `NETFIREWALL_MASTER_KEY` present in **both** env files and **byte-identical** (see `docs/master-key.md`). This is the production-incident check. |
| Paths | Binaries published under the prefix; `/etc`, `/var/lib` dirs exist. *(Linux only — Skips elsewhere.)* |
| Paths (DHCP) | The DHCP server is deployed: `$Prefix/dhcp-server/` holds the binary + `appsettings.json`. **Optional** — DHCP is installer-gated (`INSTALL_DHCP=yes`), so a missing dir Warns (not Fails). *(Linux only.)* |
| systemd | `netfirewall-daemon` + `netfirewall-web` units are active (Fail if not). `netfirewall-dhcp` is checked too but **optional** — not-installed / inactive only Warns; a `failed` unit Warns distinctly. *(Linux only.)* |
| Daemon | The Unix socket exists and answers `/health` (reuses `IDaemonClient`). *(Linux only.)* |
| DHCP | **Configuration**: effective connection string (dhcp.env override → appsettings.json) is set + non-placeholder, and at least one listening interface is configured. **Interface exists on host**: each configured NIC is present (Warn — enabled DB subnets override the config fallback; *Linux only*). **Listening on UDP/67**: something is bound to the DHCP port via `ss` (Warn if absent — a raw-socket-only deploy may not show a `:67` UDP bind; *Linux only*). |
| Database | Connection string works; PostgreSQL is **≥ 14** (Warn if older); the `__migrations` table **and** the core domain tables (`users`, `dhcp_subnets`, `dhcp_leases`, `fw_interfaces`) exist. |
| Database (migrations) | Every `.sql` under `$Prefix/migrations/sql/migrations` (or the repo's `NetFirewall.Services/sql/migrations`) is applied (Warn on pending) and no applied file's content drifted (Fail on sha256 drift — mirrors the migration runner). |
| Database (DHCP) | The DHCP server's **own** connection string reaches PostgreSQL and sees `dhcp_leases`. Separate from the daemon/web string because it can drift independently (a wrong host/password here = leases silently don't persist). |

Statuses: `✓` pass · `✗` fail · `⚠` warn · `–` skip (not applicable here).

## Behavior

- **Fail-soft**: a check never throws — a missing file / unreachable daemon / DB
  error becomes a `Fail` or `Skip` with a remedy, never a crash.
- **Cross-platform**: runs on macOS/Windows for dev; Linux-only checks report
  `Skip` ("not applicable off Linux") instead of false failures. The project has
  **no** `[assembly: SupportedOSPlatform]` on purpose.

## Extending

Add a class implementing `ICheck` (`NetFirewall.Doctor/Checks/`) and register it in
the `checks` array in `Program.cs`. Each check returns a `CheckResult`
(`Pass`/`Warn`/`Fail`/`Skip`) with an optional one-line `Remedy`. Gate Linux-only
logic behind `ctx.IsLinux`. Pure check logic is unit-tested in
`NetFirewall.Tests/Doctor/DoctorChecksTests.cs` — add cases there.
