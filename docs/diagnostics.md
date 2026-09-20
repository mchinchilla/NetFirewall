# Diagnostics

The **Diagnostics** section (`/Diagnostics`) answers two questions the rest of the
UI cannot: *where would this packet go?* and *where did it die?*

Every tool executes **in the daemon** — it needs root, `CAP_NET_ADMIN` (for
`ping -m`) and access to the kernel journal. The Web validates the form, proxies
through `IDaemonClient`, and renders the result. Each run is recorded in
`diag_runs`, which the Web reads directly, so history stays readable while the
daemon is down.

Most tools are **read-only**: they probe and look up, they never mutate the
kernel. The remedies shown next to a failed check are links to the pages that
already apply changes (Apply VPN, Apply firewall, Policy routing). Two tools —
the flow inspector and packet capture — do change the box, and are gated
accordingly (see **Invasive tools**).

## Tools

| Tool | What it runs | Why it exists |
|---|---|---|
| Ping | `ping -n -c N -W T [-m mark \| -I iface]` | A WAN or tunnel must be tested with its **fwmark**, not `-I`: policy routing ignores the bind, so a `-I` failure proves nothing. |
| Traceroute | `traceroute -n -q 1`, or `ping -t <ttl> -m <mark>` per hop when a mark is set | traceroute has no fwmark option; the per-hop ping is the only way to follow a policy-routed path. |
| Route oracle | `ip -j route get <dst> [from <src>] [iif <if>] [mark <m>]` | Which table and device the kernel picks — including the policy-routing tables. |
| Conntrack lookup | `conntrack -L -o extended` with kernel-side `-s/-d/-p/--dport` filters | The **reply tuple** shows what a flow was NATed to: the tunnel address means it left via wg0, a WAN address means it left via that WAN. |
| Drop log | `journalctl -k --since -Nmin -n L` | Decodes every nftables `log prefix` (INPUT_DROP, FORWARD_DROP, SPOOFED_SRC, BLOCKED_SCAN…), martian reports and WireGuard messages, with top prefixes/sources/ports. `dmesg` is unavailable: the unit sets `ProtectKernelLogs=yes`. |
| Interfaces & neighbours | `/sys/class/net/*`, `ip -j addr`, `ip -j neigh` | Link state, MTU, counters, errors, ARP/ND. Polled panels, not persisted. |
| Kernel tunables | `/proc/sys/...` + conntrack metrics | `ip_forward`, **effective** `rp_filter` (max of `all` and the device — strict silently drops policy-routed replies), `log_martians`, conntrack headroom. |
| VPN doctor | all of the above plus the live nft ruleset and `wg show dump` | See below. |

## Doctors

Four checklists share one engine (`IDoctorCheck<TContext>` + `DoctorRunner`):
checks run concurrently with bounded parallelism, each has its own deadline, and
a check that overruns or throws becomes a `Skip` instead of sinking the report.
All four render through the same `_DiagCheckList` partial and are persisted to
history like any other run.

| Doctor | Page | Answers |
|---|---|---|
| VPN | `/Diagnostics/Vpn` | Why does the tunnel show connected but carry nothing? |
| WAN | `/Diagnostics/Wan` | Why is traffic on the wrong uplink, or why did failover not fire? |
| DHCP | `/Diagnostics/Dhcp` | Why is this client not getting a lease? |
| DNS | `/Diagnostics/Dns` | Why can't the LAN resolve? |

### VPN doctor

`/Diagnostics/Vpn` runs ~24 checks concurrently (4 at a time, 6 s each, 25 s
total) against one memoised context, so twenty checks cost one `nft list ruleset`
and one `wg show dump`. Categories:

- **Config** — interface enabled, address is a valid host CIDR, `Table=off` when an
  upstream peer exists, peer roles coherent (upstream needs endpoint + key, site
  needs remote subnets), MTU sane.
- **Interface** — present, up, **live address == configured address**, live MTU,
  listen port, `wg show` fwmark off when Table=off.
- **Handshake** — per peer, using the shared `WgPeerHealthEvaluator`; a fresh
  handshake with `rx = 0` is flagged, because that is what "the far end drops us"
  looks like.
- **Path** — `ip route get <endpoint>`: must not loop back into the tunnel, should
  leave via a WAN.
- **Policy routing** — the `ip rule` for the tunnel mark exists and points at the
  tunnel's table; that table is **not empty** and has `default dev <iface>`;
  `ip route get <probe> mark <m>` really selects the tunnel.
- **Firewall** (live ruleset, not the DB) — masquerade out the tunnel, LAN ↔ tunnel
  forwarding, inbound listener accepted, **no interface matched by index**, **no
  unconstrained `meta mark set`** catch-all, `[vpn-auto]` rows consistent with the peers.
- **Kernel** — the sysctl checks above, scoped to the tunnel.
- **Journal** — drops and martians mentioning the interface in the last 30 min.

Two hands-on tools sit beside the checklist:

- **Data-plane probe** — reads `wg show transfer`, pings by mark and/or bound to the
  interface, reads the counters again, and classifies: `ok` · `remote-drops`
  (tx grows, rx flat → our source is not in their AllowedIPs) · `local-routing`
  (nothing entered the tunnel) · `replies-dropped` (both counters move, no replies
  → rp_filter or INPUT) · `no-interface` · `inconclusive`.
- **Compare with issued config** — paste the wg-quick config the remote admin sent;
  it diffs Address, their server key against the key we dial, endpoint, AllowedIPs
  and MTU. Private and preshared keys are stripped in the Web **and** again in the
  daemon, and never reach `diag_runs`.

### WAN doctor

A dual-WAN box fails in the gap between three sources of truth — the database,
the kernel's policy routing, and what the health monitor believes — so the
checks compare all three:

- **Inventory / link** — interfaces typed WAN, their roles, carrier, addressing
  and interface error counters.
- **Failover config** — `wan_health_config` must exist and cover every WAN, with
  monitor targets and a probe fwmark. An empty table is a **Fail**: that exact
  state once meant failover could never fire, however dead a WAN was.
- **Monitor verdict** — the recorded state per WAN, and whether it is stale
  (nothing probed in 5 minutes means the monitor is not running).
- **Per-WAN routing** — an `ip rule` exists for each probe mark, and
  `ip route get <target> mark <m>` really leaves via that WAN. Without this a
  probe silently measures the wrong uplink.
- **Default-route owner** — the `main` default route must agree with the WAN the
  failover controller considers active; a manual override is reported as a Warn
  because it freezes automatic failover.
- **Reachability** — a live ping per WAN, by **mark** rather than `-I`, because
  policy routing ignores a bind.

### DHCP doctor

The DHCP server is installed opt-in, so "not deployed" is a Skip, not a failure.

- **Service** — unit active and enabled at boot; something bound to UDP/67 (a
  raw-socket-only deployment is a Warn, since it can still work).
- **Scopes** — every enabled subnet is bound to an interface, and that interface
  actually carries an address inside the subnet. Otherwise the server offers
  addresses on a network it is not attached to.
- **Pools** — each subnet has an enabled pool with a sane range, and pool
  pressure (active leases vs capacity) warns at 80 % and fails at 95 %.
- **Activity** — active leases exist and something has renewed recently.
- **Firewall** — the input chain accepts udp/67, or client DISCOVERs never reach
  the server.

### DNS doctor

Queries are sent as **raw DNS over UDP from the daemon**, not through `dig`:
dnsutils is not a dependency of this appliance.

- **Service** — a resolver unit (unbound/dnsmasq/named) is active and enabled.
- **Listeners** — something listens on 53; loopback-only binding is a Fail
  because no LAN client can reach it, and UDP-only is a Warn.
- **Resolution** — a real A query answered locally, and the same query sent to
  **each LAN address exactly as a client would**, which catches both a bad bind
  and a firewall rule blocking 53. SERVFAIL and REFUSED get their own messages.
- **Firewall** — rules that accept or DNAT port 53.
- **Upstreams** — public resolvers are reachable at all; when they are not, the
  finding points at the WAN doctor, because that is an uplink problem.

## Authorisation

| Action | Who | Step-up |
|---|---|---|
| Every read-only tool (ping … VPN doctor) | Admin, Operator | no |
| Purge history | Admin | yes (TOTP) |
| Flow inspector, packet capture | Admin | yes (TOTP) |

Audit events: `diag.run` per tool run, `diag.denied` when the concurrency gate
refused one, `diag.purge` on a history purge, and `diag.trace.started`,
`diag.capture.started`, `diag.capture.downloaded`, `diag.job.cancelled` for the
invasive tools.

## History

`diag_runs` (migration `00041`) keeps who ran what, with which parameters, the
result JSON and the duration. `/Diagnostics/History` filters by tool, status, date
and "only my runs", and the drawer renders the **same partial** the live run used.
Results above 1 MiB are replaced by a truncation marker. Retention is
`diagnostics.history_retention_days` (default 30, `0` = keep forever), pruned by a
background service in the daemon every 6 h.

Status meanings: `ok` / `warn` / `fail` mean the tool ran and that is its verdict
(a ping with 100 % loss is `fail`, not `error`); `error`, `timeout` and `busy` mean
it did not complete.

## Settings

`diagnostics.history_retention_days`, `diagnostics.doctor_budget_seconds` (10–25,
must stay under the 30 s daemon-client timeout), `diagnostics.probe_default_target`,
`diagnostics.journal_max_lines`, `diagnostics.capture_retention_hours`.

## Invasive tools

Two tools change the box while they run, so they are **Admin only, behind TOTP
step-up**, audited at start, cancel and download, and limited to **one at a time
box-wide** by an in-memory job registry. They outlive a request: the daemon runs
them as jobs and the page polls until they finish.

### Flow inspector (`/Diagnostics/trace`)

Answers "which rule decided this packet's fate?". It creates a table of its own,
`ip netfw_diag`, with prerouting and output chains at priority **-300** (the raw
hook, before conntrack and before any of your tables), whose only rule sets
`nftrace` on the packets you describe, then streams `nft monitor trace`.

Using our own table instead of editing your chains is deliberate: the enforced
ruleset is never touched, and cleanup is a single atomic `nft delete table` that
cannot leave half a rule behind. It runs in a `finally`, and
`DiagnosticsSweeperService` deletes the table again at daemon start in case the
process was killed mid-trace. If you ever see one by hand:

```bash
nft delete table ip netfw_diag
```

At least one matcher is required. An unfiltered trace marks every packet the
firewall handles — the daemon refuses it.

Results group by trace id: one block per packet, with the `packet` line, each
`rule` it was tested against, and the verdict as a badge.

### Packet capture (`/Diagnostics/capture`)

`timeout --signal=INT <sec> tcpdump -n -Z root -U -i <if> -c <n> -s <snap> -w <file> <filter>`.

- `timeout --signal=INT` is what makes it bounded **and** leaves a valid pcap:
  SIGINT is tcpdump's clean stop, while a plain kill truncates the file. Exit 124
  means the duration elapsed, which is a normal end.
- Filters are checked twice: a character allow-list (no quotes, `$`, backticks or
  semicolons) and a real `tcpdump -d` compile before any socket is opened.
- Files are named by job id under `/var/lib/netfirewall/daemon/captures`, so a
  request can never name a file. Retention is `diagnostics.capture_retention_hours`
  (default 24; these are raw payloads — keep it short).
- Snaplen 64 captures headers only, which is usually enough and records no payload.

**Deployment requirement:** capture needs `AF_PACKET` in the daemon unit's
`RestrictAddressFamilies` (`deploy/systemd/netfirewall-daemon.service`). It is
listed there now, with a comment saying why; remove it to disable captures
outright. `tcpdump` is a Recommends of the .deb and is in the ISO package list.

## Safety rules for new tools

1. **Argument vectors only.** Spawn through
   `IProcessRunner.RunAsync(file, IReadOnlyList<string> args, …)`. Interpolating a
   request value into the string overload is forbidden and
   `NoInterpolatedProcessArgsTest` fails the build if it sees one.
2. **Validate on both sides.** `IDiagnosticInputValidator` runs in the Web and again
   in the daemon; interface names must be in the live ∪ configured allow-list, and
   hostnames are resolved in-process so the binaries only see literal IPs.
3. **Go through `IDiagnosticRunner`.** It takes the gate slot, opens and closes the
   `diag_runs` row, applies the budget and maps timeouts. History is best-effort: a
   database hiccup must not stop a ping.
4. **Fail soft.** A doctor check that cannot determine something returns `Skip`,
   never an exception; off Linux everything degrades to `Skip` with a clear message.
5. **Clean up in a `finally`, and sweep at startup.** Anything a tool adds to the
   kernel must come back out even if the daemon is killed mid-run — that is why
   the tracer owns a whole table it can delete atomically.

## Extending

Add a doctor check by implementing `IVpnDoctorCheck` (or deriving from
`VpnDoctorCheckBase` for a single row) in
`NetFirewall.Services/Diagnostics/Vpn/Checks/`, then register it in the list in
`NetFirewall.Daemon/Program.cs`. Read state through `VpnDoctorContext` so your
check shares the memoised commands. Tests for the pure logic live in
`NetFirewall.Tests/Diagnostics/`.

Every doctor reuses `DiagReport`, `_DiagCheckList` and `DoctorRunner` — only the
checks and the context are new.

## Adding a doctor

Implement `IDoctorCheck<TContext>` (or `DoctorCheckBase<TContext>` for a single
row), gather state in a context whose accessors are memoised `Lazy<Task<T>>` so
twenty checks cost one command each, and hand both to `IDoctorRunner`. Register
the checks in `NetFirewall.Daemon/Program.cs`, add a tool id to `DiagTools`, an
endpoint, a client method, and a `DoctorPageViewModel` entry — the page and the
report rendering are already shared.
