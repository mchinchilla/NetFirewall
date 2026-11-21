# NetFirewall DHCP — feature status

Status of the DHCPv4 server (`NetFirewall.DhcpServer` + `NetFirewall.Services/Dhcp`) against
what operators of pfSense / OPNsense (Kea), dnsmasq and MikroTik rely on. Full review
2026-11-20: every row was checked in the code, not taken from earlier versions of this file
(which compared against ISC-DHCP, now end-of-life, and had gone stale). Updated 2026-11-21:
PRL/57, per-host lease time, HTTP/ARM64 boot, trusted relays, rate limit, MAC block list.

**Legend:** ✅ complete (server + config/UI) · 🟡 partial · ⛔ disabled on purpose · ❌ missing

## Core protocol (RFC 2131 / 2132)

| Feature | Status | Notes |
|---|---|---|
| DISCOVER / OFFER / REQUEST / ACK / NAK / RELEASE / DECLINE / INFORM | ✅ | NAK only ever answers a REQUEST; internal errors are answered with silence (a NAK drops a renewing client's address). |
| REQUEST validation (wrong network → NAK) | ✅ | `CheckRequestedIpAsync`: subnet, pools, exclusions, network/broadcast/router. |
| Address stability | ✅ | DISCOVER re-offers the current lease, then option 50, then the pool. |
| Offer hold | ✅ | 60 s, so two clients booting together never get the same address. |
| Conflict detection | ✅ | DECLINE quarantine (1 h) + ICMP ping before offering a new address (`Dhcp:PingCheck`). |
| Reply addressing (§4.1) | ✅ | giaddr → relay:67; ciaddr → unicast; else broadcast. Replies padded to 300 B. |
| Server identifier | ✅ | Our address on the receiving interface (not the subnet's gateway). |
| Client identifier (61) | 🟡 | Echoed (RFC 6842); leases are still keyed by MAC, not client-id. |
| Max message size (57) / PRL (55) | ✅ | With a request list, only what was asked for is sent, plus 53/54/1/3/51/58/59, the 61/82 echoes and the boot options for a boot client. Without one, everything configured is sent. Replies fit in 57 (548 bytes without it, per RFC 2131); optional options that don't fit are dropped and logged. Custom options are not filtered by 55 (there is no "always send" flag yet), but requested ones go first. |
| Option overload (52), FORCERENEW, LEASEQUERY | ❌ | |

## Configuration

| Feature | Status | Notes |
|---|---|---|
| Multiple subnets / interfaces, pools, exclusions | ✅ | One raw socket per interface; a bad interface is skipped, the rest keep serving. |
| Standard options 1/3/6/15/26/28/42/44/46/2/100/119/121, 51/58/59 | ✅ | 121 always carries a default route (RFC 3442). |
| Custom options (any code, typed) | ✅ | DHCP → Custom options. Global / subnet / class / reserved device; most specific wins. |
| Static mappings (reservations) | ✅ | With a DNS host name; "Reserve" button on a lease. |
| Client classes | ✅ | All 8 match types (vendor/user class, MAC prefix, hardware type, client id, hostname, relay info, generic option). |
| Pool allow/deny per class, known-clients-only | ✅ | |
| Per-host lease time / per-host options | ✅ | A reservation may carry its own lease time (60 s – 1 year); empty = the subnet's default. Options at host scope. |

## Network services

| Feature | Status | Notes |
|---|---|---|
| Relay agents (giaddr) | ✅ | giaddr wins over the receiving interface. |
| Option 82 / trusted relays | ✅ | Echoed verbatim (RFC 3046). DHCP → Access control lists relays: once one is trusted, other relays are dropped and option 82 on direct packets (giaddr 0, as inserted by snooping switches) is still answered and echoed, but can't pick a class or pool. A relay marked refused is always dropped. No relays listed = no change. |
| PXE BIOS/UEFI | ✅ | Option 93 (or "Arch:" in 60) picks the BIOS or UEFI file; replies carry 60 "PXEClient" + 43. |
| iPXE chainloading | ✅ | User class "iPXE" gets `boot_filename_ipxe` (breaks the loop). |
| HTTP boot, ARM-specific boot files | ✅ | UEFI HTTP boot (60 "HTTPClient…") gets the subnet's HTTP URI in option 67 with 60 "HTTPClient" and no 43; no URI = a plain offer. ARM64 UEFI (arch 11) gets its own TFTP file, falling back to the UEFI file. Other architectures (ARM32, RISC-V, …) through a class with an option-93 match. |
| Hostnames in the firewall's DNS | ✅ | Leases + reservations published to Unbound (`ping nas.home.lan`). |
| Dynamic DNS to an external server (RFC 2136/TSIG) | ✅ | Off the packet path (`DdnsUpdateQueue`). Reverse zone assumes /24. |

## Operations

| Feature | Status | Notes |
|---|---|---|
| Lease export | ✅ | Grid export (CSV/xlsx). |
| Lease history | ✅ | Who had which address, when — 90 days. |
| Pool-exhaustion alerts | ✅ | Banner at 85 % / 95 %. |
| Rogue DHCP server detection | ✅ | Passive: replies from another server seen on a LAN raise an alert. |
| Rate limiting / DoS protection | ✅ | Per-MAC token bucket in the receive loop, before the queue (burst 20, then 2/s; `Dhcp:RateLimit:{Enabled,Burst,PerSecond}`). Fixed 4096-slot table: spoofed-MAC floods evict entries, never grow memory. Drops are counted in the stats line. Plus the bounded drop-oldest queue. |
| MAC block list | ✅ | DHCP → Access control. A blocked MAC gets no reply to anything; blocking releases its lease. |
| Failover / HA | ⛔ | The peer protocol has no listener; enabling it would stop DHCP on both boxes, so it is disabled. |
| Event hooks (`dhcp_events`) | ❌ | Schema only. |
| DHCPv6 / Router Advertisements | ❌ | IPv4 only. |

## Performance

About 0.85 µs and 2.4 KB of CPU work per packet (full pipeline, `FullPipelineBenchmarks`,
2026-11-21; was 0.9 µs / 2.8 KB before options were written through a stack scratch buffer), so
the server is bound by its database writes, which are set-based write-behind (`LeaseFlushBenchmarks`).
On .NET 11, BenchmarkDotNet's SDK validator doesn't recognise the runtime: run with `--inProcess`.
See `NetFirewall.Benchmarks/README.md`.
