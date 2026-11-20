# NetFirewall DHCP — feature status

Status of the DHCPv4 server (`NetFirewall.DhcpServer` + `NetFirewall.Services/Dhcp`) against
what operators of pfSense / OPNsense (Kea), dnsmasq and MikroTik rely on. Updated 2026-11-20,
after a full review: every row was checked in the code, not taken from earlier versions of
this file (which compared against ISC-DHCP, now end-of-life, and had gone stale).

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
| Max message size (57) / PRL (55) | 🟡 | Parsed, not honoured: every configured option is sent. |
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
| Per-host lease time / per-host options | 🟡 | Options yes (host scope); lease time is per subnet. |

## Network services

| Feature | Status | Notes |
|---|---|---|
| Relay agents (giaddr) | ✅ | giaddr wins over the receiving interface. |
| Option 82 | 🟡 | Echoed verbatim (RFC 3046); usable in class matching. No trusted-relay list. |
| PXE BIOS/UEFI | ✅ | Option 93 (or "Arch:" in 60) picks the BIOS or UEFI file; replies carry 60 "PXEClient" + 43. |
| iPXE chainloading | ✅ | User class "iPXE" gets `boot_filename_ipxe` (breaks the loop). |
| HTTP boot, ARM-specific boot files | 🟡 | ARM/HTTP clients get the UEFI file. |
| Hostnames in the firewall's DNS | ✅ | Leases + reservations published to Unbound (`ping nas.home.lan`). |
| Dynamic DNS to an external server (RFC 2136/TSIG) | ✅ | Off the packet path (`DdnsUpdateQueue`). Reverse zone assumes /24. |

## Operations

| Feature | Status | Notes |
|---|---|---|
| Lease export | ✅ | Grid export (CSV/xlsx). |
| Lease history | ✅ | Who had which address, when — 90 days. |
| Pool-exhaustion alerts | ✅ | Banner at 85 % / 95 %. |
| Rogue DHCP server detection | ✅ | Passive: replies from another server seen on a LAN raise an alert. |
| Rate limiting / DoS protection | 🟡 | Bounded queue (drop-oldest); no per-MAC rate limit. |
| MAC deny list | 🟡 | Through a class + pool deny; no simple block list. |
| Failover / HA | ⛔ | The peer protocol has no listener; enabling it would stop DHCP on both boxes, so it is disabled. |
| Event hooks (`dhcp_events`) | ❌ | Schema only. |
| DHCPv6 / Router Advertisements | ❌ | IPv4 only. |

## Performance

About 0.9 µs and 2.7 KB of CPU work per packet (full pipeline, `FullPipelineBenchmarks`), so
the server is bound by its database writes, which are set-based write-behind (`LeaseFlushBenchmarks`).
.NET 10 and .NET 11 measure the same. See `NetFirewall.Benchmarks/README.md`.
