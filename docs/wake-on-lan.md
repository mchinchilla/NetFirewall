# Wake-on-LAN

Power on sleeping machines from the firewall: **Network → Wake-on-LAN**, or the
**Wake** button on any DHCP reservation or lease row.

## How a wake travels

```
Web (zero caps)                         daemon (root, CAP_NET_RAW)
  WakeOnLanController ──POST /v1/wol/wake──▶ WakeOnLanService
     validates form                            re-validates everything
                                               picks the LAN link
                                               UdpWolPacketSender
                                                 SO_BINDTODEVICE <link>
                                                 udp → 255.255.255.255:9  ×3
```

- **Payload**: the magic packet, 6 × `0xFF` + the MAC 16 times (102 bytes,
  `NetFirewall.Models/Wol/MagicPacket.cs`), sent three times 100 ms apart.
- **Why the daemon sends it**: the socket is bound to the chosen link with
  `SO_BINDTODEVICE`. A limited broadcast on a bound socket is routed straight
  out of that device with no FIB lookup, so the fwmark policy routing and the
  default route never decide where a wake goes.
- **Which link**: the request's interface when given; otherwise the LAN link
  whose IPv4 subnet holds the request's IP hint (a DHCP row posts its IP),
  longest prefix wins. With neither, the request is refused.
- **Refused links**: anything `fw_interfaces` types as `WAN` or `VPN`, plus `lo`,
  and any link that is down or has no carrier.
- **Who**: Admin and Operator, no step-up (a wake changes no state on the box).
  Every attempt is audited as `wol.sent` / `wol.failed` in `auth_audit_log`.

## Saved devices

`wol_devices` (migration `00042_wol_devices.sql`): name, MAC (`macaddr`, unique),
interface, UDP port (default 9), description, last woken at/by. The list joins
DHCP by MAC to show the reserved (else last-leased) IP and hostname, and rows are
in the global search (`entity_type = 'wol_device'`).

**Status** is the firewall's ARP table (`GET /v1/diagnostics/neighbors`),
re-read every 15 s and swapped into the badges out-of-band:

| Badge | Neighbour state | Meaning |
|---|---|---|
| online | REACHABLE / PERMANENT | answered within ~30 s |
| checking | DELAY / PROBE | the kernel is re-checking it |
| idle | STALE | remembered, not confirmed — a sleeping machine looks like this too |
| offline | FAILED / INCOMPLETE | did not answer ARP |
| not seen | — | not in the table |

## If nothing wakes up

1. WoL enabled in the BIOS/UEFI ("Wake on LAN", "Power on by PCI-E").
2. Windows: adapter → Power Management → "Wake on Magic Packet"; turn Fast
   Startup off (it leaves the NIC unpowered after shutdown).
3. The machine must be wired and on standby power; most Wi-Fi adapters never listen.
4. Check the audit row and the toast: the interface and subnet it went out on
   are part of the success message.
5. Watch it on the wire from the firewall:
   `tcpdump -ni <lan-if> 'udp port 9 and ether broadcast'`
   (or Diagnostics → Packet capture with filter `udp port 9`).

## Deploying

Apply migration 00042 **before** deploying the new Web binaries (the page reads
`wol_devices`). No systemd unit change: the daemon already runs with
`CAP_NET_RAW` and `AF_INET` allowed.
