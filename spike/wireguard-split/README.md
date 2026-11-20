# WireGuard split — real-kernel feasibility

Proves, on kernel WireGuard, the assumptions behind splitting a dual-role `wg0`
(`WireGuardSplitPlanner` / `WireGuardSplitService`):

1. Two interfaces can share **one private key** — one listening (VPN server), one dialling (provider).
2. The **listen port can be handed over**: `wg0` drops to an ephemeral port, the new server binds it.
3. The provider tunnel survives (it sees our new source port and roams).
4. Road warriors keep their **unchanged** configs; one with an active session is cut until it
   re-handshakes — **~16 s** measured.

Three network namespaces (fw, provider, laptop) inside one privileged container:

```bash
docker run --rm --privileged -v "$PWD/spike/wireguard-split:/t:ro" debian:trixie bash /t/split.sh
# … RESULT: ALL PASS
```

Measured 2026-11-20 on Docker Desktop (Linux 7.0 linuxkit, arm64).
