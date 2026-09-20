using NetFirewall.Models.Diagnostics;
using NetFirewall.Models.Vpn;

namespace NetFirewall.Services.Diagnostics.Vpn.Checks;

// Live-interface checks. Everything here compares the kernel against the DB —
// the class of bug that cost four rounds on tekium (address .3 vs issued .2).

public sealed class InterfaceExistsCheck : VpnDoctorCheckBase
{
    public override string Id => "if.exists";
    public override string Category => "Interface";
    public override string Title => "Interface present";

    protected override async Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var link = await ctx.LinkAsync();
        if (link is null) return Skip("Interface inspection is Linux-only.");
        return link.Exists
            ? Pass($"{ctx.Iface} exists.")
            : Fail($"{ctx.Iface} does not exist — the tunnel is stopped, so every live check below is meaningless.",
                VpnRemedies.ApplyVpn("Apply VPN brings the link up and re-installs its policy routes."));
    }
}

public sealed class InterfaceUpCheck : VpnDoctorCheckBase
{
    public override string Id => "if.up";
    public override string Category => "Interface";
    public override string Title => "Link state";

    protected override async Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var link = await ctx.LinkAsync();
        if (link is null) return Skip("Interface inspection is Linux-only.");
        if (!link.Exists) return Skip($"{ctx.Iface} is not present.");
        // WireGuard links report operstate "unknown" — that is normal and means up.
        return link.OperState is "down"
            ? Fail($"{ctx.Iface} is DOWN.", VpnRemedies.ApplyVpn())
            : Pass($"{ctx.Iface} is {link.OperState ?? "up"}.");
    }
}

public sealed class InterfaceAddressCheck : VpnDoctorCheckBase
{
    public override string Id => "if.address";
    public override string Category => "Interface";
    public override string Title => "Live address vs configured";

    protected override async Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var link = await ctx.LinkAsync();
        if (link is null) return Skip("Interface inspection is Linux-only.");
        if (!link.Exists) return Skip($"{ctx.Iface} is not present.");

        var configured = ctx.Server.AddressCidr.Trim();
        var live = link.Addresses.Where(a => !a.StartsWith("fe80:", StringComparison.OrdinalIgnoreCase)).ToList();
        var evidence = VpnDoctorContext.Evidence($"ip -4 -o addr show dev {ctx.Iface}", string.Join('\n', link.Addresses));

        if (live.Count == 0)
            return Fail($"{ctx.Iface} has no address; the configuration says {configured}.", VpnRemedies.ApplyVpn(), evidence: evidence);

        if (live.Any(a => SameAddress(a, configured)))
            return live.Count == 1
                ? Pass($"{live[0]} matches the configuration.", evidence: evidence)
                : Warn($"Configured address {configured} is present, plus {live.Count - 1} more: {string.Join(", ", live)}.",
                    VpnRemedies.ApplyVpn("A cold restart clears strays."), evidence: evidence);

        return Fail($"Live address {string.Join(", ", live)} ≠ configured {configured}. WireGuard sends from the live address, and the remote server drops anything outside the AllowedIPs it issued for us — this is a silent, total data-plane failure with a healthy handshake.",
            VpnRemedies.ApplyVpn("Apply VPN now restarts the link cold when the address drifts, which is the only way to move it."),
            evidence: evidence);
    }

    /// <summary>A bare address and its /32 (or /128) form are the same host address.</summary>
    internal static bool SameAddress(string a, string b)
    {
        static (string Ip, string Prefix) Split(string s)
        {
            var i = s.IndexOf('/');
            return i < 0 ? (s.Trim(), "") : (s[..i].Trim(), s[(i + 1)..].Trim());
        }
        var (ia, pa) = Split(a);
        var (ib, pb) = Split(b);
        if (!string.Equals(ia, ib, StringComparison.OrdinalIgnoreCase)) return false;
        if (string.Equals(pa, pb, StringComparison.Ordinal)) return true;
        var host = new[] { "", "32", "128" };
        return host.Contains(pa) && host.Contains(pb);
    }
}

public sealed class InterfaceMtuCheck : VpnDoctorCheckBase
{
    public override string Id => "if.mtu";
    public override string Category => "Interface";
    public override string Title => "Live MTU";

    protected override async Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var link = await ctx.LinkAsync();
        if (link is null) return Skip("Interface inspection is Linux-only.");
        if (!link.Exists) return Skip($"{ctx.Iface} is not present.");
        if (ctx.Server.Mtu is not { } want) return Pass($"Live MTU {link.Mtu?.ToString() ?? "?"} (no MTU configured).");
        return link.Mtu == want
            ? Pass($"MTU {want}.")
            : Warn($"Live MTU {link.Mtu?.ToString() ?? "?"} ≠ configured {want} — like the address, MTU only moves on a cold restart.", VpnRemedies.ApplyVpn());
    }
}

public sealed class ListenPortCheck : VpnDoctorCheckBase
{
    public override string Id => "if.listen_port";
    public override string Category => "Interface";
    public override string Title => "Listen port";

    protected override async Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var dump = await ctx.DumpAsync();
        if (dump is null) return Skip($"{ctx.Iface} is not present.");
        var configured = ctx.Server.ListenPort;
        var live = dump.ListenPort;

        if (configured == 0)
            return live is null or 0
                ? Pass("Dial-only interface (no inbound listener), as configured.")
                : Pass($"Kernel picked ephemeral port {live} (configured 0 = dial-only).");

        return live == configured
            ? Pass($"Listening on UDP {configured}.")
            : Fail($"Live listen port {live?.ToString() ?? "none"} ≠ configured {configured} — inbound peers cannot reach us.", VpnRemedies.ApplyVpn());
    }
}

public sealed class FwmarkOffCheck : VpnDoctorCheckBase
{
    public override string Id => "if.fwmark_off";
    public override string Category => "Interface";
    public override string Title => "WireGuard fwmark";

    protected override async Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var dump = await ctx.DumpAsync();
        if (dump is null) return Skip($"{ctx.Iface} is not present.");
        var evidence = VpnDoctorContext.Evidence($"wg show {ctx.Iface} dump", $"fwmark = {dump.Fwmark}");

        if (string.Equals(dump.Fwmark, "off", StringComparison.OrdinalIgnoreCase))
            return Pass("fwmark off — encrypted packets are routed normally.", evidence: evidence);

        return ctx.Server.TableOff
            ? Warn($"WireGuard set its own fwmark {dump.Fwmark} even though Table=off. Its encrypted packets carry that mark; if a policy rule sends that mark back into the tunnel you get a routing loop.",
                VpnRemedies.ApplyVpn("A cold restart re-reads the config."), evidence: evidence)
            : Pass($"fwmark {dump.Fwmark} (wg-quick manages this interface's routes).", evidence: evidence);
    }
}

public sealed class HandshakeCheck : IVpnDoctorCheck
{
    public string Id => "hs.peer";
    public string Category => "Handshake";

    public async Task<IReadOnlyList<DiagCheck>> RunAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var dump = await ctx.DumpAsync();
        if (dump is null)
            return [DiagCheck.Skip(Id, Category, "Handshakes", $"{ctx.Iface} is not present.")];

        var peers = ctx.EnabledPeers.ToList();
        if (peers.Count == 0)
            return [DiagCheck.Skip(Id, Category, "Handshakes", "No enabled peers.")];

        var rows = new List<DiagCheck>();
        foreach (var peer in peers)
        {
            var id = $"{Id}.{peer.Name}";
            var live = dump.Peers.FirstOrDefault(p => string.Equals(p.PublicKey, peer.PublicKey, StringComparison.Ordinal));
            var status = live is null ? null : new WgPeerLiveStatus(live.PublicKey, live.Endpoint, live.LatestHandshakeUtc, live.RxBytes, live.TxBytes);
            var health = WgPeerHealthEvaluator.Evaluate(peer, status, ctx.NowUtc);
            var expected = WgPeerHealthEvaluator.ExpectedLive(peer);
            var age = live?.LatestHandshakeUtc is { } h ? ctx.NowUtc - h : (TimeSpan?)null;
            var detail = live is null
                ? "Peer key is not loaded on the interface."
                : $"endpoint {live.Endpoint ?? "(none)"} · rx {live.RxBytes} B · tx {live.TxBytes} B" + (age is { } a ? $" · handshake {a.TotalSeconds:0} s ago" : " · never");

            rows.Add(health switch
            {
                WgPeerHealth.Connected when live is { RxBytes: 0 } && live.TxBytes > 0 =>
                    DiagCheck.Warn(id, Category, $"Peer {peer.Name}", "Handshake is fresh but nothing has come back — the far end may be discarding our packets.",
                        VpnRemedies.Compare("Run the data-plane probe, then compare with the issued config."), detail),
                WgPeerHealth.Connected => DiagCheck.Pass(id, Category, $"Peer {peer.Name}", $"Connected, last handshake {age?.TotalSeconds:0} s ago.", detail),
                WgPeerHealth.Idle      => DiagCheck.Pass(id, Category, $"Peer {peer.Name}", "Idle (client with no current session).", detail),
                WgPeerHealth.Pending   => DiagCheck.Warn(id, Category, $"Peer {peer.Name}", "Never handshaked yet — still within the grace period.", VpnRemedies.PeerForm(peer.Id), detail),
                _ when expected        => DiagCheck.Fail(id, Category, $"Peer {peer.Name}", "No recent handshake on a tunnel that should always be up.",
                                              VpnRemedies.PeerForm(peer.Id, "Check the endpoint and keys, then Apply VPN."), detail),
                _                      => DiagCheck.Skip(id, Category, $"Peer {peer.Name}", "Client peer not connected right now.", detail),
            });
        }
        return rows;
    }
}
