using System.Net;
using System.Net.Sockets;
using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics.Vpn.Checks;

// Config checks read the DB only — no processes — so they always run, even off-Linux.

public sealed class ServerConfigCheck : VpnDoctorCheckBase
{
    public override string Id => "cfg.server";
    public override string Category => "Config";
    public override string Title => "WireGuard interface";

    protected override Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var s = ctx.Server;
        var peers = ctx.EnabledPeers.Count();
        return Task.FromResult(s.Enabled
            ? Pass($"{s.Name} configured and enabled · {peers} enabled peer{(peers == 1 ? "" : "s")}.")
            : Warn($"{s.Name} is configured but disabled — nothing will be applied.", VpnRemedies.ServerForm("Tick Enabled and Apply VPN.")));
    }
}

public sealed class AddressConfigCheck : VpnDoctorCheckBase
{
    public override string Id => "cfg.address";
    public override string Category => "Config";
    public override string Title => "Tunnel address";

    protected override Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var cidr = ctx.Server.AddressCidr;
        var slash = cidr.IndexOf('/');
        var ipPart = slash < 0 ? cidr : cidr[..slash];
        if (!IPAddress.TryParse(ipPart, out var ip) || (slash >= 0 && !int.TryParse(cidr[(slash + 1)..], out _)))
            return Task.FromResult(Fail($"'{cidr}' is not a valid address/CIDR.", VpnRemedies.ServerForm()));

        var prefix = slash < 0 ? (ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128) : int.Parse(cidr[(slash + 1)..]);
        if (ip.AddressFamily == AddressFamily.InterNetwork && prefix < 32)
        {
            var bytes = ip.GetAddressBytes();
            var value = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
            var hostBits = 32 - prefix;
            if ((value & ((1u << hostBits) - 1)) == 0)
                return Task.FromResult(Fail($"{cidr} is the network address, not a host address.", VpnRemedies.ServerForm("Use the first usable host, e.g. .1 or .2.")));
        }
        return Task.FromResult(Pass($"{cidr}" + (prefix == 32 ? " (point-to-point /32)" : string.Empty)));
    }
}

public sealed class TableOffCheck : VpnDoctorCheckBase
{
    public override string Id => "cfg.table_off";
    public override string Category => "Config";
    public override string Title => "Table = off";

    protected override Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var hasUpstream = ctx.UpstreamPeers.Any();
        if (hasUpstream && !ctx.Server.TableOff)
            return Task.FromResult(Fail("An upstream peer with a broad AllowedIPs exists but Table=off is not set — wg-quick would install its own default route and hijack the firewall's outbound.",
                VpnRemedies.ServerForm("Tick 'Table = off' (the controller forces it when saving with an upstream peer) and Apply VPN.")));
        return Task.FromResult(Pass(ctx.Server.TableOff
            ? "Table=off — policy routing owns the tunnel route."
            : "No upstream peer; wg-quick may manage routes for this interface."));
    }
}

public sealed class PeerRolesCheck : VpnDoctorCheckBase
{
    public override string Id => "cfg.peer_roles";
    public override string Category => "Config";
    public override string Title => "Peer roles";

    protected override Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct)
    {
        var problems = new List<(string Msg, bool Fatal, Guid PeerId)>();
        foreach (var p in ctx.EnabledPeers)
        {
            if (VpnDoctorContext.IsRole(p, "upstream"))
            {
                if (string.IsNullOrWhiteSpace(p.Endpoint)) problems.Add(($"'{p.Name}' (upstream) has no Endpoint — nothing to dial.", true, p.Id));
                if (string.IsNullOrWhiteSpace(p.PublicKey)) problems.Add(($"'{p.Name}' (upstream) has no public key.", true, p.Id));
                if (p.AllowedIps.Length == 0) problems.Add(($"'{p.Name}' (upstream) has empty AllowedIPs — WireGuard will drop everything it receives.", true, p.Id));
            }
            else if (VpnDoctorContext.IsRole(p, "site"))
            {
                if (p.AllowedSubnets.Length == 0 && !p.AllowedIps.Any(a => !a.EndsWith("/0", StringComparison.Ordinal)))
                    problems.Add(($"'{p.Name}' (site) has no remote LAN subnets — no forward rules can be scoped, none are generated.", false, p.Id));
            }
            else
            {
                if (!p.AllowedIps.Any(a => a.EndsWith("/32", StringComparison.Ordinal) || a.EndsWith("/128", StringComparison.Ordinal)))
                    problems.Add(($"'{p.Name}' (client) has no /32 tunnel address in AllowedIPs.", false, p.Id));
            }
        }

        if (problems.Count == 0)
            return Task.FromResult(Pass($"{ctx.EnabledPeers.Count()} peer(s) have coherent role, endpoint and AllowedIPs."));

        var detail = string.Join('\n', problems.Select(p => "• " + p.Msg));
        var first = problems[0];
        return Task.FromResult(problems.Any(p => p.Fatal)
            ? Fail($"{problems.Count} peer configuration problem(s).", VpnRemedies.PeerForm(first.PeerId), detail)
            : Warn($"{problems.Count} peer configuration warning(s).", VpnRemedies.PeerForm(first.PeerId), detail));
    }
}

public sealed class MtuConfigCheck : VpnDoctorCheckBase
{
    public override string Id => "cfg.mtu";
    public override string Category => "Config";
    public override string Title => "MTU";

    protected override Task<DiagCheck> CheckAsync(VpnDoctorContext ctx, CancellationToken ct) =>
        Task.FromResult(ctx.Server.Mtu switch
        {
            null => Pass("Default (wg-quick derives 1420 from the underlying link)."),
            < 1280 => Fail($"MTU {ctx.Server.Mtu} is below the IPv6 minimum (1280).", VpnRemedies.ServerForm()),
            > 1420 => Warn($"MTU {ctx.Server.Mtu} leaves no room for the WireGuard header over a 1500-byte WAN (PPPoE/PMTU black holes).", VpnRemedies.ServerForm("1420 is the safe default; 1412 over PPPoE.")),
            _ => Pass($"MTU {ctx.Server.Mtu}."),
        });
}
