using System.Net;
using System.Net.Sockets;
using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics.Doctors.Dhcp;

public sealed class DhcpUnitCheck : DhcpDoctorCheckBase
{
    public override string Id => "dhcp.unit";
    public override string Category => "Service";
    public override string Title => "DHCP server unit";

    protected override async Task<DiagCheck> CheckAsync(DhcpDoctorContext ctx, CancellationToken ct)
    {
        var unit = await ctx.DhcpUnitAsync();
        if (unit is null || string.Equals(unit.ActiveState, "not-found", StringComparison.OrdinalIgnoreCase))
            return Skip("The DHCP server is not deployed on this host (it is opt-in at install time).");

        var detail = $"{unit.UnitName} · {unit.ActiveState}/{unit.SubState} · {(unit.Enabled ? "enabled" : "not enabled at boot")}";
        if (!string.Equals(unit.ActiveState, "active", StringComparison.OrdinalIgnoreCase))
            return Fail($"{unit.UnitName} is {unit.ActiveState} — no client will get a lease.", DhcpRemedies.Service(), detail);

        return unit.Enabled
            ? Pass($"{unit.UnitName} active since {unit.SinceUtc:HH:mm} UTC.", detail)
            : Warn($"{unit.UnitName} is running but not enabled — it will not come back after a reboot.", DhcpRemedies.Service("systemctl enable netfirewall-dhcp"), detail);
    }
}

public sealed class DhcpListenerCheck : DhcpDoctorCheckBase
{
    public override string Id => "dhcp.listener";
    public override string Category => "Service";
    public override string Title => "Bound to UDP/67";

    protected override async Task<DiagCheck> CheckAsync(DhcpDoctorContext ctx, CancellationToken ct)
    {
        var unit = await ctx.DhcpUnitAsync();
        if (unit is null || !string.Equals(unit.ActiveState, "active", StringComparison.OrdinalIgnoreCase))
            return Skip("The DHCP server is not running.");

        var listeners = await ctx.UdpListenersAsync();
        if (string.IsNullOrWhiteSpace(listeners)) return Skip("Could not read the UDP listener table (ss).");

        var bound = listeners.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Any(l => l.Contains(":67 ", StringComparison.Ordinal) || l.TrimEnd().EndsWith(":67", StringComparison.Ordinal));
        var evidence = new[] { new DiagEvidence("ss -lunp", listeners.Trim()) };

        // The server also uses AF_PACKET for L2 receive, which never shows as a UDP
        // bind — so a missing :67 is suspicious, not conclusive.
        return bound
            ? Pass("Something is bound to UDP/67.", evidence: evidence)
            : Warn("Nothing is bound to UDP/67. A raw-socket-only deployment can still work, but normally the server binds it.",
                DhcpRemedies.Service(), evidence: evidence);
    }
}

public sealed class DhcpSubnetSanityCheck : IDhcpDoctorCheck
{
    public string Id => "dhcp.subnet";
    public string Category => "Scopes";

    public async Task<IReadOnlyList<DiagCheck>> RunAsync(DhcpDoctorContext ctx, CancellationToken ct)
    {
        var subnets = (await ctx.SubnetsAsync()).Where(s => s.Enabled).ToList();
        if (subnets.Count == 0)
            return [DiagCheck.Fail(Id, Category, "Subnets", "No enabled DHCP subnet — the server has nothing to hand out.", DhcpRemedies.Subnets())];

        var links = await ctx.LinksAsync();
        var interfaces = await ctx.InterfacesAsync();
        var rows = new List<DiagCheck>();

        foreach (var subnet in subnets)
        {
            var id = $"{Id}.{subnet.Name}";
            var title = $"Subnet {subnet.Name}";
            if (!TryParseCidr(subnet.Network, out var network, out var prefix))
            {
                rows.Add(DiagCheck.Fail(id, Category, title, $"'{subnet.Network}' is not a valid network.", DhcpRemedies.Subnets()));
                continue;
            }

            // The scope must live on an interface that actually carries that network,
            // or the server will answer for addresses it cannot reach.
            var iface = subnet.InterfaceId is { } ifid ? interfaces.FirstOrDefault(i => i.Id == ifid) : null;
            if (iface is null)
            {
                rows.Add(DiagCheck.Warn(id, Category, title, $"{subnet.Network} is not bound to an interface — the server has to guess which link it serves.",
                    DhcpRemedies.Subnets("Set the subnet's interface.")));
                continue;
            }

            var link = links.FirstOrDefault(l => l.Name == iface.Name);
            var onLink = link?.Addresses
                .Select(a => a.Split('/')[0])
                .Any(a => IPAddress.TryParse(a, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork && SameNetwork(ip, network, prefix)) ?? false;
            var detail = $"interface {iface.Name} · addresses {(link is null ? "unknown" : string.Join(", ", link.Addresses))}";

            rows.Add(onLink
                ? DiagCheck.Pass(id, Category, title, $"{subnet.Network} served on {iface.Name}.", detail)
                : DiagCheck.Fail(id, Category, title,
                    $"{iface.Name} has no address inside {subnet.Network}. The server would offer addresses on a network it is not attached to, and clients would never reach the gateway.",
                    DhcpRemedies.Subnets(), detail));
        }
        return rows;
    }

    internal static bool TryParseCidr(string cidr, out IPAddress network, out int prefix)
    {
        network = IPAddress.None; prefix = 0;
        var parts = (cidr ?? string.Empty).Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var ip) || !int.TryParse(parts[1], out prefix)) return false;
        if (ip.AddressFamily != AddressFamily.InterNetwork || prefix is < 0 or > 32) return false;
        network = ip;
        return true;
    }

    internal static bool SameNetwork(IPAddress a, IPAddress network, int prefix)
    {
        if (prefix == 0) return true;
        var ab = a.GetAddressBytes(); var nb = network.GetAddressBytes();
        var mask = prefix == 32 ? uint.MaxValue : uint.MaxValue << (32 - prefix);
        var av = ((uint)ab[0] << 24) | ((uint)ab[1] << 16) | ((uint)ab[2] << 8) | ab[3];
        var nv = ((uint)nb[0] << 24) | ((uint)nb[1] << 16) | ((uint)nb[2] << 8) | nb[3];
        return (av & mask) == (nv & mask);
    }
}

public sealed class DhcpPoolCheck : IDhcpDoctorCheck
{
    public string Id => "dhcp.pool";
    public string Category => "Scopes";

    public async Task<IReadOnlyList<DiagCheck>> RunAsync(DhcpDoctorContext ctx, CancellationToken ct)
    {
        var subnets = (await ctx.SubnetsAsync()).Where(s => s.Enabled).ToList();
        if (subnets.Count == 0) return [DiagCheck.Skip(Id, Category, "Pools", "No enabled subnet.")];

        var pools = (await ctx.PoolsAsync()).Where(p => p.Enabled).ToList();
        var leases = await ctx.LeasesAsync();
        var rows = new List<DiagCheck>();

        foreach (var subnet in subnets)
        {
            var id = $"{Id}.{subnet.Name}";
            var title = $"Pool for {subnet.Name}";
            var mine = pools.Where(p => p.SubnetId == subnet.Id).ToList();
            if (mine.Count == 0)
            {
                rows.Add(DiagCheck.Fail(id, Category, title, $"{subnet.Name} has no enabled pool — the server can answer but has no address to give.", DhcpRemedies.Pools()));
                continue;
            }

            var capacity = mine.Sum(p => RangeSize(p.RangeStart, p.RangeEnd));
            if (capacity <= 0)
            {
                rows.Add(DiagCheck.Fail(id, Category, title, "The pool range is empty or inverted (start is above end).", DhcpRemedies.Pools()));
                continue;
            }

            var used = leases.Count(l => DhcpSubnetSanityCheck.TryParseCidr(subnet.Network, out var net, out var prefix)
                                         && DhcpSubnetSanityCheck.SameNetwork(l.IpAddress, net, prefix));
            var pct = 100.0 * used / capacity;
            var detail = string.Join('\n', mine.Select(p => $"• {p.Name ?? "(unnamed)"} {p.RangeStart}–{p.RangeEnd} ({RangeSize(p.RangeStart, p.RangeEnd)} addresses)"))
                         + $"\n{used} active lease(s) of {capacity}";

            rows.Add(pct switch
            {
                >= 95 => DiagCheck.Fail(id, Category, title, $"Pool is {pct:0}% used ({used}/{capacity}) — new clients will be refused.", DhcpRemedies.Pools("Widen the range or shorten the lease time."), detail),
                >= 80 => DiagCheck.Warn(id, Category, title, $"Pool is {pct:0}% used ({used}/{capacity}).", DhcpRemedies.Pools(), detail),
                _     => DiagCheck.Pass(id, Category, title, $"{used}/{capacity} addresses in use ({pct:0}%).", detail),
            });
        }
        return rows;
    }

    internal static long RangeSize(IPAddress? start, IPAddress? end)
    {
        if (start is null || end is null) return 0;
        if (start.AddressFamily != AddressFamily.InterNetwork || end.AddressFamily != AddressFamily.InterNetwork) return 0;
        var s = ToUInt(start); var e = ToUInt(end);
        return e >= s ? e - s + 1 : 0;
    }

    private static long ToUInt(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        return ((long)b[0] << 24) | ((long)b[1] << 16) | ((long)b[2] << 8) | b[3];
    }
}

public sealed class DhcpActivityCheck : DhcpDoctorCheckBase
{
    public override string Id => "dhcp.activity";
    public override string Category => "Activity";
    public override string Title => "Recent leases";

    protected override async Task<DiagCheck> CheckAsync(DhcpDoctorContext ctx, CancellationToken ct)
    {
        var unit = await ctx.DhcpUnitAsync();
        if (unit is null || !string.Equals(unit.ActiveState, "active", StringComparison.OrdinalIgnoreCase))
            return Skip("The DHCP server is not running.");

        var leases = await ctx.LeasesAsync();
        if (leases.Count == 0)
            return Warn("No active lease at all. If clients are connected, they are not getting addresses from this server.",
                DhcpRemedies.Leases());

        var newest = leases.Max(l => l.StartTime);
        var age = DateTime.UtcNow - newest;
        var detail = $"{leases.Count} active lease(s) · newest {newest:yyyy-MM-dd HH:mm} UTC";

        // Half a typical lease time with no renewal at all suggests the server stopped answering.
        return age > TimeSpan.FromHours(12)
            ? Warn($"{leases.Count} active lease(s), but the newest was handed out {age.TotalHours:0} h ago — no client has renewed recently.", DhcpRemedies.Leases(), detail)
            : Pass($"{leases.Count} active lease(s), newest {age.TotalMinutes:0} min ago.", detail);
    }
}

public sealed class DhcpFirewallCheck : DhcpDoctorCheckBase
{
    public override string Id => "dhcp.firewall";
    public override string Category => "Firewall";
    public override string Title => "DHCP allowed on the LAN";

    private readonly Firewall.INftApplyService _nft;

    public DhcpFirewallCheck(Firewall.INftApplyService nft) => _nft = nft;

    protected override async Task<DiagCheck> CheckAsync(DhcpDoctorContext ctx, CancellationToken ct)
    {
        var subnets = (await ctx.SubnetsAsync()).Where(s => s.Enabled).ToList();
        if (subnets.Count == 0) return Skip("No enabled subnet.");

        var ruleset = await _nft.GetCurrentRulesetAsync(ct);
        if (string.IsNullOrWhiteSpace(ruleset)) return Skip("Live ruleset unavailable.");

        var line = ruleset.Split('\n').Select(l => l.Trim())
            .FirstOrDefault(l => l.Contains("accept", StringComparison.Ordinal)
                                 && (l.Contains("dport { 67, 68 }", StringComparison.Ordinal)
                                     || l.Contains("dport 67", StringComparison.Ordinal)
                                     || l.Contains("dport { 67,68 }", StringComparison.Ordinal)));
        var evidence = new[] { new DiagEvidence("nft list ruleset | grep 'dport 67'", line ?? "(no match)") };

        return line is not null
            ? Pass("The input chain accepts DHCP (udp/67-68) from the LAN.", evidence: evidence)
            : Fail("No input rule accepts udp/67 — client DISCOVERs are dropped before the server ever sees them.",
                DhcpRemedies.FilterRules("Add an accept for udp 67-68 on the LAN interface."), evidence: evidence);
    }
}
