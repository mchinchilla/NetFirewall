using System.ComponentModel.DataAnnotations;
using NetFirewall.Models.Vpn;

namespace NetFirewall.Web.Models.Vpn;

/// <summary>One outbound connection = one client-kind interface and its single remote peer.</summary>
public sealed record OutboundConnectionCard(WgServer Interface, WgPeer? Remote)
{
    public bool IsProvider => Remote?.Role == "upstream";
    public string Title => Remote?.Name ?? Interface.Name;
    public string KindLabel => IsProvider ? "VPN provider" : "Site-to-site";
}

/// <summary>Tunnels still living on the remote-access server's interface (pre-split dual-role wg0).</summary>
public sealed record SharedInterfaceTunnels(WgServer Interface, IReadOnlyList<WgPeer> Tunnels);

public sealed class OutboundConnectionsPageViewModel
{
    public IReadOnlyList<OutboundConnectionCard> Connections { get; init; } = [];
    public SharedInterfaceTunnels? Shared { get; init; }
    public string? CreatedName { get; init; }
    public string? DeletedName { get; init; }
    public bool DeleteApplyWarn { get; init; }

    /// <summary>Pure: split every interface into outbound cards + tunnels still sharing the server interface.</summary>
    public static OutboundConnectionsPageViewModel From(
        IReadOnlyList<(WgServer Server, IReadOnlyList<WgPeer> Peers)> all,
        string? created, string? deleted, bool applyWarn)
    {
        var cards = all
            .Where(x => string.Equals(x.Server.Mode, "client", StringComparison.OrdinalIgnoreCase))
            .Select(x => new OutboundConnectionCard(x.Server, x.Peers.FirstOrDefault()))
            .ToList();
        var shared = all
            .Where(x => string.Equals(x.Server.Mode, "server", StringComparison.OrdinalIgnoreCase))
            .Select(x => new SharedInterfaceTunnels(x.Server, x.Peers.Where(p => p.Role == "upstream").ToList()))
            .FirstOrDefault(x => x.Tunnels.Count > 0);
        return new() { Connections = cards, Shared = shared, CreatedName = created, DeletedName = deleted, DeleteApplyWarn = applyWarn };
    }
}

/// <summary>The "New connection" drawer: the wg-quick text the provider / remote site issued.</summary>
public sealed class OutboundConnectionFormViewModel
{
    [Required(ErrorMessage = "Paste the WireGuard configuration you were given.")]
    [StringLength(16 * 1024, MinimumLength = 40, ErrorMessage = "That does not look like a WireGuard configuration (16 KB max).")]
    public string ConfigText { get; set; } = string.Empty;

    [StringLength(64, ErrorMessage = "Keep the name under 64 characters.")]
    [RegularExpression(@"^[^<>\r\n]*$", ErrorMessage = "The name cannot contain < > or line breaks.")]
    public string? Label { get; set; }
}

public sealed record InterfaceOutcomeStripModel(string? Name, bool Deleted, bool ApplyWarn = false);
