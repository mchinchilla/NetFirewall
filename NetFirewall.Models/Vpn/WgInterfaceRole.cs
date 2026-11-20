namespace NetFirewall.Models.Vpn;

/// <summary>What an interface actually does, read from its data (not from wg_servers.mode).</summary>
public enum WgRole
{
    /// <summary>Accepts connections: a listen port, road-warrior clients or sites that dial in.</summary>
    Server,
    /// <summary>Dials out: a provider (upstream) or a remote site it connects to.</summary>
    Outbound,
    /// <summary>Both at once — a legacy single wg0 (it can be split).</summary>
    DualRole,
    /// <summary>Nothing configured yet.</summary>
    Empty,
}

/// <summary>
/// Classifies an interface from its listen port and peers. wg_servers.mode was "legacy, preserved"
/// from migration 00036 until the per-role redesign, so an old wg0 may say 'client' while it also
/// listens for road warriors — deciding by mode hid its clients and its shared tunnels. Pure.
/// </summary>
public static class WgInterfaceRole
{
    public static WgRole Classify(WgServer server, IReadOnlyCollection<WgPeer> peers)
    {
        var accepts = server.ListenPort > 0
                      || peers.Any(p => p.Role is "client" || (p.Role is "site" && string.IsNullOrWhiteSpace(p.Endpoint)));
        var dials = peers.Any(p => p.Role is "upstream" || (p.Role is "site" && !string.IsNullOrWhiteSpace(p.Endpoint)));
        return (accepts, dials) switch
        {
            (true, true) => WgRole.DualRole,
            (true, false) => WgRole.Server,
            (false, true) => WgRole.Outbound,
            _ => string.Equals(server.Mode, "client", StringComparison.OrdinalIgnoreCase) ? WgRole.Outbound : WgRole.Server,
        };
    }

    /// <summary>Hosts the remote-access server (alone or alongside outbound tunnels).</summary>
    public static bool IsServerSide(WgRole role) => role is WgRole.Server or WgRole.DualRole;

    /// <summary>The name for a new server interface: wg0 unless taken, then wg1, wg2 …</summary>
    public static string NextServerName(IEnumerable<string> taken)
    {
        var used = taken.ToHashSet(StringComparer.Ordinal);
        for (var n = 0; ; n++)
            if (!used.Contains($"wg{n}")) return $"wg{n}";
    }
}
