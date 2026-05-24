namespace NetFirewall.Models.Network;

/// <summary>
/// Wire format for the daemon's <c>/v1/dns/apply</c> endpoint. Used by the
/// Web's Setup Wizard to ask the daemon to render an unbound conf and restart
/// the service. Kept as a flat record so JSON round-trips are trivial.
/// </summary>
public sealed record DnsForwarderConfig
{
    /// <summary>When false the daemon writes an empty conf (i.e. unbound passes through to system defaults) and leaves the service stopped.</summary>
    public bool Enabled { get; init; }

    /// <summary>Primary upstream resolver (required when Enabled).</summary>
    public string? UpstreamDns1 { get; init; }

    /// <summary>Secondary upstream — optional.</summary>
    public string? UpstreamDns2 { get; init; }

    /// <summary>UDP/TCP listen port; defaults to 53.</summary>
    public int ListenPort { get; init; } = 53;

    /// <summary>
    /// CIDRs that are allowed to query the resolver. Defaults to RFC1918 + link-local
    /// when null/empty (typical LAN-only firewall setup).
    /// </summary>
    public IReadOnlyList<string>? AllowedClients { get; init; }
}
