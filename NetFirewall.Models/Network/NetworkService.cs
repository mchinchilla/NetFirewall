using RepoDb.Attributes;

namespace NetFirewall.Models.Network;

[Map("network_services")]
public class NetworkService
{
    [Map("id")]            public Guid     Id          { get; set; }
    [Map("name")]          public string   Name        { get; set; } = string.Empty;
    [Map("protocol")]      public string   Protocol    { get; set; } = NetworkServiceProtocols.Tcp;
    [Map("port_start")]    public int      PortStart   { get; set; }
    [Map("port_end")]      public int?     PortEnd     { get; set; }
    [Map("description")]   public string?  Description { get; set; }
    [Map("category")]      public string?  Category    { get; set; }
    [Map("is_builtin")]    public bool     IsBuiltin   { get; set; }
    [Map("created_at")]    public DateTime CreatedAt   { get; set; }
    [Map("updated_at")]    public DateTime UpdatedAt   { get; set; }

    /// <summary>Not persisted — populated when callers request group members.</summary>
    public List<NetworkService>? Members { get; set; }

    /// <summary>"22" for single ports, "10000-20000" for ranges.</summary>
    public string PortString => PortEnd.HasValue && PortEnd.Value != PortStart
        ? $"{PortStart}-{PortEnd}"
        : PortStart.ToString();
}

public static class NetworkServiceProtocols
{
    public const string Tcp     = "tcp";
    public const string Udp     = "udp";
    public const string TcpUdp  = "tcp+udp";
    public const string Icmp    = "icmp";

    public static readonly string[] All = [Tcp, Udp, TcpUdp, Icmp];
    public static bool IsValid(string p) => Array.IndexOf(All, p) >= 0;
}
