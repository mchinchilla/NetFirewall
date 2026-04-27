using RepoDb.Attributes;

namespace NetFirewall.Models.Network;

/// <summary>
/// One named, reusable address object — host, network, range, or group.
/// Filter / NAT / mangle rules reference these by <see cref="Name"/>.
/// </summary>
[Map("network_objects")]
public class NetworkObject
{
    [Map("id")]            public Guid     Id          { get; set; }
    [Map("name")]          public string   Name        { get; set; } = string.Empty;
    [Map("type")]          public string   Type        { get; set; } = NetworkObjectTypes.Host;
    [Map("value")]         public string   Value       { get; set; } = string.Empty;
    [Map("description")]   public string?  Description { get; set; }
    [Map("created_at")]    public DateTime CreatedAt   { get; set; }
    [Map("updated_at")]    public DateTime UpdatedAt   { get; set; }

    // Not persisted — populated by the service when callers request members.
    public List<NetworkObject>? Members { get; set; }
}

public static class NetworkObjectTypes
{
    public const string Host    = "host";
    public const string Network = "network";
    public const string Range   = "range";
    public const string Group   = "group";

    public static readonly string[] All = [Host, Network, Range, Group];

    public static bool IsValid(string t) => Array.IndexOf(All, t) >= 0;
}
