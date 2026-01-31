using System.Net;
using RepoDb.Attributes;

namespace NetFirewall.Models.Dhcp;

/// <summary>
/// Configuration for Dynamic DNS (RFC 2136) updates.
/// </summary>
[Map("dhcp_ddns_config")]
public class DdnsConfig
{
    [Map("id")]
    public Guid Id { get; set; }

    /// <summary>
    /// Associated subnet ID (null for global config)
    /// </summary>
    [Map("subnet_id")]
    public Guid? SubnetId { get; set; }

    /// <summary>
    /// Enable forward DNS updates (A/AAAA records)
    /// </summary>
    [Map("enable_forward")]
    public bool EnableForward { get; set; } = true;

    /// <summary>
    /// Enable reverse DNS updates (PTR records)
    /// </summary>
    [Map("enable_reverse")]
    public bool EnableReverse { get; set; } = true;

    /// <summary>
    /// Forward zone for A records (e.g., "example.com")
    /// </summary>
    [Map("forward_zone")]
    public string? ForwardZone { get; set; }

    /// <summary>
    /// Reverse zone for PTR records (e.g., "1.168.192.in-addr.arpa")
    /// If null, will be auto-generated from IP
    /// </summary>
    [Map("reverse_zone")]
    public string? ReverseZone { get; set; }

    /// <summary>
    /// Primary DNS server for updates
    /// </summary>
    [Map("dns_server")]
    public IPAddress? DnsServer { get; set; }

    /// <summary>
    /// DNS server port (default 53)
    /// </summary>
    [Map("dns_port")]
    public int DnsPort { get; set; } = 53;

    /// <summary>
    /// TSIG key name for authentication
    /// </summary>
    [Map("tsig_key_name")]
    public string? TsigKeyName { get; set; }

    /// <summary>
    /// TSIG key secret (Base64 encoded)
    /// </summary>
    [Map("tsig_key_secret")]
    public string? TsigKeySecret { get; set; }

    /// <summary>
    /// TSIG algorithm: hmac-md5, hmac-sha1, hmac-sha256, hmac-sha512
    /// </summary>
    [Map("tsig_algorithm")]
    public string TsigAlgorithm { get; set; } = DdnsTsigAlgorithm.HmacSha256;

    /// <summary>
    /// TTL for DNS records in seconds
    /// </summary>
    [Map("ttl")]
    public int Ttl { get; set; } = 300;

    /// <summary>
    /// Update style: interim (client FQDN), standard (hostname + domain)
    /// </summary>
    [Map("update_style")]
    public string UpdateStyle { get; set; } = DdnsUpdateStyle.Standard;

    /// <summary>
    /// Override client-provided hostname
    /// </summary>
    [Map("override_client_update")]
    public bool OverrideClientUpdate { get; set; } = false;

    /// <summary>
    /// Allow client to update its own A record (server does PTR only)
    /// </summary>
    [Map("allow_client_updates")]
    public bool AllowClientUpdates { get; set; } = false;

    /// <summary>
    /// Conflict resolution: check for existing records before update
    /// </summary>
    [Map("conflict_resolution")]
    public string ConflictResolution { get; set; } = DdnsConflictResolution.CheckWithDhcid;

    /// <summary>
    /// Enabled
    /// </summary>
    [Map("enabled")]
    public bool Enabled { get; set; } = true;

    [Map("created_at")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [Map("updated_at")]
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// TSIG algorithm constants
/// </summary>
public static class DdnsTsigAlgorithm
{
    public const string HmacMd5 = "hmac-md5.sig-alg.reg.int";
    public const string HmacSha1 = "hmac-sha1";
    public const string HmacSha256 = "hmac-sha256";
    public const string HmacSha512 = "hmac-sha512";
}

/// <summary>
/// DDNS update style
/// </summary>
public static class DdnsUpdateStyle
{
    /// <summary>
    /// Use hostname + domain from DHCP config
    /// </summary>
    public const string Standard = "standard";

    /// <summary>
    /// Use client FQDN option (81)
    /// </summary>
    public const string Interim = "interim";

    /// <summary>
    /// No updates
    /// </summary>
    public const string None = "none";
}

/// <summary>
/// Conflict resolution modes
/// </summary>
public static class DdnsConflictResolution
{
    /// <summary>
    /// Use DHCID record to verify ownership before update
    /// </summary>
    public const string CheckWithDhcid = "check-with-dhcid";

    /// <summary>
    /// Always update, don't check for conflicts
    /// </summary>
    public const string NoCheck = "no-check";

    /// <summary>
    /// Fail if record exists with different owner
    /// </summary>
    public const string FailOnConflict = "fail-on-conflict";
}
