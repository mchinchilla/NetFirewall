using System.Net;
using RepoDb.Attributes;

namespace NetFirewall.Models.Dhcp;

/// <summary>
/// DHCP Failover peer configuration.
/// </summary>
[Map("dhcp_failover_peers")]
public class FailoverPeer
{
    [Map("id")]
    public Guid Id { get; set; }

    /// <summary>
    /// Unique name for this failover relationship
    /// </summary>
    [Map("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Role of this server in the relationship
    /// </summary>
    [Map("role")]
    public string Role { get; set; } = "primary";

    /// <summary>
    /// Partner server IP address
    /// </summary>
    [Map("peer_address")]
    public IPAddress PeerAddress { get; set; } = IPAddress.Any;

    /// <summary>
    /// Partner server port (default 647)
    /// </summary>
    [Map("peer_port")]
    public int PeerPort { get; set; } = 647;

    /// <summary>
    /// Local address to bind to
    /// </summary>
    [Map("local_address")]
    public IPAddress? LocalAddress { get; set; }

    /// <summary>
    /// Local port to listen on (default 647)
    /// </summary>
    [Map("local_port")]
    public int LocalPort { get; set; } = 647;

    /// <summary>
    /// Maximum response delay in seconds before assuming partner down
    /// </summary>
    [Map("max_response_delay")]
    public int MaxResponseDelay { get; set; } = 60;

    /// <summary>
    /// Maximum unacknowledged updates before blocking
    /// </summary>
    [Map("max_unacked_updates")]
    public int MaxUnackedUpdates { get; set; } = 10;

    /// <summary>
    /// Maximum Client Lead Time in seconds.
    /// Primary can extend leases by this amount beyond partner's knowledge.
    /// </summary>
    [Map("mclt")]
    public int Mclt { get; set; } = 3600;

    /// <summary>
    /// Split ratio for address allocation (0-255).
    /// Primary gets addresses 0 to split-1, secondary gets split to 255.
    /// Default 128 = 50/50 split.
    /// </summary>
    [Map("split")]
    public int Split { get; set; } = 128;

    /// <summary>
    /// Load balance max seconds.
    /// If client hash time is within this range, use load balancing.
    /// </summary>
    [Map("load_balance_max")]
    public int LoadBalanceMax { get; set; } = 3;

    /// <summary>
    /// Auto partner-down delay in seconds.
    /// Time to wait in COMMUNICATIONS-INTERRUPTED before assuming partner down.
    /// 0 = manual intervention required.
    /// </summary>
    [Map("auto_partner_down")]
    public int AutoPartnerDown { get; set; } = 0;

    /// <summary>
    /// Shared secret for authentication (optional)
    /// </summary>
    [Map("shared_secret")]
    public string? SharedSecret { get; set; }

    /// <summary>
    /// Whether this failover relationship is enabled
    /// </summary>
    [Map("enabled")]
    public bool Enabled { get; set; } = false;

    [Map("created_at")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // Runtime state (not persisted)
    public FailoverState CurrentState { get; set; } = FailoverState.Startup;
    public DateTime LastContactTime { get; set; } = DateTime.MinValue;
    public DateTime StateTransitionTime { get; set; } = DateTime.UtcNow;
    public FailoverState PeerState { get; set; } = FailoverState.Startup;
    public bool IsConnected { get; set; } = false;
    public int UnackedUpdates { get; set; } = 0;

    /// <summary>
    /// Check if this server is primary
    /// </summary>
    public bool IsPrimary => Role.Equals("primary", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Check if we can serve addresses normally
    /// </summary>
    public bool CanServeNormally => CurrentState == FailoverState.Normal ||
                                     CurrentState == FailoverState.PartnerDown;

    /// <summary>
    /// Check if we're in a degraded state
    /// </summary>
    public bool IsDegraded => CurrentState == FailoverState.CommunicationsInterrupted ||
                               CurrentState == FailoverState.PotentialConflict;
}

/// <summary>
/// Failover binding update message
/// </summary>
public class FailoverBindingUpdate
{
    public IPAddress IpAddress { get; set; } = IPAddress.Any;
    public string MacAddress { get; set; } = string.Empty;
    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }
    public DateTime PotentialExpirationTime { get; set; }
    public DateTime ClientLastTransactionTime { get; set; }
    public FailoverBindingState BindingState { get; set; }
    public string? ClientHostname { get; set; }
    public byte[]? ClientIdentifier { get; set; }
    public Guid? SubnetId { get; set; }
    public long Stos { get; set; } // Start Time of State
    public long Cltt { get; set; } // Client Last Transaction Time
}

/// <summary>
/// Failover pool statistics
/// </summary>
public class FailoverPoolStats
{
    public Guid PoolId { get; set; }
    public int TotalAddresses { get; set; }
    public int FreeAddresses { get; set; }
    public int BackupAddresses { get; set; }
    public int ActiveLeases { get; set; }
    public int MyFreeAddresses { get; set; }
    public int PeerFreeAddresses { get; set; }
}
