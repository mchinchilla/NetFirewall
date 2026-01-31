using System.Net;
using NetFirewall.Models.Dhcp;

namespace NetFirewall.Services.Dhcp;

/// <summary>
/// Service for DHCP Failover protocol operations.
/// Implements ISC-DHCP compatible failover for high availability.
/// </summary>
public interface IFailoverService
{
    /// <summary>
    /// Current failover state
    /// </summary>
    FailoverState CurrentState { get; }

    /// <summary>
    /// Whether failover is enabled and configured
    /// </summary>
    bool IsEnabled { get; }

    /// <summary>
    /// Whether we can serve DHCP requests in current state
    /// </summary>
    bool CanServe { get; }

    /// <summary>
    /// Initialize failover and start communication with peer
    /// </summary>
    Task StartAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gracefully shutdown failover
    /// </summary>
    Task StopAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Check if this server should handle a request based on load balancing
    /// </summary>
    /// <param name="macAddress">Client MAC address</param>
    /// <param name="ipAddress">Requested/offered IP address</param>
    /// <returns>True if this server should handle the request</returns>
    bool ShouldHandleRequest(string macAddress, IPAddress? ipAddress);

    /// <summary>
    /// Notify peer of a binding update (lease change)
    /// </summary>
    Task<bool> SendBindingUpdateAsync(
        FailoverBindingUpdate update,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Notify peer of a lease release
    /// </summary>
    Task<bool> SendBindingReleaseAsync(
        IPAddress ipAddress,
        string macAddress,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Request pool rebalancing from peer
    /// </summary>
    Task<bool> RequestPoolRebalanceAsync(
        Guid poolId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Transition to a new state
    /// </summary>
    Task TransitionToStateAsync(
        FailoverState newState,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Force transition to partner-down state (admin action)
    /// </summary>
    Task ForcePartnerDownAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Get current failover peer configuration
    /// </summary>
    FailoverPeer? GetPeerConfig();

    /// <summary>
    /// Get pool statistics for failover
    /// </summary>
    Task<IReadOnlyList<FailoverPoolStats>> GetPoolStatsAsync(
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Synchronize all leases with peer (recovery operation)
    /// </summary>
    Task<int> SynchronizeLeasesAsync(
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Event raised when failover state changes
    /// </summary>
    event EventHandler<FailoverStateChangedEventArgs>? StateChanged;
}

/// <summary>
/// Event arguments for failover state change
/// </summary>
public class FailoverStateChangedEventArgs : EventArgs
{
    public FailoverState OldState { get; }
    public FailoverState NewState { get; }
    public string? Reason { get; }

    public FailoverStateChangedEventArgs(FailoverState oldState, FailoverState newState, string? reason = null)
    {
        OldState = oldState;
        NewState = newState;
        Reason = reason;
    }
}
