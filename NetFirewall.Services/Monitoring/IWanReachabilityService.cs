namespace NetFirewall.Services.Monitoring;

/// <summary>
/// Pings each WAN gateway and reports up/down + RTT. On-demand (no persistence)
/// — caller decides when to invoke. Runs inside the daemon so it can use the
/// gateway IP from <c>fw_interfaces</c> without round-tripping the Web.
/// </summary>
public interface IWanReachabilityService
{
    Task<IReadOnlyList<WanReachability>> ProbeAllAsync(CancellationToken ct = default);
}

/// <summary>
/// One WAN probe outcome. <c>RttMs</c> = round-trip time of the successful
/// ping (null if down). <c>Target</c> = whatever was actually pinged (gateway
/// or fallback).
/// </summary>
public sealed record WanReachability(
    string InterfaceName,
    string Role,           // primary_wan, secondary_wan, …
    string? Target,        // IP that was pinged
    bool IsUp,
    double? RttMs,
    string? Message);
