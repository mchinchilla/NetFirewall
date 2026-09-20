using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics.Trace;

/// <summary>
/// "Which rule touched this packet?" — installs a temporary nftables table whose
/// only job is to set <c>nftrace</c> on the packets you describe, streams
/// <c>nft monitor trace</c> while it runs, and removes the table afterwards.
///
/// The temporary state is a table of our own (<see cref="TraceTableName"/>) with
/// hooks at priority -300, never an edit of the operator's chains: the ruleset the
/// firewall enforces is untouched, and cleanup is a single atomic
/// <c>nft delete table</c> that cannot leave half a rule behind.
/// </summary>
public interface IFlowInspectorService
{
    /// <summary>Table the tracer owns end to end. Anything left in it is stale and safe to delete.</summary>
    const string TraceTableName = "netfw_diag";

    /// <summary>
    /// Start a trace in the background. Returns the job id to poll, or null when
    /// another invasive job already holds the slot.
    /// </summary>
    Guid? Start(TraceRequest request, string? requestedBy);
}
