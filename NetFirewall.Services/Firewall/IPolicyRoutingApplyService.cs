namespace NetFirewall.Services.Firewall;

/// <summary>
/// Privileged reconciler: pushes <c>fw_route_tables</c> + <c>fw_policy_rules</c>
/// + <c>fw_static_routes(table_id NOT NULL)</c> into the kernel via iproute2.
/// Lives in the daemon because it needs CAP_NET_ADMIN + CAP_DAC_OVERRIDE
/// (to write <c>/etc/iproute2/rt_tables</c>).
/// </summary>
public interface IPolicyRoutingApplyService
{
    /// <summary>
    /// Build the change set and either preview (<paramref name="dryRun"/>=true,
    /// no kernel mutations) or execute it. Either way returns the full list of
    /// steps for the UI to show.
    /// </summary>
    Task<PolicyRoutingApplyResult> ApplyAsync(bool dryRun, CancellationToken ct = default);
}
