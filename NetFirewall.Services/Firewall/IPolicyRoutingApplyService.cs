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

    /// <summary>
    /// Re-install only the per-table routes that ride on <paramref name="device"/>:
    /// rows whose interface is that device, or that live in the table named after
    /// it (the VPN scaffold names a tunnel's table after its interface). Deleting a
    /// netdevice purges its routes from EVERY table, and wg-quick with
    /// <c>Table=off</c> puts nothing back — so after a Stop/Start the fwmark lookup
    /// hits an empty table and traffic falls through to main: "connected", no
    /// traffic. Skips rt_tables and ip rule on purpose: those survive a link flap,
    /// and bringing a VPN up must not apply unrelated pending routing changes.
    /// </summary>
    Task<PolicyRoutingApplyResult> ReapplyRoutesForDeviceAsync(string device, CancellationToken ct = default);
}
