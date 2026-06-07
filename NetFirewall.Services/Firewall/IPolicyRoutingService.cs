using NetFirewall.Models.Firewall;

namespace NetFirewall.Services.Firewall;

/// <summary>
/// CRUD + reconciliation for policy routing (the iproute2 layer that
/// <c>/root/firewall.sh</c> used to manage). Applies in three stages:
///
///   1. Sync <c>/etc/iproute2/rt_tables</c> with rows in <c>fw_route_tables</c>.
///   2. Reconcile <c>ip rule</c>s: add missing, remove DB-not-present entries
///      among the ones we manage (matched by fwmark+table).
///   3. Reconcile per-table routes: <c>ip route replace … table {name}</c>
///      for every <c>fw_static_routes WHERE table_id IS NOT NULL</c>.
/// </summary>
public interface IPolicyRoutingService
{
    Task<IReadOnlyList<FwRouteTable>> GetRouteTablesAsync(CancellationToken ct = default);
    Task<IReadOnlyList<FwPolicyRule>> GetPolicyRulesAsync(CancellationToken ct = default);

    // ── write-side (added for WireGuard↔policy-routing auto-integration) ──
    // All upserts are idempotent (ON CONFLICT DO NOTHING-style) so re-running the
    // VPN scaffold never duplicates or clobbers existing (possibly hand-seeded) rows.

    Task<FwRouteTable?> GetRouteTableByNameAsync(string name, CancellationToken ct = default);
    Task<FwPolicyRule?> GetPolicyRuleByTableNameAsync(string tableName, CancellationToken ct = default);

    /// <summary>Insert a route table if neither its table_id nor table_name exists;
    /// returns the existing or newly-created row. Never updates an existing row.</summary>
    Task<FwRouteTable> EnsureRouteTableAsync(int tableId, string name, string? description, CancellationToken ct = default);

    /// <summary>Insert a policy rule if no row with the same (fwmark, table_name)
    /// exists; returns existing or new. Never updates.</summary>
    Task<FwPolicyRule> EnsurePolicyRuleAsync(long fwmark, string tableName, int? priority, string? description, CancellationToken ct = default);

    /// <summary>Lowest free table_id in [200,252] not used by any fw_route_tables row.
    /// Throws if the range is exhausted.</summary>
    Task<int> AllocateTableIdAsync(CancellationToken ct = default);
}

/// <summary>
/// Result of an apply (real or dry-run). <c>Steps</c> = ordered list of every
/// kernel-mutating command considered. <c>DryRun=true</c> means nothing was
/// actually executed.
/// </summary>
public sealed record PolicyRoutingApplyResult(
    bool Success,
    bool DryRun,
    IReadOnlyList<RoutingStep> Steps,
    string? Error);

public sealed record RoutingStep(
    string Phase,       // "rt_tables" | "ip-rule-add" | "ip-rule-del" | "ip-route"
    string Command,     // human-readable shell-ish ("ip rule add fwmark 0x100 lookup wan1 priority 100")
    bool Executed,      // false in dry-run, or true/false after real execution
    bool Success,       // n/a when not executed
    string? Detail);    // stderr / extra context
