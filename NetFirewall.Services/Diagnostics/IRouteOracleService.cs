using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics;

/// <summary>
/// "Which way would this packet go?" — kernel route lookups through iproute2's
/// JSON output. <c>ip route get</c> honours <c>mark</c>, <c>from</c> and <c>iif</c>,
/// so the answer reflects the policy-routing tables, not just <c>main</c>.
/// </summary>
public interface IRouteOracleService
{
    /// <param name="fwmark">0 = no mark.</param>
    Task<RouteGetResult> GetAsync(string targetIp, long fwmark, string? fromIp, string? iif, CancellationToken ct = default);

    /// <summary><c>ip -j rule list</c>.</summary>
    Task<IReadOnlyList<IpRuleEntry>> ListRulesAsync(CancellationToken ct = default);

    /// <summary><c>ip -j route show table &lt;name|id&gt;</c>. Empty list = empty table (the Stop/Start symptom).</summary>
    Task<IReadOnlyList<IpRouteEntry>> ShowTableAsync(string table, CancellationToken ct = default);
}
