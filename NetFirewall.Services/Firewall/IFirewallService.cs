using NetFirewall.Models.Firewall;

namespace NetFirewall.Services.Firewall;

/// <summary>
/// Service for managing firewall configuration and generating nftables rules.
/// </summary>
public interface IFirewallService
{
    // Interface operations
    Task<IReadOnlyList<FwInterface>> GetInterfacesAsync(CancellationToken ct = default);
    Task<FwInterface?> GetInterfaceByIdAsync(Guid id, CancellationToken ct = default);
    Task<FwInterface?> GetInterfaceByNameAsync(string name, CancellationToken ct = default);
    Task<FwInterface> CreateInterfaceAsync(FwInterface iface, CancellationToken ct = default);
    Task<FwInterface> UpdateInterfaceAsync(FwInterface iface, CancellationToken ct = default);
    Task<bool> DeleteInterfaceAsync(Guid id, CancellationToken ct = default);

    // Static route operations
    Task<IReadOnlyList<FwStaticRoute>> GetStaticRoutesAsync(Guid? interfaceId = null, CancellationToken ct = default);
    Task<FwStaticRoute?> GetStaticRouteByIdAsync(Guid id, CancellationToken ct = default);
    Task<FwStaticRoute> CreateStaticRouteAsync(FwStaticRoute route, CancellationToken ct = default);
    Task<FwStaticRoute> UpdateStaticRouteAsync(FwStaticRoute route, CancellationToken ct = default);
    Task<bool> DeleteStaticRouteAsync(Guid id, CancellationToken ct = default);

    // Filter rule operations
    Task<IReadOnlyList<FwFilterRule>> GetFilterRulesAsync(string? chain = null, CancellationToken ct = default);
    Task<FwFilterRule?> GetFilterRuleByIdAsync(Guid id, CancellationToken ct = default);
    Task<FwFilterRule> CreateFilterRuleAsync(FwFilterRule rule, CancellationToken ct = default);
    Task<FwFilterRule> UpdateFilterRuleAsync(FwFilterRule rule, CancellationToken ct = default);
    Task<bool> DeleteFilterRuleAsync(Guid id, CancellationToken ct = default);

    // Port forward operations
    Task<IReadOnlyList<FwPortForward>> GetPortForwardsAsync(CancellationToken ct = default);
    Task<FwPortForward?> GetPortForwardByIdAsync(Guid id, CancellationToken ct = default);
    Task<FwPortForward> CreatePortForwardAsync(FwPortForward portForward, CancellationToken ct = default);
    Task<FwPortForward> UpdatePortForwardAsync(FwPortForward portForward, CancellationToken ct = default);
    Task<bool> DeletePortForwardAsync(Guid id, CancellationToken ct = default);

    // NAT rule operations
    Task<IReadOnlyList<FwNatRule>> GetNatRulesAsync(CancellationToken ct = default);
    Task<FwNatRule?> GetNatRuleByIdAsync(Guid id, CancellationToken ct = default);
    Task<FwNatRule> CreateNatRuleAsync(FwNatRule rule, CancellationToken ct = default);
    Task<FwNatRule> UpdateNatRuleAsync(FwNatRule rule, CancellationToken ct = default);
    Task<bool> DeleteNatRuleAsync(Guid id, CancellationToken ct = default);

    // Traffic mark operations
    Task<IReadOnlyList<FwTrafficMark>> GetTrafficMarksAsync(CancellationToken ct = default);
    Task<FwTrafficMark?> GetTrafficMarkByIdAsync(Guid id, CancellationToken ct = default);
    Task<FwTrafficMark> CreateTrafficMarkAsync(FwTrafficMark mark, CancellationToken ct = default);
    Task<FwTrafficMark> UpdateTrafficMarkAsync(FwTrafficMark mark, CancellationToken ct = default);
    Task<bool> DeleteTrafficMarkAsync(Guid id, CancellationToken ct = default);

    // Mangle rule operations
    Task<IReadOnlyList<FwMangleRule>> GetMangleRulesAsync(string? chain = null, CancellationToken ct = default);
    Task<FwMangleRule?> GetMangleRuleByIdAsync(Guid id, CancellationToken ct = default);
    Task<FwMangleRule> CreateMangleRuleAsync(FwMangleRule rule, CancellationToken ct = default);
    Task<FwMangleRule> UpdateMangleRuleAsync(FwMangleRule rule, CancellationToken ct = default);
    Task<bool> DeleteMangleRuleAsync(Guid id, CancellationToken ct = default);

    // QoS operations
    Task<IReadOnlyList<FwQosConfig>> GetQosConfigsAsync(CancellationToken ct = default);
    Task<FwQosConfig?> GetQosConfigByIdAsync(Guid id, CancellationToken ct = default);
    Task<FwQosConfig> CreateQosConfigAsync(FwQosConfig config, CancellationToken ct = default);
    Task<FwQosConfig> UpdateQosConfigAsync(FwQosConfig config, CancellationToken ct = default);
    Task<bool> DeleteQosConfigAsync(Guid id, CancellationToken ct = default);

    Task<IReadOnlyList<FwQosClass>> GetQosClassesAsync(Guid? configId = null, CancellationToken ct = default);
    Task<FwQosClass> CreateQosClassAsync(FwQosClass qosClass, CancellationToken ct = default);
    Task<FwQosClass> UpdateQosClassAsync(FwQosClass qosClass, CancellationToken ct = default);
    Task<bool> DeleteQosClassAsync(Guid id, CancellationToken ct = default);

    // Audit log
    Task<IReadOnlyList<FwAuditLog>> GetAuditLogsAsync(int limit = 100, int offset = 0, CancellationToken ct = default);
    Task LogAuditAsync(string tableName, Guid recordId, string action, object? oldValues, object? newValues, string? userId = null, CancellationToken ct = default);

    // Configuration generation
    Task<string> GenerateNftablesConfigAsync(CancellationToken ct = default);
    Task<string> GenerateNftablesConfigPreviewAsync(CancellationToken ct = default);

    // Statistics
    Task<FirewallStats> GetStatsAsync(CancellationToken ct = default);
}

/// <summary>
/// Firewall statistics for dashboard.
/// </summary>
public class FirewallStats
{
    public int TotalInterfaces { get; set; }
    public int ActiveInterfaces { get; set; }
    public int TotalFilterRules { get; set; }
    public int EnabledFilterRules { get; set; }
    public int TotalPortForwards { get; set; }
    public int EnabledPortForwards { get; set; }
    public int TotalNatRules { get; set; }
    public int EnabledNatRules { get; set; }
}
