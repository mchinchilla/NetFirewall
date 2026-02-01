using NetFirewall.Models.Firewall;
using NetFirewall.Models.System;

namespace NetFirewall.Services.Network;

public interface INetworkConfigService
{
    Task<string> GenerateConfigAsync(FwInterface iface, IEnumerable<FwStaticRoute>? routes = null);
    Task<NetworkApplyResult> ApplyConfigAsync(FwInterface iface, IEnumerable<FwStaticRoute>? routes = null);
    Task<NetworkApplyResult> RestartNetworkingAsync();
    Task<bool> ValidateConfigAsync(string config);
    string GetConfigFilePath(FwInterface iface);
    NetworkConfigMethod ConfigMethod { get; }
}
