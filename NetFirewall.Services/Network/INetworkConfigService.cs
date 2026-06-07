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

    /// <summary>
    /// Read the DECLARED addressing mode of an interface from the system network
    /// config (the source of truth for "is this NIC DHCP or static"). Returns
    /// "dhcp", "static", or null if it can't be determined (interface not in the
    /// config, unrecognised stanza, file absent). Callers fall back to a heuristic
    /// only when this returns null. Read-only — never mutates config.
    /// </summary>
    Task<string?> DetectAddressingModeAsync(string interfaceName, CancellationToken ct = default);
}
