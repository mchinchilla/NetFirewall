using NetFirewall.Models.Firewall;
using NetFirewall.Models.System;

namespace NetFirewall.Services.Network;

/// <summary>
/// Stand-in writer used on non-Linux dev machines (macOS / Windows) and when the
/// distro detector returns <see cref="NetworkConfigMethod.Unknown"/>. Generation
/// still works (so the UI can show a synthetic preview), but apply intentionally
/// fails with an informative message instead of mutating the host filesystem.
/// </summary>
public sealed class NoOpNetworkConfigService : INetworkConfigService
{
    public NetworkConfigMethod ConfigMethod => NetworkConfigMethod.Unknown;

    public string GetConfigFilePath(FwInterface iface) => $"<no writer for this platform>/{iface.Name}";

    public Task<string> GenerateConfigAsync(FwInterface iface, IEnumerable<FwStaticRoute>? routes = null)
    {
        var addressing = iface.AddressingMode switch
        {
            "dhcp"     => "DHCP",
            "disabled" => "Disabled",
            _          => $"Static {iface.IpAddress}/{iface.SubnetMask} via {iface.Gateway}"
        };

        var dns = iface.DnsServers is { Length: > 0 }
            ? string.Join(", ", iface.DnsServers.Select(d => d.ToString()))
            : "(none)";

        var preview = $"""
            # NetFirewall — preview only (no Linux network backend on this host)
            #
            # Interface : {iface.Name}
            # Type      : {iface.Type} / {iface.Role}
            # Addressing: {addressing}
            # DNS       : {dns}
            # MTU       : {iface.Mtu?.ToString() ?? "default"}
            # VLAN      : {(iface.VlanId.HasValue ? $"{iface.VlanId} on {iface.VlanParent}" : "none")}
            # Auto-start: {iface.AutoStart}
            #
            # Apply will fail on this platform — boot the AppHost on Debian/Ubuntu/Rocky/Alma
            # (or openSUSE) for the matching writer to take over.
            """;

        return Task.FromResult(preview);
    }

    public Task<NetworkApplyResult> ApplyConfigAsync(FwInterface iface, IEnumerable<FwStaticRoute>? routes = null) =>
        Task.FromResult(new NetworkApplyResult
        {
            Success = false,
            Message = "Network apply is not supported on this platform — preview only.",
            ConfigFilePath = GetConfigFilePath(iface),
            ExitCode = -1
        });

    public Task<NetworkApplyResult> RestartNetworkingAsync() =>
        Task.FromResult(new NetworkApplyResult
        {
            Success = false,
            Message = "Networking restart is not supported on this platform.",
            ExitCode = -1
        });

    public Task<bool> ValidateConfigAsync(string config) => Task.FromResult(!string.IsNullOrWhiteSpace(config));
}
