using System.Net;
using System.Text;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.System;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.Network;

/// <summary>
/// Writes NetworkManager keyfiles for RHEL/Rocky/Alma/Fedora 8+ and openSUSE 15+.
/// Files live under <c>/etc/NetworkManager/system-connections/</c> with mode 0600 owned by root,
/// then <c>nmcli connection reload</c> + <c>up &lt;id&gt;</c> applies them.
/// </summary>
public sealed class NetworkManagerConfigService : INetworkConfigService
{
    private readonly ILogger<NetworkManagerConfigService> _logger;
    private readonly IProcessRunner _runner;
    private const string ConnectionsDir = "/etc/NetworkManager/system-connections";
    private const string ConfigPrefix = "netfirewall";

    public NetworkConfigMethod ConfigMethod => NetworkConfigMethod.NetworkManager;

    public NetworkManagerConfigService(IProcessRunner runner, ILogger<NetworkManagerConfigService> logger)
    {
        _runner = runner;
        _logger = logger;
    }

    public string GetConfigFilePath(FwInterface iface) =>
        Path.Combine(ConnectionsDir, $"{ConnectionId(iface)}.nmconnection");

    public Task<string> GenerateConfigAsync(FwInterface iface, IEnumerable<FwStaticRoute>? routes = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Managed by NetFirewall — do not edit manually");
        if (!string.IsNullOrEmpty(iface.Description))
            sb.AppendLine($"# {iface.Description}");
        sb.AppendLine();

        // [connection]
        sb.AppendLine("[connection]");
        sb.AppendLine($"id={ConnectionId(iface)}");
        sb.AppendLine($"uuid={DeterministicUuid(iface.Name)}");
        sb.AppendLine($"type={(iface.VlanId.HasValue ? "vlan" : "ethernet")}");
        sb.AppendLine($"interface-name={iface.Name}");
        sb.AppendLine($"autoconnect={(iface.AutoStart ? "true" : "false")}");
        sb.AppendLine();

        // [vlan] when applicable
        if (iface.VlanId.HasValue && !string.IsNullOrEmpty(iface.VlanParent))
        {
            sb.AppendLine("[vlan]");
            sb.AppendLine($"id={iface.VlanId.Value}");
            sb.AppendLine($"parent={iface.VlanParent}");
            sb.AppendLine();
        }

        // [ethernet]
        if (!iface.VlanId.HasValue)
        {
            sb.AppendLine("[ethernet]");
            if (iface.Mtu.HasValue) sb.AppendLine($"mtu={iface.Mtu.Value}");
            if (!string.IsNullOrEmpty(iface.MacAddress)) sb.AppendLine($"cloned-mac-address={iface.MacAddress}");
            sb.AppendLine();
        }

        // [ipv4]
        sb.AppendLine("[ipv4]");
        switch (iface.AddressingMode)
        {
            case "dhcp":
                sb.AppendLine("method=auto");
                break;
            case "disabled":
                sb.AppendLine("method=disabled");
                break;
            default: // static
                sb.AppendLine("method=manual");
                if (iface.IpAddress != null && iface.SubnetMask != null)
                {
                    var prefix = SubnetMaskToCidr(iface.SubnetMask);
                    var addressLine = iface.Gateway != null
                        ? $"address1={iface.IpAddress}/{prefix},{iface.Gateway}"
                        : $"address1={iface.IpAddress}/{prefix}";
                    sb.AppendLine(addressLine);
                }
                if (iface.DnsServers is { Length: > 0 })
                {
                    sb.AppendLine($"dns={string.Join(';', iface.DnsServers.Select(d => d.ToString()))};");
                    sb.AppendLine("ignore-auto-dns=true");
                }
                break;
        }
        if (iface.Metric.HasValue) sb.AppendLine($"route-metric={iface.Metric.Value}");
        sb.AppendLine();

        // [ipv6] — disabled by default; we'll let users opt in later from the UI.
        sb.AppendLine("[ipv6]");
        sb.AppendLine("method=disabled");
        sb.AppendLine();

        // Static routes
        if (routes != null)
        {
            var idx = 1;
            foreach (var route in routes)
            {
                if (string.IsNullOrEmpty(route.Destination) || !route.Enabled) continue;
                var line = $"route{idx}={route.Destination}";
                if (route.Gateway != null) line += $",{route.Gateway}";
                line += $",{route.Metric}";
                sb.AppendLine(line);
                idx++;
            }
        }

        return Task.FromResult(sb.ToString());
    }

    public async Task<NetworkApplyResult> ApplyConfigAsync(FwInterface iface, IEnumerable<FwStaticRoute>? routes = null)
    {
        var result = new NetworkApplyResult();

        try
        {
            var configPath = GetConfigFilePath(iface);
            result.ConfigFilePath = configPath;

            var config = await GenerateConfigAsync(iface, routes);

            if (!Directory.Exists(ConnectionsDir))
                Directory.CreateDirectory(ConnectionsDir);

            // Backup existing keyfile if present.
            if (File.Exists(configPath))
            {
                var backupPath = $"{configPath}.backup.{DateTime.UtcNow:yyyyMMddHHmmss}";
                File.Copy(configPath, backupPath);
                result.BackupFilePath = backupPath;
            }

            await File.WriteAllTextAsync(configPath, config);

            // NetworkManager refuses to load keyfiles unless they are owned by root with mode 0600.
            await _runner.RunAsync("chmod", $"600 {configPath}");
            await _runner.RunAsync("chown", $"root:root {configPath}");

            // Reload definitions, then bring this connection up (idempotent).
            await _runner.RunAsync("nmcli", "connection reload");
            var upResult = await _runner.RunAsync("nmcli", $"connection up {ConnectionId(iface)}");

            result.Success = upResult.Success;
            result.Output = upResult.Output;
            result.ErrorOutput = upResult.Error;
            result.ExitCode = upResult.ExitCode;
            result.Message = result.Success
                ? "NetworkManager profile applied"
                : $"nmcli returned {upResult.ExitCode}; check the connection manually";

            _logger.LogInformation("Applied NetworkManager config for {Interface}", iface.Name);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to apply NetworkManager config for {Interface}", iface.Name);
            result.Success = false;
            result.Message = ex.Message;
        }

        return result;
    }

    public async Task<NetworkApplyResult> RestartNetworkingAsync()
    {
        var result = await _runner.RunAsync("systemctl", "restart NetworkManager");
        return new NetworkApplyResult
        {
            Success = result.Success,
            Message = result.Success ? "NetworkManager restarted" : "Failed to restart NetworkManager",
            Output = result.Output,
            ErrorOutput = result.Error,
            ExitCode = result.ExitCode
        };
    }

    public Task<bool> ValidateConfigAsync(string config)
    {
        // The bare minimum NM keyfile must declare [connection] and [ipv4].
        var ok = config.Contains("[connection]") && config.Contains("[ipv4]") && config.Contains("interface-name=");
        return Task.FromResult(ok);
    }

    private static string ConnectionId(FwInterface iface) => $"{ConfigPrefix}-{iface.Name}";

    /// <summary>
    /// Stable UUID derived from the interface name so re-applying the same interface
    /// reuses the same NM connection (avoids orphan profiles on rename).
    /// </summary>
    private static string DeterministicUuid(string interfaceName)
    {
        // RFC 4122 §4.3 name-based UUID — using SHA1 over a fixed namespace + interface name.
        // Simplified: hash name with a static salt and format as UUID v5-ish.
        Span<byte> seed = stackalloc byte[16];
        var hash = System.Security.Cryptography.SHA1.HashData(Encoding.UTF8.GetBytes($"netfirewall::{interfaceName}"));
        hash.AsSpan(0, 16).CopyTo(seed);
        // Force version 5 / variant RFC4122.
        seed[6] = (byte)((seed[6] & 0x0F) | 0x50);
        seed[8] = (byte)((seed[8] & 0x3F) | 0x80);
        return new Guid(seed.ToArray()).ToString();
    }

    private static int SubnetMaskToCidr(IPAddress mask)
    {
        var bytes = mask.GetAddressBytes();
        int cidr = 0;
        foreach (var b in bytes)
        {
            for (int i = 7; i >= 0; i--)
            {
                if ((b & (1 << i)) != 0) cidr++;
                else return cidr;
            }
        }
        return cidr;
    }

}
