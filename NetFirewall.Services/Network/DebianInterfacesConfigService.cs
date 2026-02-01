using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.System;

namespace NetFirewall.Services.Network;

public sealed class DebianInterfacesConfigService : INetworkConfigService
{
    private readonly ILogger<DebianInterfacesConfigService> _logger;
    private const string InterfacesDir = "/etc/network/interfaces.d";
    private const string ConfigPrefix = "60-netfirewall";

    public NetworkConfigMethod ConfigMethod => NetworkConfigMethod.Interfaces;

    public DebianInterfacesConfigService(ILogger<DebianInterfacesConfigService> logger)
    {
        _logger = logger;
    }

    public string GetConfigFilePath(FwInterface iface)
    {
        return Path.Combine(InterfacesDir, $"{ConfigPrefix}-{iface.Name}");
    }

    public Task<string> GenerateConfigAsync(FwInterface iface, IEnumerable<FwStaticRoute>? routes = null)
    {
        var sb = new StringBuilder();

        sb.AppendLine("# Managed by NetFirewall - Do not edit manually");

        // Description as comment
        if (!string.IsNullOrEmpty(iface.Description))
        {
            sb.AppendLine($"# {iface.Description}");
        }

        sb.AppendLine();

        // Auto start
        if (iface.AutoStart)
        {
            sb.AppendLine($"auto {iface.Name}");
        }
        else
        {
            sb.AppendLine($"allow-hotplug {iface.Name}");
        }

        // VLAN configuration
        if (iface.VlanId.HasValue && !string.IsNullOrEmpty(iface.VlanParent))
        {
            // This is a VLAN interface
            sb.AppendLine($"iface {iface.Name} inet {GetAddressMethod(iface.AddressingMode)}");
            sb.AppendLine($"    vlan-raw-device {iface.VlanParent}");
        }
        else
        {
            sb.AppendLine($"iface {iface.Name} inet {GetAddressMethod(iface.AddressingMode)}");
        }

        if (iface.AddressingMode == "static")
        {
            // IP Address and subnet
            if (iface.IpAddress != null)
            {
                sb.AppendLine($"    address {iface.IpAddress}");
            }

            if (iface.SubnetMask != null)
            {
                sb.AppendLine($"    netmask {iface.SubnetMask}");
            }

            // Gateway
            if (iface.Gateway != null)
            {
                sb.AppendLine($"    gateway {iface.Gateway}");
            }

            // DNS servers
            if (iface.DnsServers is { Length: > 0 })
            {
                sb.AppendLine($"    dns-nameservers {string.Join(" ", iface.DnsServers.Select(d => d.ToString()))}");
            }
        }

        // MTU
        if (iface.Mtu.HasValue)
        {
            sb.AppendLine($"    mtu {iface.Mtu}");
        }

        // MAC override
        if (!string.IsNullOrEmpty(iface.MacAddress))
        {
            sb.AppendLine($"    hwaddress ether {iface.MacAddress}");
        }

        // Metric (for gateway)
        if (iface.Metric.HasValue && iface.Gateway != null)
        {
            sb.AppendLine($"    metric {iface.Metric}");
        }

        // Static routes
        var routeList = routes?.Where(r => r.Enabled).ToList() ?? new List<FwStaticRoute>();
        foreach (var route in routeList)
        {
            var via = route.Gateway != null ? $"via {route.Gateway}" : "";
            sb.AppendLine($"    up ip route add {route.Destination} {via} metric {route.Metric} dev {iface.Name} || true");
            sb.AppendLine($"    down ip route del {route.Destination} {via} dev {iface.Name} || true");
        }

        sb.AppendLine();

        return Task.FromResult(sb.ToString());
    }

    public async Task<NetworkApplyResult> ApplyConfigAsync(FwInterface iface, IEnumerable<FwStaticRoute>? routes = null)
    {
        var result = new NetworkApplyResult();

        try
        {
            // Ensure interfaces.d is included in main config
            await EnsureInterfacesDirIncluded();

            var configPath = GetConfigFilePath(iface);
            result.ConfigFilePath = configPath;

            // Generate config
            var config = await GenerateConfigAsync(iface, routes);

            // Create backup if file exists
            if (File.Exists(configPath))
            {
                var backupPath = $"{configPath}.backup.{DateTime.UtcNow:yyyyMMddHHmmss}";
                File.Copy(configPath, backupPath);
                result.BackupFilePath = backupPath;
            }

            // Ensure directory exists
            if (!Directory.Exists(InterfacesDir))
            {
                Directory.CreateDirectory(InterfacesDir);
            }

            // Write config
            await File.WriteAllTextAsync(configPath, config);

            // Apply by bringing interface down and up
            // First try ifdown/ifup
            var downResult = await RunCommandAsync("ifdown", $"--force {iface.Name}");
            var upResult = await RunCommandAsync("ifup", iface.Name);

            if (upResult.ExitCode != 0)
            {
                // Fallback to ip commands
                await RunCommandAsync("ip", $"link set {iface.Name} down");
                await RunCommandAsync("ip", $"link set {iface.Name} up");

                // If static, apply IP manually
                if (iface.AddressingMode == "static" && iface.IpAddress != null && iface.SubnetMask != null)
                {
                    var prefix = SubnetMaskToCidr(iface.SubnetMask.ToString());
                    await RunCommandAsync("ip", $"addr flush dev {iface.Name}");
                    await RunCommandAsync("ip", $"addr add {iface.IpAddress}/{prefix} dev {iface.Name}");

                    if (iface.Gateway != null)
                    {
                        await RunCommandAsync("ip", $"route add default via {iface.Gateway} dev {iface.Name}");
                    }
                }
            }

            result.Success = true;
            result.Output = upResult.Output;
            result.ErrorOutput = upResult.Error;
            result.ExitCode = upResult.ExitCode;
            result.Message = "Configuration applied successfully";

            _logger.LogInformation("Applied Debian interfaces config for {Interface}", iface.Name);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to apply Debian interfaces config for {Interface}", iface.Name);
            result.Success = false;
            result.Message = ex.Message;
        }

        return result;
    }

    public async Task<NetworkApplyResult> RestartNetworkingAsync()
    {
        var result = await RunCommandAsync("systemctl", "restart networking");
        return new NetworkApplyResult
        {
            Success = result.ExitCode == 0,
            Message = result.ExitCode == 0 ? "Networking restarted" : "Failed to restart networking",
            Output = result.Output,
            ErrorOutput = result.Error,
            ExitCode = result.ExitCode
        };
    }

    public Task<bool> ValidateConfigAsync(string config)
    {
        // Basic validation - check for required keywords
        var hasIface = config.Contains("iface ");
        var hasMethod = config.Contains(" inet ");

        return Task.FromResult(hasIface && hasMethod);
    }

    private async Task EnsureInterfacesDirIncluded()
    {
        const string mainConfig = "/etc/network/interfaces";
        if (!File.Exists(mainConfig)) return;

        var content = await File.ReadAllTextAsync(mainConfig);
        if (!content.Contains("source /etc/network/interfaces.d/*") &&
            !content.Contains("source-directory /etc/network/interfaces.d"))
        {
            _logger.LogWarning("The main interfaces file does not include interfaces.d. " +
                             "Add 'source /etc/network/interfaces.d/*' to {Path}", mainConfig);
        }
    }

    private static string GetAddressMethod(string addressingMode)
    {
        return addressingMode switch
        {
            "dhcp" => "dhcp",
            "disabled" => "manual",
            _ => "static"
        };
    }

    private static int SubnetMaskToCidr(string mask)
    {
        var parts = mask.Split('.');
        int cidr = 0;
        foreach (var part in parts)
        {
            if (int.TryParse(part, out var octet))
            {
                while (octet > 0)
                {
                    cidr += octet & 1;
                    octet >>= 1;
                }
            }
        }
        return cidr;
    }

    private static async Task<(int ExitCode, string Output, string Error)> RunCommandAsync(string command, string args)
    {
        var psi = new ProcessStartInfo
        {
            FileName = command,
            Arguments = args,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        try
        {
            using var process = Process.Start(psi);
            if (process == null)
                return (-1, "", "Failed to start process");

            var output = await process.StandardOutput.ReadToEndAsync();
            var error = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();

            return (process.ExitCode, output, error);
        }
        catch (Exception ex)
        {
            return (-1, "", ex.Message);
        }
    }
}
