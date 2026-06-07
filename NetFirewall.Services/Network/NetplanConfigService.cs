using System.Text;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.System;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.Network;

public sealed class NetplanConfigService : INetworkConfigService
{
    private readonly ILogger<NetplanConfigService> _logger;
    private readonly IProcessRunner _runner;
    private const string NetplanDir = "/etc/netplan";
    private const string ConfigPrefix = "60-netfirewall";

    public NetworkConfigMethod ConfigMethod => NetworkConfigMethod.Netplan;

    public NetplanConfigService(IProcessRunner runner, ILogger<NetplanConfigService> logger)
    {
        _runner = runner;
        _logger = logger;
    }

    public string GetConfigFilePath(FwInterface iface)
    {
        return Path.Combine(NetplanDir, $"{ConfigPrefix}-{iface.Name}.yaml");
    }

    public Task<string> GenerateConfigAsync(FwInterface iface, IEnumerable<FwStaticRoute>? routes = null)
    {
        var sb = new StringBuilder();
        var indent = "  ";

        sb.AppendLine("# Managed by NetFirewall - Do not edit manually");
        sb.AppendLine("network:");
        sb.AppendLine($"{indent}version: 2");
        sb.AppendLine($"{indent}renderer: networkd");

        // Determine section type based on interface name
        var section = GetInterfaceSection(iface.Name);
        sb.AppendLine($"{indent}{section}:");
        sb.AppendLine($"{indent}{indent}{iface.Name}:");

        // Description as comment
        if (!string.IsNullOrEmpty(iface.Description))
        {
            sb.AppendLine($"{indent}{indent}  # {iface.Description}");
        }

        // Addressing mode
        if (iface.AddressingMode == "dhcp")
        {
            sb.AppendLine($"{indent}{indent}{indent}dhcp4: true");
        }
        else if (iface.AddressingMode == "disabled")
        {
            sb.AppendLine($"{indent}{indent}{indent}optional: true");
        }
        else // static
        {
            sb.AppendLine($"{indent}{indent}{indent}dhcp4: false");

            // IP Address with CIDR
            if (iface.IpAddress != null && iface.SubnetMask != null)
            {
                var prefix = SubnetMaskToCidr(iface.SubnetMask.ToString());
                sb.AppendLine($"{indent}{indent}{indent}addresses:");
                sb.AppendLine($"{indent}{indent}{indent}  - {iface.IpAddress}/{prefix}");
            }

            // Routes
            var routeList = routes?.Where(r => r.Enabled).ToList() ?? new List<FwStaticRoute>();

            // Add default gateway as a route
            if (iface.Gateway != null)
            {
                sb.AppendLine($"{indent}{indent}{indent}routes:");
                sb.AppendLine($"{indent}{indent}{indent}  - to: default");
                sb.AppendLine($"{indent}{indent}{indent}    via: {iface.Gateway}");
                if (iface.Metric.HasValue)
                {
                    sb.AppendLine($"{indent}{indent}{indent}    metric: {iface.Metric}");
                }

                // Additional static routes
                foreach (var route in routeList)
                {
                    sb.AppendLine($"{indent}{indent}{indent}  - to: {route.Destination}");
                    if (route.Gateway != null)
                    {
                        sb.AppendLine($"{indent}{indent}{indent}    via: {route.Gateway}");
                    }
                    sb.AppendLine($"{indent}{indent}{indent}    metric: {route.Metric}");
                }
            }
            else if (routeList.Count > 0)
            {
                sb.AppendLine($"{indent}{indent}{indent}routes:");
                foreach (var route in routeList)
                {
                    sb.AppendLine($"{indent}{indent}{indent}  - to: {route.Destination}");
                    if (route.Gateway != null)
                    {
                        sb.AppendLine($"{indent}{indent}{indent}    via: {route.Gateway}");
                    }
                    sb.AppendLine($"{indent}{indent}{indent}    metric: {route.Metric}");
                }
            }

            // DNS servers
            if (iface.DnsServers is { Length: > 0 })
            {
                sb.AppendLine($"{indent}{indent}{indent}nameservers:");
                sb.AppendLine($"{indent}{indent}{indent}  addresses:");
                foreach (var dns in iface.DnsServers)
                {
                    sb.AppendLine($"{indent}{indent}{indent}    - {dns}");
                }
            }
        }

        // MTU
        if (iface.Mtu.HasValue)
        {
            sb.AppendLine($"{indent}{indent}{indent}mtu: {iface.Mtu}");
        }

        // MAC override
        if (!string.IsNullOrEmpty(iface.MacAddress))
        {
            sb.AppendLine($"{indent}{indent}{indent}macaddress: {iface.MacAddress}");
        }

        // Optional (don't wait for this interface at boot)
        if (!iface.AutoStart)
        {
            sb.AppendLine($"{indent}{indent}{indent}optional: true");
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

            // Generate config
            var config = await GenerateConfigAsync(iface, routes);

            // Validate before writing
            if (!await ValidateConfigAsync(config))
            {
                result.Success = false;
                result.Message = "Generated configuration failed validation";
                return result;
            }

            // Create backup if file exists
            if (File.Exists(configPath))
            {
                var backupPath = $"{configPath}.backup.{DateTime.UtcNow:yyyyMMddHHmmss}";
                File.Copy(configPath, backupPath);
                result.BackupFilePath = backupPath;
            }

            // Write config
            await File.WriteAllTextAsync(configPath, config);

            // Apply with netplan apply
            var applyResult = await _runner.RunAsync("netplan", "apply");
            result.Success = applyResult.Success;
            result.Output = applyResult.Output;
            result.ErrorOutput = applyResult.Error;
            result.ExitCode = applyResult.ExitCode;
            result.Message = result.Success ? "Configuration applied successfully" : "Failed to apply configuration";

            _logger.LogInformation("Applied netplan config for {Interface}: {Success}", iface.Name, result.Success);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to apply netplan config for {Interface}", iface.Name);
            result.Success = false;
            result.Message = ex.Message;
        }

        return result;
    }

    public async Task<NetworkApplyResult> RestartNetworkingAsync()
    {
        var result = await _runner.RunAsync("netplan", "apply");
        return new NetworkApplyResult
        {
            Success = result.Success,
            Message = result.Success ? "Networking restarted" : "Failed to restart networking",
            Output = result.Output,
            ErrorOutput = result.Error,
            ExitCode = result.ExitCode
        };
    }

    public async Task<bool> ValidateConfigAsync(string config)
    {
        // Write to temp file and run netplan generate
        var tempFile = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(tempFile, config);

            // netplan generate validates the config
            var result = await _runner.RunAsync("netplan", "generate");
            return result.Success;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Config validation failed");
            return false;
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    private static string GetInterfaceSection(string name)
    {
        if (name.StartsWith("eth") || name.StartsWith("en"))
            return "ethernets";
        if (name.StartsWith("wlan") || name.StartsWith("wl"))
            return "wifis";
        if (name.StartsWith("bond"))
            return "bonds";
        if (name.StartsWith("br"))
            return "bridges";
        if (name.EndsWith(".") && int.TryParse(name.Split('.').Last(), out _))
            return "vlans";

        return "ethernets";
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

    /// <summary>
    /// Read the declared mode from /etc/netplan/*.yaml. Netplan nests interfaces
    /// under ethernets:/&lt;name&gt;: with `dhcp4: true|false`. We do a light
    /// indentation-aware scan (no YAML dependency): find the interface's block,
    /// then read its dhcp4 value. Returns "dhcp", "static", or null.
    /// </summary>
    public async Task<string?> DetectAddressingModeAsync(string interfaceName, CancellationToken ct = default)
    {
        try
        {
            if (!Directory.Exists(NetplanDir)) return null;
            // Later files override earlier (lexical order is netplan's merge order).
            var files = Directory.GetFiles(NetplanDir, "*.yaml").OrderBy(f => f, StringComparer.Ordinal);

            string? mode = null;
            foreach (var file in files)
            {
                string[] lines;
                try { lines = await File.ReadAllLinesAsync(file, ct); }
                catch (Exception ex) { _logger.LogDebug(ex, "Skipping unreadable netplan file {File}", file); continue; }

                int ifaceIndent = -1;
                for (int i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];
                    var trimmed = line.TrimStart();
                    if (trimmed.Length == 0 || trimmed[0] == '#') continue;
                    int indent = line.Length - trimmed.Length;

                    // Entering the interface's own block: "<name>:" as a mapping key.
                    if (ifaceIndent < 0 &&
                        (trimmed.StartsWith(interfaceName + ":", StringComparison.Ordinal)))
                    {
                        ifaceIndent = indent;
                        continue;
                    }
                    if (ifaceIndent < 0) continue;

                    // Left the block (dedent to <= the iface key indent on a non-empty line).
                    if (indent <= ifaceIndent) { ifaceIndent = -1; continue; }

                    if (trimmed.StartsWith("dhcp4:", StringComparison.Ordinal))
                    {
                        var val = trimmed["dhcp4:".Length..].Trim().ToLowerInvariant();
                        if (val is "true" or "yes") mode = "dhcp";
                        else if (val is "false" or "no") mode = "static";
                    }
                }
            }
            return mode;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not detect netplan addressing mode for {Interface}", interfaceName);
            return null;
        }
    }

}
