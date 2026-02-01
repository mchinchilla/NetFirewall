using System.Net;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.System;

namespace NetFirewall.Services.Network;

public sealed partial class LinuxDistroService : ILinuxDistroService
{
    private readonly ILogger<LinuxDistroService> _logger;
    private LinuxDistroInfo? _cachedDistroInfo;

    public LinuxDistroService(ILogger<LinuxDistroService> logger)
    {
        _logger = logger;
    }

    public async Task<LinuxDistroInfo> DetectDistributionAsync(CancellationToken ct = default)
    {
        if (_cachedDistroInfo != null)
            return _cachedDistroInfo;

        var info = new LinuxDistroInfo();

        try
        {
            // Read /etc/os-release for distribution info
            const string osReleasePath = "/etc/os-release";
            if (File.Exists(osReleasePath))
            {
                var content = await File.ReadAllTextAsync(osReleasePath, ct);
                info.Id = ParseOsReleaseValue(content, "ID") ?? "unknown";
                info.Name = ParseOsReleaseValue(content, "NAME")?.Trim('"') ?? "Unknown";
                info.Version = ParseOsReleaseValue(content, "VERSION_ID")?.Trim('"') ?? "";
                info.VersionCodename = ParseOsReleaseValue(content, "VERSION_CODENAME") ?? "";

                // Determine family
                info.Family = info.Id.ToLowerInvariant() switch
                {
                    "debian" => DistroFamily.Debian,
                    "ubuntu" => DistroFamily.Debian,
                    "linuxmint" => DistroFamily.Debian,
                    "raspbian" => DistroFamily.Debian,
                    "fedora" => DistroFamily.RedHat,
                    "rhel" => DistroFamily.RedHat,
                    "centos" => DistroFamily.RedHat,
                    "rocky" => DistroFamily.RedHat,
                    "alma" => DistroFamily.RedHat,
                    "arch" => DistroFamily.Arch,
                    "manjaro" => DistroFamily.Arch,
                    "alpine" => DistroFamily.Alpine,
                    _ => DistroFamily.Unknown
                };
            }

            // Determine network configuration method
            info.ConfigMethod = DetermineConfigMethod(info);

            _logger.LogInformation("Detected distribution: {Name} {Version} ({Id}), config method: {Method}",
                info.Name, info.Version, info.Id, info.ConfigMethod);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to detect Linux distribution, running on non-Linux?");

            // Return macOS/Windows compatible defaults for development
            info.Id = Environment.OSVersion.Platform == PlatformID.Unix ? "linux" : "windows";
            info.Name = Environment.OSVersion.VersionString;
            info.ConfigMethod = NetworkConfigMethod.Unknown;
        }

        _cachedDistroInfo = info;
        return info;
    }

    public async Task<IReadOnlyList<InterfaceSuggestion>> DiscoverInterfacesAsync(CancellationToken ct = default)
    {
        var suggestions = new List<InterfaceSuggestion>();

        try
        {
            // Try to read from /sys/class/net on Linux
            const string netClassPath = "/sys/class/net";
            if (Directory.Exists(netClassPath))
            {
                var interfaceDirs = Directory.GetDirectories(netClassPath);
                foreach (var dir in interfaceDirs)
                {
                    var name = Path.GetFileName(dir);
                    if (name == "lo") continue; // Skip loopback

                    var suggestion = await AnalyzeInterfaceFromSysFs(name, ct);
                    suggestions.Add(suggestion);
                }
            }
            else
            {
                // Fallback: use .NET NetworkInterface API (works on all platforms)
                var interfaces = NetworkInterface.GetAllNetworkInterfaces();
                foreach (var ni in interfaces)
                {
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                    var suggestion = AnalyzeNetworkInterface(ni);
                    suggestions.Add(suggestion);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to discover network interfaces");
        }

        return suggestions;
    }

    public async Task<InterfaceSuggestion> AnalyzeInterfaceAsync(string name, CancellationToken ct = default)
    {
        const string netClassPath = "/sys/class/net";
        if (Directory.Exists(Path.Combine(netClassPath, name)))
        {
            return await AnalyzeInterfaceFromSysFs(name, ct);
        }

        // Fallback to .NET API
        var ni = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(n => n.Name == name);

        if (ni != null)
            return AnalyzeNetworkInterface(ni);

        return new InterfaceSuggestion
        {
            Name = name,
            SuggestedType = "LAN",
            SuggestedRole = "local_network",
            Confidence = 0,
            Reason = "Interface not found"
        };
    }

    private async Task<InterfaceSuggestion> AnalyzeInterfaceFromSysFs(string name, CancellationToken ct)
    {
        var basePath = $"/sys/class/net/{name}";
        var suggestion = new InterfaceSuggestion { Name = name };

        try
        {
            // Read MAC address
            var addressPath = Path.Combine(basePath, "address");
            if (File.Exists(addressPath))
            {
                suggestion.MacAddress = (await File.ReadAllTextAsync(addressPath, ct)).Trim();
            }

            // Check if interface is up
            var operstatePath = Path.Combine(basePath, "operstate");
            if (File.Exists(operstatePath))
            {
                var state = (await File.ReadAllTextAsync(operstatePath, ct)).Trim();
                suggestion.IsUp = state == "up";
            }

            // Read MTU
            var mtuPath = Path.Combine(basePath, "mtu");
            if (File.Exists(mtuPath))
            {
                if (int.TryParse((await File.ReadAllTextAsync(mtuPath, ct)).Trim(), out var mtu))
                    suggestion.Mtu = mtu;
            }

            // Check if virtual
            var devicePath = Path.Combine(basePath, "device");
            suggestion.IsVirtual = !Directory.Exists(devicePath);

            // Get IP info from ip command
            await GetIpInfoAsync(name, suggestion, ct);

            // Analyze and suggest type
            AnalyzeSuggestion(suggestion);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error analyzing interface {Name}", name);
            suggestion.Confidence = 0;
            suggestion.Reason = "Error reading interface info";
        }

        return suggestion;
    }

    private InterfaceSuggestion AnalyzeNetworkInterface(NetworkInterface ni)
    {
        var suggestion = new InterfaceSuggestion
        {
            Name = ni.Name,
            MacAddress = BitConverter.ToString(ni.GetPhysicalAddress().GetAddressBytes()).Replace("-", ":").ToLower(),
            IsUp = ni.OperationalStatus == OperationalStatus.Up,
            IsVirtual = ni.NetworkInterfaceType == NetworkInterfaceType.Tunnel ||
                        ni.NetworkInterfaceType == NetworkInterfaceType.Ppp
        };

        // Get IP addresses
        var ipProps = ni.GetIPProperties();
        var unicast = ipProps.UnicastAddresses
            .FirstOrDefault(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);

        if (unicast != null)
        {
            suggestion.CurrentIp = unicast.Address;
            suggestion.CurrentSubnet = $"{unicast.Address}/{GetPrefixLength(unicast.IPv4Mask)}";
        }

        // Get gateway
        var gateway = ipProps.GatewayAddresses
            .FirstOrDefault(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork);
        if (gateway != null)
        {
            suggestion.CurrentGateway = gateway.Address;
        }

        AnalyzeSuggestion(suggestion);
        return suggestion;
    }

    private async Task GetIpInfoAsync(string name, InterfaceSuggestion suggestion, CancellationToken ct)
    {
        try
        {
            // Use ip addr show to get IP info
            var process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "ip",
                    Arguments = $"-4 addr show {name}",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync(ct);
            await process.WaitForExitAsync(ct);

            // Parse inet line: inet 192.168.1.1/24 ...
            var inetMatch = InetRegex().Match(output);
            if (inetMatch.Success)
            {
                var ipCidr = inetMatch.Groups[1].Value;
                suggestion.CurrentSubnet = ipCidr;
                var parts = ipCidr.Split('/');
                if (IPAddress.TryParse(parts[0], out var ip))
                    suggestion.CurrentIp = ip;
            }

            // Get default route through this interface
            process = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "ip",
                    Arguments = $"-4 route show dev {name}",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            output = await process.StandardOutput.ReadToEndAsync(ct);
            await process.WaitForExitAsync(ct);

            // Parse default route: default via 192.168.1.254 ...
            var defaultMatch = DefaultRouteRegex().Match(output);
            if (defaultMatch.Success)
            {
                if (IPAddress.TryParse(defaultMatch.Groups[1].Value, out var gw))
                    suggestion.CurrentGateway = gw;
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not get IP info for {Name}", name);
        }
    }

    private void AnalyzeSuggestion(InterfaceSuggestion suggestion)
    {
        int score = 0;
        var reasons = new List<string>();

        var name = suggestion.Name.ToLowerInvariant();

        // Name-based analysis
        if (name.StartsWith("wan") || name.StartsWith("ppp") || name == "eth0" || name == "ens192")
        {
            score += 30;
            reasons.Add("Name suggests WAN");
            suggestion.SuggestedType = "WAN";
        }
        else if (name.StartsWith("lan") || name.StartsWith("br") || name == "eth1" || name == "ens224" || name == "ens256")
        {
            score += 30;
            reasons.Add("Name suggests LAN");
            suggestion.SuggestedType = "LAN";
        }
        else if (name.StartsWith("wg") || name.StartsWith("tun") || name.StartsWith("tap"))
        {
            score += 50;
            reasons.Add("VPN interface name");
            suggestion.SuggestedType = "VPN";
            suggestion.SuggestedRole = name.StartsWith("wg") ? "wireguard_tunnel" : "openvpn_tunnel";
        }
        else if (name.StartsWith("veth") || name.StartsWith("docker") || name.StartsWith("vir"))
        {
            score += 20;
            reasons.Add("Container/VM interface");
            suggestion.SuggestedType = "LAN";
            suggestion.IsVirtual = true;
        }

        // Gateway analysis - strong indicator of WAN
        if (suggestion.CurrentGateway != null)
        {
            score += 40;
            reasons.Add("Has default gateway");
            if (string.IsNullOrEmpty(suggestion.SuggestedType) || suggestion.SuggestedType != "VPN")
                suggestion.SuggestedType = "WAN";
        }

        // IP analysis
        if (suggestion.CurrentIp != null)
        {
            var ip = suggestion.CurrentIp;
            var bytes = ip.GetAddressBytes();

            // Check for public IP
            bool isPrivate = (bytes[0] == 10) ||
                            (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                            (bytes[0] == 192 && bytes[1] == 168) ||
                            (bytes[0] == 169 && bytes[1] == 254); // link-local

            if (!isPrivate)
            {
                score += 50;
                reasons.Add("Has public IP");
                suggestion.SuggestedType = "WAN";
            }
            else if (suggestion.CurrentGateway == null)
            {
                score += 30;
                reasons.Add("Private IP without gateway");
                if (string.IsNullOrEmpty(suggestion.SuggestedType))
                    suggestion.SuggestedType = "LAN";
            }
        }

        // Set defaults if not determined
        if (string.IsNullOrEmpty(suggestion.SuggestedType))
        {
            suggestion.SuggestedType = "LAN";
            score = Math.Max(score, 20);
            reasons.Add("Default to LAN");
        }

        // Set role based on type
        if (string.IsNullOrEmpty(suggestion.SuggestedRole))
        {
            suggestion.SuggestedRole = suggestion.SuggestedType switch
            {
                "WAN" => "primary_wan",
                "LAN" => "local_network",
                "VPN" => "wireguard_tunnel",
                _ => "local_network"
            };
        }

        suggestion.Confidence = Math.Min(100, score);
        suggestion.Reason = string.Join("; ", reasons);
    }

    private static NetworkConfigMethod DetermineConfigMethod(LinuxDistroInfo info)
    {
        // Ubuntu 18.04+ uses netplan
        if (info.Id.Equals("ubuntu", StringComparison.OrdinalIgnoreCase) &&
            Directory.Exists("/etc/netplan"))
        {
            return NetworkConfigMethod.Netplan;
        }

        // Debian and derivatives use /etc/network/interfaces
        if (info.Family == DistroFamily.Debian &&
            File.Exists("/etc/network/interfaces"))
        {
            return NetworkConfigMethod.Interfaces;
        }

        // Check for files as fallback
        if (Directory.Exists("/etc/netplan"))
            return NetworkConfigMethod.Netplan;

        if (File.Exists("/etc/network/interfaces"))
            return NetworkConfigMethod.Interfaces;

        return NetworkConfigMethod.Unknown;
    }

    private static string? ParseOsReleaseValue(string content, string key)
    {
        var lines = content.Split('\n');
        foreach (var line in lines)
        {
            if (line.StartsWith($"{key}=", StringComparison.OrdinalIgnoreCase))
            {
                return line[(key.Length + 1)..].Trim().Trim('"');
            }
        }
        return null;
    }

    private static int GetPrefixLength(IPAddress mask)
    {
        var bytes = mask.GetAddressBytes();
        int prefix = 0;
        foreach (var b in bytes)
        {
            for (int i = 7; i >= 0; i--)
            {
                if ((b & (1 << i)) != 0)
                    prefix++;
                else
                    return prefix;
            }
        }
        return prefix;
    }

    [GeneratedRegex(@"inet (\d+\.\d+\.\d+\.\d+/\d+)")]
    private static partial Regex InetRegex();

    [GeneratedRegex(@"default via (\d+\.\d+\.\d+\.\d+)")]
    private static partial Regex DefaultRouteRegex();
}
