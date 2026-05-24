using System.ComponentModel.DataAnnotations;
using NetFirewall.Models.Setup;
using NetFirewall.Services.Setup;
using NetFirewall.Web.Models.Network;

namespace NetFirewall.Web.Models.Setup;

/// <summary>Top-level model for the wizard page (step + saved state + detected interfaces).</summary>
public sealed class WizardPageViewModel
{
    /// <summary>Step currently rendered. May be earlier than <see cref="MaxUnlockedStep"/> if the user jumped back.</summary>
    public required int CurrentStep { get; init; }

    /// <summary>Highest step the wizard service has unlocked. The Stepper renders steps &lt;= this as clickable.</summary>
    public required int MaxUnlockedStep { get; init; }

    public required bool IsCompleted { get; init; }
    public required IReadOnlyList<DetectedNetworkInterface> Detected { get; init; }
    public required Step1ViewModel Step1 { get; init; }
    public required Step2ViewModel Step2 { get; init; }
    public required Step3ViewModel Step3 { get; init; }
    public required Step4ViewModel Step4 { get; init; }
}

// ---------------- Step 1 — Network interface roles ----------------

public sealed class Step1ViewModel
{
    public List<Step1RowViewModel> Interfaces { get; set; } = new();
}

public sealed class Step1RowViewModel : IValidatableObject
{
    [Required] public string Name { get; set; } = string.Empty;
    public string? MacAddress { get; set; }
    public string? CurrentIp { get; set; }
    public string? CurrentGateway { get; set; }
    public string? SuggestedRole { get; set; }
    public int Confidence { get; set; }
    public string? Reason { get; set; }
    public bool IsUp { get; set; }
    public bool IsVirtual { get; set; }

    [Required, RegularExpression("^(disabled|wan_primary|wan_secondary|lan|vpn)$")]
    public string Role { get; set; } = "disabled";

    /// <summary>"dhcp" | "static" | "disabled". Backs the addressing radio in the form.</summary>
    [Required, RegularExpression("^(dhcp|static|disabled)$")]
    public string AddressingMode { get; set; } = "dhcp";

    [IPv4(AllowEmpty = true)] public string? IpAddress { get; set; }
    [IPv4(AllowEmpty = true)] public string? SubnetMask { get; set; }
    [IPv4(AllowEmpty = true)] public string? Gateway { get; set; }

    [Range(576, 9216, ErrorMessage = "MTU must be between 576 and 9216.")]
    public int? Mtu { get; set; }

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        // Static addressing must include an IP + mask. Gateway is required for WAN
        // (no gateway → no default route → the firewall can't reach the internet).
        if (AddressingMode == "static" && Role != "disabled")
        {
            if (string.IsNullOrWhiteSpace(IpAddress))
                yield return new ValidationResult("IP address is required for static addressing.", new[] { nameof(IpAddress) });
            if (string.IsNullOrWhiteSpace(SubnetMask))
                yield return new ValidationResult("Subnet mask is required for static addressing.", new[] { nameof(SubnetMask) });
            if (Role is "wan_primary" or "wan_secondary" && string.IsNullOrWhiteSpace(Gateway))
                yield return new ValidationResult("Gateway is required for WAN interfaces with static addressing.", new[] { nameof(Gateway) });
        }
    }
}

// ---------------- Step 2 — LAN / DHCP per LAN interface ----------------

public sealed class Step2ViewModel : IValidatableObject
{
    public List<Step2RowViewModel> Lans { get; set; } = new();

    /// <summary>WAN CIDRs detected/configured in Step 1, so the view can warn on overlap.</summary>
    public List<string> WanCidrs { get; set; } = new();

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        // Foot-gun #1: same CIDR on two LAN interfaces — DHCP/routing breaks silently.
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var lan in Lans.Where(l => l.EnableDhcp && !string.IsNullOrEmpty(l.NetworkCidr)))
        {
            if (!seen.Add(lan.NetworkCidr))
                yield return new ValidationResult(
                    $"Subnet {lan.NetworkCidr} is configured on more than one LAN interface.",
                    new[] { nameof(Lans) });
        }

        // Foot-gun #2: LAN subnet overlaps the WAN — the firewall can't decide which iface to route through.
        foreach (var lan in Lans.Where(l => l.EnableDhcp && !string.IsNullOrEmpty(l.NetworkCidr)))
        {
            foreach (var wan in WanCidrs)
            {
                if (CidrOverlap(lan.NetworkCidr, wan))
                {
                    yield return new ValidationResult(
                        $"LAN subnet {lan.NetworkCidr} overlaps with WAN subnet {wan}.",
                        new[] { nameof(Lans) });
                }
            }
        }
    }

    /// <summary>True when two CIDR ranges share at least one address.</summary>
    public static bool CidrOverlap(string a, string b)
    {
        if (!TryParseCidr(a, out var aNet, out var aPrefix)) return false;
        if (!TryParseCidr(b, out var bNet, out var bPrefix)) return false;
        var minPrefix = Math.Min(aPrefix, bPrefix);
        var mask = minPrefix == 0 ? 0u : 0xFFFFFFFFu << (32 - minPrefix);
        return (aNet & mask) == (bNet & mask);
    }

    private static bool TryParseCidr(string s, out uint network, out int prefix)
    {
        network = 0; prefix = 0;
        var slash = s.IndexOf('/');
        if (slash < 0) return false;
        if (!System.Net.IPAddress.TryParse(s[..slash], out var ip)) return false;
        if (!int.TryParse(s[(slash + 1)..], out prefix) || prefix < 0 || prefix > 32) return false;
        var bytes = ip.GetAddressBytes();
        if (bytes.Length != 4) return false;
        network = ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
        return true;
    }
}

public sealed class Step2RowViewModel
{
    [Required] public string InterfaceName { get; set; } = string.Empty;
    public bool EnableDhcp { get; set; } = true;

    [IPv4] public string ServerIp { get; set; } = string.Empty;
    [IPv4] public string SubnetMask { get; set; } = "255.255.255.0";

    [Required, RegularExpression(@"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$",
        ErrorMessage = "CIDR notation required, e.g. 192.168.99.0/24")]
    public string NetworkCidr { get; set; } = string.Empty;

    [IPv4] public string DhcpRangeStart { get; set; } = string.Empty;
    [IPv4] public string DhcpRangeEnd { get; set; } = string.Empty;

    [StringLength(255)] public string? DomainName { get; set; }

    [Range(60, 7 * 24 * 3600, ErrorMessage = "Lease time must be 60s – 7 days.")]
    public int LeaseTime { get; set; } = 86400;
}

// ---------------- Step 3 — Firewall toggles ----------------

public sealed class Step3ViewModel
{
    public bool EnableNat { get; set; } = true;
    public bool AllowSsh { get; set; } = true;
    public bool AllowIcmp { get; set; } = true;
    public bool AllowDhcp { get; set; } = true;
    public bool AllowDns { get; set; } = true;
    public bool AllowWebInterface { get; set; } = true;

    [Range(1, 65535)] public int WebInterfacePort { get; set; } = 5000;

    public bool ForwardLanToWan { get; set; } = true;
    public bool BlockInvalidPackets { get; set; } = true;
}

// ---------------- Step 4 — Optional services ----------------

public sealed class Step4ViewModel : IValidatableObject
{
    public bool EnableDnsForwarder { get; set; }
    [IPv4(AllowEmpty = true)] public string? UpstreamDns1 { get; set; } = "8.8.8.8";
    [IPv4(AllowEmpty = true)] public string? UpstreamDns2 { get; set; } = "8.8.4.4";

    public bool EnableWireGuard { get; set; }

    [RegularExpression(@"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$", ErrorMessage = "WireGuard subnet must be CIDR notation.")]
    public string? WireGuardSubnet { get; set; } = "10.100.0.0/24";

    [Range(1, 65535)] public int WireGuardPort { get; set; } = 51820;

    public bool EnableQos { get; set; }
    [Range(1, 100000)] public int? DownloadBandwidthMbps { get; set; }
    [Range(1, 100000)] public int? UploadBandwidthMbps { get; set; }

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (EnableDnsForwarder && string.IsNullOrWhiteSpace(UpstreamDns1))
            yield return new ValidationResult("Upstream DNS 1 is required when DNS forwarder is enabled.",
                new[] { nameof(UpstreamDns1) });

        if (EnableQos && (!DownloadBandwidthMbps.HasValue || !UploadBandwidthMbps.HasValue))
            yield return new ValidationResult("Download + upload bandwidth required when QoS is enabled.",
                new[] { nameof(DownloadBandwidthMbps) });
    }
}

// ---------------- Mappers between view-model rows and the wizard service DTOs ----------------

public static class WizardMappers
{
    public static List<WizardInterfaceConfig> ToServiceModel(this Step1ViewModel vm) =>
        vm.Interfaces.Select(r => new WizardInterfaceConfig
        {
            Name = r.Name,
            Role = r.Role,
            AddressingMode = r.AddressingMode,
            IpAddress = r.IpAddress,
            SubnetMask = r.SubnetMask,
            Gateway = r.Gateway,
            Mtu = r.Mtu
        }).ToList();

    public static List<WizardLanConfig> ToServiceModel(this Step2ViewModel vm) =>
        vm.Lans.Select(r => new WizardLanConfig
        {
            InterfaceName = r.InterfaceName,
            ServerIp = r.ServerIp,
            SubnetMask = r.SubnetMask,
            NetworkCidr = r.NetworkCidr,
            EnableDhcp = r.EnableDhcp,
            DhcpRangeStart = r.DhcpRangeStart,
            DhcpRangeEnd = r.DhcpRangeEnd,
            DomainName = r.DomainName,
            LeaseTime = r.LeaseTime
        }).ToList();

    public static WizardFirewallConfig ToServiceModel(this Step3ViewModel vm) => new()
    {
        EnableNat = vm.EnableNat,
        AllowSsh = vm.AllowSsh,
        AllowIcmp = vm.AllowIcmp,
        AllowDhcp = vm.AllowDhcp,
        AllowDns = vm.AllowDns,
        AllowWebInterface = vm.AllowWebInterface,
        WebInterfacePort = vm.WebInterfacePort,
        ForwardLanToWan = vm.ForwardLanToWan,
        BlockInvalidPackets = vm.BlockInvalidPackets
    };

    public static WizardServicesConfig ToServiceModel(this Step4ViewModel vm) => new()
    {
        EnableDnsForwarder = vm.EnableDnsForwarder,
        UpstreamDns1 = vm.UpstreamDns1,
        UpstreamDns2 = vm.UpstreamDns2,
        EnableWireGuard = vm.EnableWireGuard,
        WireGuardSubnet = vm.WireGuardSubnet,
        WireGuardPort = vm.WireGuardPort,
        EnableQos = vm.EnableQos,
        DownloadBandwidthMbps = vm.DownloadBandwidthMbps,
        UploadBandwidthMbps = vm.UploadBandwidthMbps
    };

    public static Step1ViewModel ToViewModel(this List<WizardInterfaceConfig>? saved, IReadOnlyList<DetectedNetworkInterface> detected)
    {
        // Merge saved choices with currently-detected interfaces so the form
        // shows every NIC the kernel sees, with role pre-selected from prior runs.
        // If a NIC was saved but is no longer plugged in, we still keep it as a
        // disabled-grey row so the operator can decide what to do with the stale entry.
        var savedByName = (saved ?? new List<WizardInterfaceConfig>())
            .ToDictionary(c => c.Name, StringComparer.OrdinalIgnoreCase);
        var detectedByName = detected.ToDictionary(d => d.Name, StringComparer.OrdinalIgnoreCase);

        var rows = detected.Select(d =>
        {
            savedByName.TryGetValue(d.Name, out var s);
            return new Step1RowViewModel
            {
                Name = d.Name,
                MacAddress = d.MacAddress,
                CurrentIp = d.CurrentIpAddress,
                CurrentGateway = d.CurrentGateway,
                SuggestedRole = d.SuggestedRole,
                Confidence = d.Confidence,
                Reason = d.Reason,
                IsUp = d.HasCarrier,
                IsVirtual = d.IsVirtual,
                Role = s?.Role ?? d.SuggestedRole,
                AddressingMode = s?.AddressingMode ?? SuggestAddressingMode(d),
                IpAddress = s?.IpAddress ?? d.CurrentIpAddress,
                SubnetMask = s?.SubnetMask ?? d.CurrentSubnetMask,
                Gateway = s?.Gateway ?? d.CurrentGateway,
                Mtu = s?.Mtu ?? d.Mtu
            };
        }).ToList();

        // Surface saved-but-missing NICs at the end so the operator notices.
        foreach (var s in savedByName.Values.Where(c => !detectedByName.ContainsKey(c.Name)))
        {
            rows.Add(new Step1RowViewModel
            {
                Name = s.Name,
                Role = s.Role,
                AddressingMode = s.AddressingMode,
                IpAddress = s.IpAddress,
                SubnetMask = s.SubnetMask,
                Gateway = s.Gateway,
                Mtu = s.Mtu,
                SuggestedRole = "disabled",
                Confidence = 0,
                Reason = "Saved configuration; kernel no longer reports this NIC.",
                IsUp = false
            });
        }

        return new Step1ViewModel { Interfaces = rows };
    }

    /// <summary>WAN with a current gateway → DHCP (typical ISP). Otherwise default to static so the form prompts for an IP.</summary>
    private static string SuggestAddressingMode(DetectedNetworkInterface d) =>
        d.SuggestedRole.StartsWith("wan", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(d.CurrentGateway)
            ? "dhcp"
            : (d.SuggestedRole == "disabled" ? "disabled" : "static");

    public static Step2ViewModel ToViewModel(this List<WizardLanConfig>? saved, Step1ViewModel step1)
    {
        var savedByName = (saved ?? new List<WizardLanConfig>())
            .ToDictionary(c => c.InterfaceName, StringComparer.OrdinalIgnoreCase);

        // Pre-compute "occupied" CIDRs from Step 1 so LAN defaults pick a slot
        // that doesn't collide with the WAN. Saved-LAN choices keep their CIDR;
        // newly-suggested LANs walk 192.168.10..254 looking for a free /24.
        var occupied = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var wanCidrs = new List<string>();
        foreach (var i in step1.Interfaces.Where(x => x.AddressingMode == "static" && !string.IsNullOrEmpty(x.IpAddress)))
        {
            var cidr = CidrFromIpMask(i.IpAddress, i.SubnetMask);
            if (cidr is null) continue;
            occupied.Add(cidr);
            if (i.Role is "wan_primary" or "wan_secondary") wanCidrs.Add(cidr);
        }
        // Saved LAN CIDRs are already taken even if not present in Step 1 static config.
        foreach (var s in savedByName.Values.Where(v => !string.IsNullOrEmpty(v.NetworkCidr)))
            occupied.Add(s.NetworkCidr);

        int nextThird = 10;
        string NextFreeSlash24()
        {
            while (nextThird < 255)
            {
                var candidate = $"192.168.{nextThird}.0/24";
                nextThird++;
                if (!occupied.Any(o => Step2ViewModel.CidrOverlap(o, candidate)))
                {
                    occupied.Add(candidate);
                    return candidate;
                }
            }
            return "10.99.0.0/24"; // unlikely fallback when 192.168 space is exhausted
        }

        var lans = step1.Interfaces
            .Where(i => string.Equals(i.Role, "lan", StringComparison.OrdinalIgnoreCase))
            .Select(i =>
            {
                if (savedByName.TryGetValue(i.Name, out var s)) return Map(i.Name, s);

                var cidr = NextFreeSlash24();
                var third = int.Parse(cidr.Split('.')[2]);
                return new Step2RowViewModel
                {
                    InterfaceName = i.Name,
                    EnableDhcp = true,
                    ServerIp = $"192.168.{third}.1",
                    SubnetMask = "255.255.255.0",
                    NetworkCidr = cidr,
                    DhcpRangeStart = $"192.168.{third}.10",
                    DhcpRangeEnd = $"192.168.{third}.250",
                    DomainName = "lan.local",
                    LeaseTime = 86400
                };
            }).ToList();

        return new Step2ViewModel { Lans = lans, WanCidrs = wanCidrs };
    }

    /// <summary>"10.0.0.5" + "255.255.255.0" → "10.0.0.0/24". Returns null on parse failure.</summary>
    private static string? CidrFromIpMask(string? ip, string? mask)
    {
        if (string.IsNullOrEmpty(ip) || string.IsNullOrEmpty(mask)) return null;
        if (!System.Net.IPAddress.TryParse(ip, out var ipAddr) || !System.Net.IPAddress.TryParse(mask, out var maskAddr)) return null;
        var ipB = ipAddr.GetAddressBytes();
        var mB = maskAddr.GetAddressBytes();
        if (ipB.Length != 4 || mB.Length != 4) return null;
        var netB = new byte[4];
        for (int k = 0; k < 4; k++) netB[k] = (byte)(ipB[k] & mB[k]);
        var prefix = mB.Sum(b => System.Numerics.BitOperations.PopCount(b));
        return $"{new System.Net.IPAddress(netB)}/{prefix}";
    }

    public static Step3ViewModel ToViewModel(this WizardFirewallConfig? saved) => saved is null
        ? new Step3ViewModel()
        : new Step3ViewModel
        {
            EnableNat = saved.EnableNat,
            AllowSsh = saved.AllowSsh,
            AllowIcmp = saved.AllowIcmp,
            AllowDhcp = saved.AllowDhcp,
            AllowDns = saved.AllowDns,
            AllowWebInterface = saved.AllowWebInterface,
            WebInterfacePort = saved.WebInterfacePort,
            ForwardLanToWan = saved.ForwardLanToWan,
            BlockInvalidPackets = saved.BlockInvalidPackets
        };

    public static Step4ViewModel ToViewModel(this WizardServicesConfig? saved) => saved is null
        ? new Step4ViewModel()
        : new Step4ViewModel
        {
            EnableDnsForwarder = saved.EnableDnsForwarder,
            UpstreamDns1 = saved.UpstreamDns1,
            UpstreamDns2 = saved.UpstreamDns2,
            EnableWireGuard = saved.EnableWireGuard,
            WireGuardSubnet = saved.WireGuardSubnet,
            WireGuardPort = saved.WireGuardPort,
            EnableQos = saved.EnableQos,
            DownloadBandwidthMbps = saved.DownloadBandwidthMbps,
            UploadBandwidthMbps = saved.UploadBandwidthMbps
        };

    private static Step2RowViewModel Map(string name, WizardLanConfig s) => new()
    {
        InterfaceName = name,
        EnableDhcp = s.EnableDhcp,
        ServerIp = s.ServerIp,
        SubnetMask = s.SubnetMask,
        NetworkCidr = s.NetworkCidr,
        DhcpRangeStart = s.DhcpRangeStart,
        DhcpRangeEnd = s.DhcpRangeEnd,
        DomainName = s.DomainName,
        LeaseTime = s.LeaseTime
    };
}
