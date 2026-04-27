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

public sealed class Step1RowViewModel
{
    [Required] public string Name { get; set; } = string.Empty;
    public string? MacAddress { get; set; }
    public string? CurrentIp { get; set; }
    public string? CurrentGateway { get; set; }
    public string? SuggestedRole { get; set; }
    public bool IsUp { get; set; }

    [Required, RegularExpression("^(disabled|wan_primary|wan_secondary|lan|vpn)$")]
    public string Role { get; set; } = "disabled";

    public bool UseDhcp { get; set; }

    [IPv4(AllowEmpty = true)] public string? IpAddress { get; set; }
    [IPv4(AllowEmpty = true)] public string? SubnetMask { get; set; }
    [IPv4(AllowEmpty = true)] public string? Gateway { get; set; }
}

// ---------------- Step 2 — LAN / DHCP per LAN interface ----------------

public sealed class Step2ViewModel : IValidatableObject
{
    public List<Step2RowViewModel> Lans { get; set; } = new();

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        // Disallow overlapping CIDRs across LANs (very common foot-gun).
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var lan in Lans.Where(l => l.EnableDhcp && !string.IsNullOrEmpty(l.NetworkCidr)))
        {
            if (!seen.Add(lan.NetworkCidr))
                yield return new ValidationResult(
                    $"Subnet {lan.NetworkCidr} is configured on more than one LAN interface.",
                    new[] { nameof(Lans) });
        }
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
            UseDhcp = r.UseDhcp,
            IpAddress = r.IpAddress,
            SubnetMask = r.SubnetMask,
            Gateway = r.Gateway
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
        // shows every NIC that's plugged in, with role pre-selected from prior runs.
        var savedByName = (saved ?? new List<WizardInterfaceConfig>()).ToDictionary(c => c.Name, StringComparer.OrdinalIgnoreCase);
        var rows = detected.Select(d => new Step1RowViewModel
        {
            Name = d.Name,
            MacAddress = d.MacAddress,
            CurrentIp = d.CurrentIpAddress,
            CurrentGateway = d.CurrentGateway,
            SuggestedRole = d.SuggestedRole,
            IsUp = d.HasCarrier,
            Role = savedByName.TryGetValue(d.Name, out var s) ? s.Role : d.SuggestedRole,
            UseDhcp = savedByName.TryGetValue(d.Name, out var s2) ? s2.UseDhcp : false,
            IpAddress = savedByName.TryGetValue(d.Name, out var s3) ? s3.IpAddress : d.CurrentIpAddress,
            SubnetMask = savedByName.TryGetValue(d.Name, out var s4) ? s4.SubnetMask : d.CurrentSubnetMask,
            Gateway = savedByName.TryGetValue(d.Name, out var s5) ? s5.Gateway : d.CurrentGateway
        }).ToList();
        return new Step1ViewModel { Interfaces = rows };
    }

    public static Step2ViewModel ToViewModel(this List<WizardLanConfig>? saved, Step1ViewModel step1)
    {
        // One row per LAN-marked iface in step 1; pre-populate sensible defaults.
        var savedByName = (saved ?? new List<WizardLanConfig>()).ToDictionary(c => c.InterfaceName, StringComparer.OrdinalIgnoreCase);
        var lans = step1.Interfaces
            .Where(i => string.Equals(i.Role, "lan", StringComparison.OrdinalIgnoreCase))
            .Select((i, idx) =>
            {
                if (savedByName.TryGetValue(i.Name, out var s)) return Map(i.Name, s);
                // Sensible defaults: 192.168.{99-idx}.0/24, server is .1, range is .10–.250
                var third = 99 + idx;
                return new Step2RowViewModel
                {
                    InterfaceName = i.Name,
                    EnableDhcp = true,
                    ServerIp = $"192.168.{third}.1",
                    SubnetMask = "255.255.255.0",
                    NetworkCidr = $"192.168.{third}.0/24",
                    DhcpRangeStart = $"192.168.{third}.10",
                    DhcpRangeEnd = $"192.168.{third}.250",
                    DomainName = "lan.local",
                    LeaseTime = 86400
                };
            }).ToList();
        return new Step2ViewModel { Lans = lans };
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
