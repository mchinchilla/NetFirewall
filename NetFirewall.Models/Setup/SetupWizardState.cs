using RepoDb.Attributes;

namespace NetFirewall.Models.Setup;

/// <summary>
/// Tracks the state and progress of the initial setup wizard.
/// Only one row should exist in this table (singleton pattern).
/// </summary>
[Map("setup_wizard_state")]
public class SetupWizardState
{
    [Map("id")]
    public Guid Id { get; set; }

    /// <summary>
    /// Current step in the wizard (1-4)
    /// </summary>
    [Map("current_step")]
    public int CurrentStep { get; set; } = 1;

    /// <summary>
    /// Whether the wizard has been completed
    /// </summary>
    [Map("is_completed")]
    public bool IsCompleted { get; set; }

    /// <summary>
    /// Step 1: Network interfaces configuration as JSON
    /// </summary>
    [Map("interfaces_config")]
    public string? InterfacesConfigJson { get; set; }

    /// <summary>
    /// Step 2: LAN/DHCP configuration as JSON
    /// </summary>
    [Map("lan_config")]
    public string? LanConfigJson { get; set; }

    /// <summary>
    /// Step 3: Firewall rules configuration as JSON
    /// </summary>
    [Map("firewall_config")]
    public string? FirewallConfigJson { get; set; }

    /// <summary>
    /// Step 4: Optional services configuration as JSON
    /// </summary>
    [Map("services_config")]
    public string? ServicesConfigJson { get; set; }

    [Map("started_at")]
    public DateTime StartedAt { get; set; } = DateTime.UtcNow;

    [Map("completed_at")]
    public DateTime? CompletedAt { get; set; }

    [Map("updated_at")]
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Step 1: Interface configuration model
/// </summary>
public class WizardInterfaceConfig
{
    public string Name { get; set; } = string.Empty;
    public string Role { get; set; } = "disabled"; // wan_primary, wan_secondary, lan, vpn, disabled
    public string? IpAddress { get; set; }
    public string? SubnetMask { get; set; }
    public string? Gateway { get; set; }
    public bool UseDhcp { get; set; }
}

/// <summary>
/// Step 2: LAN subnet configuration model
/// </summary>
public class WizardLanConfig
{
    public string InterfaceName { get; set; } = string.Empty;
    public string ServerIp { get; set; } = string.Empty;
    public string SubnetMask { get; set; } = "255.255.255.0";
    public string NetworkCidr { get; set; } = string.Empty;
    public bool EnableDhcp { get; set; } = true;
    public string DhcpRangeStart { get; set; } = string.Empty;
    public string DhcpRangeEnd { get; set; } = string.Empty;
    public string? DomainName { get; set; }
    public int LeaseTime { get; set; } = 86400;
}

/// <summary>
/// Step 3: Firewall rules configuration model
/// </summary>
public class WizardFirewallConfig
{
    public bool EnableNat { get; set; } = true;
    public bool AllowSsh { get; set; } = true;
    public bool AllowIcmp { get; set; } = true;
    public bool AllowDhcp { get; set; } = true;
    public bool AllowDns { get; set; } = true;
    public bool AllowWebInterface { get; set; } = true;
    public int WebInterfacePort { get; set; } = 5000;
    public bool ForwardLanToWan { get; set; } = true;
    public bool BlockInvalidPackets { get; set; } = true;
}

/// <summary>
/// Step 4: Optional services configuration model
/// </summary>
public class WizardServicesConfig
{
    public bool EnableDnsForwarder { get; set; } = false;
    public string? UpstreamDns1 { get; set; } = "8.8.8.8";
    public string? UpstreamDns2 { get; set; } = "8.8.4.4";

    public bool EnableWireGuard { get; set; } = false;
    public string? WireGuardSubnet { get; set; } = "10.100.0.0/24";
    public int WireGuardPort { get; set; } = 51820;

    public bool EnableQos { get; set; } = false;
    public int? DownloadBandwidthMbps { get; set; }
    public int? UploadBandwidthMbps { get; set; }
}
