using System.Net.NetworkInformation;
using NetFirewall.Models.Setup;

namespace NetFirewall.Services.Setup;

/// <summary>
/// Service for managing the initial setup wizard.
/// </summary>
public interface ISetupWizardService
{
    /// <summary>
    /// Check if the setup wizard has been completed.
    /// </summary>
    Task<bool> IsWizardCompletedAsync(CancellationToken ct = default);

    /// <summary>
    /// Get the current wizard state, creating one if it doesn't exist.
    /// </summary>
    Task<SetupWizardState> GetOrCreateWizardStateAsync(CancellationToken ct = default);

    /// <summary>
    /// Update the wizard state.
    /// </summary>
    Task<SetupWizardState> UpdateWizardStateAsync(SetupWizardState state, CancellationToken ct = default);

    /// <summary>
    /// Detect all network interfaces on the system.
    /// </summary>
    Task<IReadOnlyList<DetectedNetworkInterface>> DetectNetworkInterfacesAsync(CancellationToken ct = default);

    /// <summary>
    /// Apply Step 1: Save interface configurations to fw_interfaces.
    /// </summary>
    Task ApplyInterfaceConfigAsync(List<WizardInterfaceConfig> configs, CancellationToken ct = default);

    /// <summary>
    /// Apply Step 2: Create DHCP subnets and pools for LAN interfaces.
    /// </summary>
    Task ApplyLanConfigAsync(List<WizardLanConfig> configs, CancellationToken ct = default);

    /// <summary>
    /// Apply Step 3: Create firewall rules.
    /// </summary>
    Task ApplyFirewallConfigAsync(WizardFirewallConfig config, List<WizardInterfaceConfig> interfaces, CancellationToken ct = default);

    /// <summary>
    /// Apply Step 4: Configure optional services.
    /// </summary>
    Task ApplyServicesConfigAsync(WizardServicesConfig config, CancellationToken ct = default);

    /// <summary>
    /// Mark the wizard as completed.
    /// </summary>
    Task CompleteWizardAsync(CancellationToken ct = default);

    /// <summary>
    /// Reset the wizard to start fresh.
    /// </summary>
    Task ResetWizardAsync(CancellationToken ct = default);

    // ------------------------------------------------------------------
    // Typed step accessors. Controllers call these instead of touching
    // the JSON columns directly (project rule #10 — no SQL/parsing in
    // controllers). Returns null when the step has not been saved yet.
    // ------------------------------------------------------------------

    Task<List<WizardInterfaceConfig>?> GetStep1InterfacesAsync(CancellationToken ct = default);
    Task<List<WizardLanConfig>?>       GetStep2LanAsync(CancellationToken ct = default);
    Task<WizardFirewallConfig?>        GetStep3FirewallAsync(CancellationToken ct = default);
    Task<WizardServicesConfig?>        GetStep4ServicesAsync(CancellationToken ct = default);

    Task SaveStep1InterfacesAsync(List<WizardInterfaceConfig> configs, CancellationToken ct = default);
    Task SaveStep2LanAsync(List<WizardLanConfig> configs, CancellationToken ct = default);
    Task SaveStep3FirewallAsync(WizardFirewallConfig config, CancellationToken ct = default);
    Task SaveStep4ServicesAsync(WizardServicesConfig config, CancellationToken ct = default);

    /// <summary>Advance the saved current_step pointer (1-5; 5 = complete summary).</summary>
    Task SetCurrentStepAsync(int step, CancellationToken ct = default);
}

/// <summary>
/// Represents a detected network interface from the system.
/// </summary>
public class DetectedNetworkInterface
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public NetworkInterfaceType Type { get; set; }
    public OperationalStatus Status { get; set; }
    public string? CurrentIpAddress { get; set; }
    public string? CurrentSubnetMask { get; set; }
    public string? CurrentGateway { get; set; }
    public bool HasCarrier { get; set; }
    public long SpeedMbps { get; set; }

    /// <summary>Suggested role based on interface characteristics.</summary>
    public string SuggestedRole { get; set; } = "disabled";

    /// <summary>0-100 confidence in the suggested role from the distro analyzer.</summary>
    public int Confidence { get; set; }

    /// <summary>Human-readable explanation of why this role was suggested (semicolon-joined heuristics).</summary>
    public string? Reason { get; set; }

    /// <summary>MTU read from sysfs (typically 1500 for Ethernet, 1420 for WireGuard).</summary>
    public int? Mtu { get; set; }

    /// <summary>True when the kernel reports the iface as virtual (no /sys/class/net/X/device).</summary>
    public bool IsVirtual { get; set; }

    /// <summary>
    /// DECLARED addressing mode ("dhcp"/"static"/"disabled") read from the system
    /// network config by the daemon, or null if undetermined. The wizard form
    /// prefers this over its heuristic when pre-selecting the addressing dropdown.
    /// </summary>
    public string? DetectedAddressingMode { get; set; }
}
