using NetFirewall.Models.Firewall;
using NetFirewall.Models.System;

namespace NetFirewall.Web.Models.Network;

/// <summary>Merged view of a detected interface (live system state) and its persisted configuration.</summary>
public sealed class InterfaceRowViewModel
{
    public required string Name { get; init; }
    public string? MacAddress { get; init; }
    public bool IsUp { get; init; }
    public bool IsVirtual { get; init; }
    public string? CurrentIp { get; init; }
    public string? CurrentGateway { get; init; }

    public string SuggestedType { get; init; } = "LAN";
    public string SuggestedRole { get; init; } = "local_network";
    public int SuggestionConfidence { get; init; }
    public string SuggestionReason { get; init; } = string.Empty;

    public FwInterface? Configured { get; init; }
    public InterfaceRowStatus Status { get; init; }
}

public enum InterfaceRowStatus
{
    /// <summary>Detected on the host but no DB row yet.</summary>
    Detected,
    /// <summary>Detected and configured — applied state matches DB.</summary>
    Configured,
    /// <summary>Configured in DB but not currently visible to the OS.</summary>
    Missing
}
