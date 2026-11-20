using NetFirewall.Models.Dhcp;

namespace NetFirewall.Web.Models.Dhcp;

/// <summary>Expanded row of the DDNS grid. The view never prints <see cref="DdnsConfig.TsigKeySecret"/>, only whether one is set.</summary>
public sealed class DdnsDetailViewModel
{
    public required DdnsConfig Config { get; init; }
    public required string Scope { get; init; }
}
