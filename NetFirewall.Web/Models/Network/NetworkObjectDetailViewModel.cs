using NetFirewall.Models.Network;
using NetFirewall.Services.Network;

namespace NetFirewall.Web.Models.Network;

/// <summary>Expanded row of the Objects grid: the full value / member list and where it is used.</summary>
public sealed record NetworkObjectDetailViewModel(NetworkObject Object, NetworkObjectUsage Usages);
