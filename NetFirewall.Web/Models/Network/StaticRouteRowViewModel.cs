using NetFirewall.Models.Firewall;

namespace NetFirewall.Web.Models.Network;

/// <summary>Row shown in the static routes table — joins the route with its owning interface.</summary>
public sealed class StaticRouteRowViewModel
{
    public required FwStaticRoute Route { get; init; }
    public string InterfaceName { get; init; } = string.Empty;
    public string? InterfaceType { get; init; }
}
