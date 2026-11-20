using Microsoft.AspNetCore.Authorization;
using NetFirewall.Web.Auth;
using NetOpenGrid.Application.Builders;
using NetOpenGrid.Application.Options;
using NetOpenGrid.Domain.Abstractions;
using NetOpenGrid.Infrastructure;
using NetOpenGrid.Infrastructure.Endpoints;

namespace NetFirewall.Web.Grids;

/// <summary>
/// Registers NetFirewall's grids with house defaults (theme, sizing, page sizes) and records
/// each grid's roles in <see cref="GridAccessPolicy"/>. Feature grids live next to each other
/// under <c>Grids/</c> as small static definitions; their rows always come from a DI service.
/// </summary>
public sealed class NetFirewallGridBuilder(NetOpenGridBuilder grids, GridAccessPolicy access)
{
    public NetFirewallGridBuilder Add<TRow>(
        string id,
        string[] roles,
        Action<GridOptionsBuilder<TRow>> configure,
        Func<IServiceProvider, GridOptions<TRow>, IGridDataSource<TRow>> source)
    {
        access.Register(id, roles);
        grids.AddGrid<TRow>(id, o =>
        {
            o.WithTheme("grid")
             .WithMinHeight("")                     // the host frame sizes itself to the grid
             .WithDefaultPageSize(25)
             .WithPageSizeChoices(10, 25, 50, 100, 250)
             .WithDebounce(250);
            configure(o);
        }, source);
        return this;
    }
}

public static class NetFirewallGrids
{
    /// <summary>Route prefix of every grid document and fragment (same origin as the app).</summary>
    public const string Prefix = "/netgrid";

    public static IServiceCollection AddNetFirewallGrids(this IServiceCollection services)
    {
        var access = new GridAccessPolicy();
        var grids = services.AddNetOpenGrid(assets =>
        {
            // The grid document links the app's own stylesheet after its theme: site.css
            // remaps the grid's neutral/brand palette onto the semantic theme tokens
            // (html[data-nf-grid]) and brings .badge / .btn / .nf-chip into the frame.
            assets.ExtraStylesheets.Add("/css/site.css");
        });

        var builder = new NetFirewallGridBuilder(grids, access);
        Dhcp.DhcpLeasesGrid.Register(builder);
        Dhcp.DhcpReservationsGrid.Register(builder);
        Dhcp.DhcpSubnetsGrid.Register(builder);
        Dhcp.DhcpClassesGrid.Register(builder);
        Dhcp.DhcpDdnsGrid.Register(builder);
        Dhcp.DhcpFailoverGrid.Register(builder);
        Firewall.FwAuditLogGrid.Register(builder);
        Firewall.FwPortForwardsGrid.Register(builder);
        Firewall.FwNatRulesGrid.Register(builder);
        Firewall.FwMangleRulesGrid.Register(builder);
        Firewall.FwSchedulesGrid.Register(builder);
        Firewall.FwTrafficMarksGrid.Register(builder);
        Firewall.FwQosConfigsGrid.Register(builder);
        Network.NetworkObjectsGrid.Register(builder);
        Network.NetworkServicesGrid.Register(builder);
        Network.StaticRoutesGrid.Register(builder);
        Network.WakeOnLanGrid.Register(builder);
        Vpn.WireGuardPeersGrid.Register(builder);          // wg-tunnels + wg-clients
        Diagnostics.DiagnosticsHistoryGrid.Register(builder);

        services.AddSingleton<IGridAccessPolicy>(access);
        services.AddSingleton<GridAccessEndpointFilter>();
        return services;
    }

    public static IEndpointRouteBuilder MapNetFirewallGrids(this IEndpointRouteBuilder app)
    {
        var authenticated = new AuthorizationPolicyBuilder(SessionCookieAuthHandler.SchemeName)
            .RequireAuthenticatedUser()
            .Build();

        app.MapNetOpenGrid(o => o.Prefix = Prefix)
           .RequireAuthorization(authenticated)
           .AddEndpointFilter<GridAccessEndpointFilter>();
        return app;
    }
}
