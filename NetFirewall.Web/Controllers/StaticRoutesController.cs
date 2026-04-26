using System.Net;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Network;

namespace NetFirewall.Web.Controllers;

[Route("/Network/Routes")]
public sealed class StaticRoutesController : Controller
{
    private readonly IFirewallService _firewall;
    private readonly IStaticRouteApplicator _applicator;
    private readonly ILogger<StaticRoutesController> _logger;

    public StaticRoutesController(
        IFirewallService firewall,
        IStaticRouteApplicator applicator,
        ILogger<StaticRoutesController> logger)
    {
        _firewall = firewall;
        _applicator = applicator;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("table")]
    public async Task<IActionResult> Table(CancellationToken ct)
    {
        var rows = await BuildRowsAsync(ct);
        return PartialView("_RoutesTable", rows);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid? id, CancellationToken ct)
    {
        var ifaces = await _firewall.GetInterfacesAsync(ct);
        ViewBag.Interfaces = ifaces;

        if (id.HasValue)
        {
            var existing = await _firewall.GetStaticRouteByIdAsync(id.Value, ct);
            if (existing == null) return NotFound();
            return PartialView("_RouteForm", FromExisting(existing));
        }

        return PartialView("_RouteForm", new StaticRouteFormViewModel());
    }

    [HttpPost("save")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(StaticRouteFormViewModel form, CancellationToken ct)
    {
        // ValidationToServiceResponseFilter already returned 422 for any ModelState errors.
        var iface = await _firewall.GetInterfaceByIdAsync(form.InterfaceId, ct);
        if (iface == null)
            return this.ToHtmxResponse(ServiceResponse<FwStaticRoute>.Fail("Selected interface no longer exists."));

        try
        {
            var route = ToEntity(form);
            FwStaticRoute saved;
            if (form.Id.HasValue && await _firewall.GetStaticRouteByIdAsync(form.Id.Value, ct) != null)
            {
                route.Id = form.Id.Value;
                saved = await _firewall.UpdateStaticRouteAsync(route, ct);
            }
            else
            {
                saved = await _firewall.CreateStaticRouteAsync(route, ct);
            }

            var envelope = ServiceResponse<FwStaticRoute>.Ok(saved, $"Route {saved.Destination} saved.");
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = AppendTrigger(Response.Headers["HX-Trigger"].ToString(), "refreshRoutes");
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save static route");
            return this.ToHtmxResponse(ServiceResponse<FwStaticRoute>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("apply/{id:guid}")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Apply(Guid id, CancellationToken ct)
    {
        var envelope = await _applicator.ApplyAsync(id, ct);
        Response.Headers["HX-Trigger"] = AppendTrigger(Response.Headers["HX-Trigger"].ToString(), "refreshRoutes");
        return this.ToHtmxResponse(envelope);
    }

    [HttpPost("delete/{id:guid}")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var envelope = await _applicator.RemoveAsync(id, ct);
        Response.Headers["HX-Trigger"] = AppendTrigger(Response.Headers["HX-Trigger"].ToString(), "refreshRoutes");
        return this.ToHtmxResponse(envelope);
    }

    // ---------- Helpers ----------

    private async Task<List<StaticRouteRowViewModel>> BuildRowsAsync(CancellationToken ct)
    {
        var routes = await _firewall.GetStaticRoutesAsync(null, ct);
        var ifaces = (await _firewall.GetInterfacesAsync(ct)).ToDictionary(i => i.Id);

        return routes.Select(r => new StaticRouteRowViewModel
        {
            Route = r,
            InterfaceName = ifaces.TryGetValue(r.InterfaceId, out var fi) ? fi.Name : "(unknown)",
            InterfaceType = ifaces.TryGetValue(r.InterfaceId, out var ft) ? ft.Type : null
        }).OrderBy(r => r.InterfaceName).ThenBy(r => r.Route.Destination).ToList();
    }

    private static StaticRouteFormViewModel FromExisting(FwStaticRoute r) => new()
    {
        Id = r.Id,
        InterfaceId = r.InterfaceId,
        Destination = r.Destination,
        Gateway = r.Gateway?.ToString(),
        Metric = r.Metric,
        Description = r.Description,
        Enabled = r.Enabled
    };

    private static FwStaticRoute ToEntity(StaticRouteFormViewModel f) => new()
    {
        InterfaceId = f.InterfaceId,
        Destination = f.Destination,
        Gateway = string.IsNullOrWhiteSpace(f.Gateway) ? null : IPAddress.Parse(f.Gateway),
        Metric = f.Metric,
        Description = f.Description,
        Enabled = f.Enabled
    };

    private static string AppendTrigger(string existing, string evt)
    {
        if (string.IsNullOrEmpty(existing)) return $"{{\"{evt}\":{{}}}}";
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(existing);
            var dict = doc.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => (object)p.Value.Clone());
            dict[evt] = new { };
            return System.Text.Json.JsonSerializer.Serialize(dict);
        }
        catch
        {
            return $"{existing},{evt}";
        }
    }
}

