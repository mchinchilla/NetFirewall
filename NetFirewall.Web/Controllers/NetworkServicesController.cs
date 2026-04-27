using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Network;
using NetFirewall.Services.Network;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Network;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// CRUD over <c>network_services</c> (the L4 catalog: SSH, HTTP, RTP, …).
/// Filter / mangle / port-forward rules reference these by name; the
/// resolver expands them to numeric ports at apply time.
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Network/Services")]
public sealed class NetworkServicesController : Controller
{
    private readonly INetworkServiceService _services;
    private readonly ILogger<NetworkServicesController> _logger;

    public NetworkServicesController(INetworkServiceService services, ILogger<NetworkServicesController> logger)
    {
        _services = services;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("table")]
    public async Task<IActionResult> Table(string? category, CancellationToken ct)
    {
        var rows = await _services.GetAllAsync(includeMembers: true, ct);
        if (!string.IsNullOrWhiteSpace(category))
            rows = rows.Where(s => string.Equals(s.Category, category, StringComparison.OrdinalIgnoreCase)).ToList();
        ViewBag.Categories = (await _services.GetAllAsync(false, ct))
            .Select(s => s.Category)
            .Where(c => !string.IsNullOrEmpty(c))
            .Distinct()
            .OrderBy(c => c)
            .ToList();
        ViewBag.SelectedCategory = category;
        return PartialView("_ServicesTable", rows);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid? id, CancellationToken ct)
    {
        ViewBag.Catalog = await _services.GetAllAsync(false, ct);
        if (id is null) return PartialView("_ServiceForm", new NetworkServiceFormViewModel());
        var s = await _services.GetByIdAsync(id.Value, includeMembers: true, ct);
        return s is null ? NotFound() : PartialView("_ServiceForm", FromEntity(s));
    }

    /// <summary>Lightweight name+port lookup for the rule-editor service-picker.</summary>
    [HttpGet("autocomplete")]
    public async Task<IActionResult> Autocomplete(string? q, CancellationToken ct)
    {
        var all = await _services.GetAllAsync(false, ct);
        var filtered = string.IsNullOrWhiteSpace(q)
            ? all
            : all.Where(s => s.Name.Contains(q, StringComparison.OrdinalIgnoreCase)
                          || (s.Category?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false)).ToList();
        return Json(filtered
            .Select(s => new { s.Id, s.Name, s.Protocol, port = s.PortString, s.Category })
            .Take(20));
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(NetworkServiceFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return this.ToHtmxResponse(ServiceResponse<NetworkService>.Fail(
                string.Join(" ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage))));

        try
        {
            var entity = ToEntity(form);
            NetworkService saved;
            if (form.Id.HasValue && await _services.GetByIdAsync(form.Id.Value, false, ct) is not null)
            {
                entity.Id = form.Id.Value;
                saved = await _services.UpdateAsync(entity, ct);
            }
            else
            {
                saved = await _services.CreateAsync(entity, ct);
            }

            // Group members are managed separately; only call when non-empty.
            if (form.MemberIds.Count > 0)
                await _services.SetGroupMembersAsync(saved.Id, form.MemberIds, ct);

            var envelope = ServiceResponse<NetworkService>.Ok(saved, $"Service '{saved.Name}' saved.");
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = "refreshNetworkServices";
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Network service save failed");
            return this.ToHtmxResponse(ServiceResponse<NetworkService>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var ok = await _services.DeleteAsync(id, ct);
        Response.Headers["HX-Trigger"] = "refreshNetworkServices";
        return this.ToHtmxResponse(ok
            ? ServiceResponse<object>.Ok(new { }, "Service deleted.")
            : ServiceResponse<object>.Fail("Service not found."));
    }

    private static NetworkServiceFormViewModel FromEntity(NetworkService s) => new()
    {
        Id          = s.Id,
        Name        = s.Name,
        Protocol    = s.Protocol,
        PortStart   = s.PortStart,
        PortEnd     = s.PortEnd,
        Description = s.Description,
        Category    = s.Category,
        IsBuiltin   = s.IsBuiltin,
        MemberIds   = s.Members?.Select(m => m.Id).ToList() ?? new()
    };

    private static NetworkService ToEntity(NetworkServiceFormViewModel f) => new()
    {
        Name        = f.Name.Trim(),
        Protocol    = f.Protocol,
        PortStart   = f.PortStart,
        PortEnd     = f.PortEnd,
        Description = string.IsNullOrWhiteSpace(f.Description) ? null : f.Description,
        Category    = string.IsNullOrWhiteSpace(f.Category)    ? null : f.Category,
        IsBuiltin   = false  // operator-created services are never marked builtin
    };
}
