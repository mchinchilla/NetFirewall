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
/// CRUD over <c>network_objects</c>. Filter / NAT / mangle rules reference
/// these by name; the resolver flattens them into CIDRs at apply time.
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Network/Objects")]
public sealed class NetworkObjectsController : Controller
{
    private readonly INetworkObjectService _objects;
    private readonly ILogger<NetworkObjectsController> _logger;

    public NetworkObjectsController(INetworkObjectService objects, ILogger<NetworkObjectsController> logger)
    {
        _objects = objects;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("table")]
    public async Task<IActionResult> Table(CancellationToken ct)
    {
        var rows = await _objects.GetAllAsync(includeMembers: true, ct);
        return PartialView("_ObjectsTable", rows);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid? id, CancellationToken ct)
    {
        // Pass the catalog so the form can render a member-picker for groups.
        ViewBag.Catalog = await _objects.GetAllAsync(includeMembers: false, ct);

        if (id is null) return PartialView("_ObjectForm", new NetworkObjectFormViewModel());

        var obj = await _objects.GetByIdAsync(id.Value, includeMembers: true, ct);
        return obj is null ? NotFound() : PartialView("_ObjectForm", FromEntity(obj));
    }

    /// <summary>Lightweight name-only listing for autocomplete in rule editors.</summary>
    [HttpGet("autocomplete")]
    public async Task<IActionResult> Autocomplete(string? q, CancellationToken ct)
    {
        var all = await _objects.GetAllAsync(includeMembers: false, ct);
        var filtered = string.IsNullOrWhiteSpace(q)
            ? all
            : all.Where(o => o.Name.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();
        return Json(filtered.Select(o => new { o.Id, o.Name, o.Type, o.Value }).Take(20));
    }

    /// <summary>
    /// Where-used panel — consumed by the Edit drawer (top of form) so the
    /// operator sees what depends on this object before changing/deleting it.
    /// </summary>
    [HttpGet("usages/{id:guid}")]
    public async Task<IActionResult> Usages(Guid id, CancellationToken ct)
    {
        var obj = await _objects.GetByIdAsync(id, includeMembers: false, ct);
        if (obj is null) return NotFound();
        var usages = await _objects.FindUsagesAsync(obj.Name, ct);
        ViewBag.ObjectName = obj.Name;
        return PartialView("_Usages", usages);
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(NetworkObjectFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return this.ToHtmxResponse(ServiceResponse<NetworkObject>.Fail(
                string.Join(" ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage))));

        try
        {
            var entity = ToEntity(form);
            NetworkObject saved;
            if (form.Id.HasValue && await _objects.GetByIdAsync(form.Id.Value, false, ct) is not null)
            {
                entity.Id = form.Id.Value;
                saved = await _objects.UpdateAsync(entity, ct);
            }
            else
            {
                saved = await _objects.CreateAsync(entity, ct);
            }

            if (saved.Type == NetworkObjectTypes.Group)
                await _objects.SetGroupMembersAsync(saved.Id, form.MemberIds, ct);

            var envelope = ServiceResponse<NetworkObject>.Ok(saved, $"Object '{saved.Name}' saved.");
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = "refreshNetworkObjects";
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Network object save failed");
            return this.ToHtmxResponse(ServiceResponse<NetworkObject>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var ok = await _objects.DeleteAsync(id, ct);
        Response.Headers["HX-Trigger"] = "refreshNetworkObjects";
        return this.ToHtmxResponse(ok
            ? ServiceResponse<object>.Ok(new { }, "Object deleted.")
            : ServiceResponse<object>.Fail("Object not found."));
    }

    private static NetworkObjectFormViewModel FromEntity(NetworkObject o) => new()
    {
        Id          = o.Id,
        Name        = o.Name,
        Type        = o.Type,
        Value       = o.Value,
        Description = o.Description,
        MemberIds   = o.Members?.Select(m => m.Id).ToList() ?? new()
    };

    private static NetworkObject ToEntity(NetworkObjectFormViewModel f) => new()
    {
        Name        = f.Name.Trim(),
        Type        = f.Type,
        Value       = f.Type == NetworkObjectTypes.Group ? "" : (f.Value ?? "").Trim(),
        Description = string.IsNullOrWhiteSpace(f.Description) ? null : f.Description
    };
}
