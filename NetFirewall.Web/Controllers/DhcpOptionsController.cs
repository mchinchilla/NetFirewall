using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Dhcp;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// DHCP → Custom options (dhcp_custom_options): settings the standard subnet fields don't cover,
/// for everyone, a subnet, a client class or one reserved device. The DHCP server picks changes up
/// through its cache NOTIFY and sends them at each client's next renewal.
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Dhcp/Options")]
public sealed class DhcpOptionsController(IDhcpCustomOptionService options) : Controller
{
    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid? id, CancellationToken ct)
    {
        var form = new DhcpOptionFormViewModel();
        if (id is { } existing)
        {
            var row = await options.GetAsync(existing, ct);
            if (row is null) return NotFound();
            form = new DhcpOptionFormViewModel
            {
                Id = row.Id, ScopeType = row.ScopeType, ScopeId = row.ScopeId, Code = row.Code,
                Name = row.Name, Format = row.Format ?? DhcpOptionFormats.Hex, Value = row.ValueText,
            };
        }
        return await FormAsync(form, ct);
    }

    /// <summary>The target picker for a scope (swapped in when the scope changes).</summary>
    [HttpGet("targets")]
    public async Task<IActionResult> Targets([FromQuery(Name = "ScopeType")] string scope, [FromQuery] Guid? selected, CancellationToken ct) =>
        PartialView("_ScopeTargets", new DhcpOptionFormPageViewModel
        {
            Form = new DhcpOptionFormViewModel { ScopeType = scope, ScopeId = selected },
            Targets = DhcpOptionScopes.All.Contains(scope) ? await options.ScopeTargetsAsync(scope, ct) : [],
        });

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(DhcpOptionFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return this.ToHtmxResponse(ServiceResponse<object>.Fail(
                string.Join(" ", ModelState.Values.SelectMany(v => v.Errors).Select(e => e.ErrorMessage))));

        var saved = await options.SaveAsync(new DhcpCustomOptionInput(
            form.Id, form.ScopeType, form.ScopeId, form.Code, form.Name, form.Format, form.Value), ct);
        if (saved.Success) this.AttachHxEvent("refreshDhcpOptions", new { });
        return this.ToHtmxResponse(saved);
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var ok = await options.DeleteAsync(id, ct);
        this.AttachHxEvent("refreshDhcpOptions", new { });
        return this.ToHtmxResponse(ok
            ? ServiceResponse<object>.Ok(new { }, "Option removed — clients drop it at their next renewal.")
            : ServiceResponse<object>.Fail("Option not found."));
    }

    private async Task<IActionResult> FormAsync(DhcpOptionFormViewModel form, CancellationToken ct) =>
        PartialView("_OptionForm", new DhcpOptionFormPageViewModel
        {
            Form = form,
            Targets = form.ScopeType == DhcpOptionScopes.Global ? [] : await options.ScopeTargetsAsync(form.ScopeType, ct),
        });
}
