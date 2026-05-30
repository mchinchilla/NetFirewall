using System.Net;
using System.Net.NetworkInformation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Dhcp;

namespace NetFirewall.Web.Controllers;

[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Dhcp/Reservations")]
public sealed class DhcpReservationsController : Controller
{
    private readonly IDhcpAdminService _admin;
    private readonly ILogger<DhcpReservationsController> _logger;

    public DhcpReservationsController(IDhcpAdminService admin, ILogger<DhcpReservationsController> logger)
    {
        _admin = admin;
        _logger = logger;
    }

    [HttpGet("")]
    public IActionResult Index() => View();

    [HttpGet("table")]
    public async Task<IActionResult> Table([FromQuery] string? q, CancellationToken ct)
    {
        var rows = await _admin.GetReservationsAsync(filter: q, ct: ct);
        ViewBag.Query = q;
        return PartialView("_ReservationsTable", rows);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid? id, CancellationToken ct)
    {
        if (id is null) return PartialView("_ReservationForm", new ReservationFormViewModel());

        var r = await _admin.GetReservationByIdAsync(id.Value, ct);
        return r is null ? NotFound() : PartialView("_ReservationForm", FromEntity(r));
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(ReservationFormViewModel form, CancellationToken ct)
    {
        try
        {
            var entity = ToEntity(form);
            DhcpMacReservation saved;
            if (form.Id.HasValue && await _admin.GetReservationByIdAsync(form.Id.Value, ct) is not null)
            {
                entity.Id = form.Id.Value;
                saved = await _admin.UpdateReservationAsync(entity, ct);
            }
            else
            {
                saved = await _admin.CreateReservationAsync(entity, ct);
            }

            var envelope = ServiceResponse<DhcpMacReservation>.Ok(saved,
                $"Reservation {saved.MacAddress} → {saved.ReservedIp} saved.");
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = "refreshReservations";
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save reservation");
            return this.ToHtmxResponse(ServiceResponse<DhcpMacReservation>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        var ok = await _admin.DeleteReservationAsync(id, ct);
        var envelope = ok
            ? ServiceResponse<object>.Ok(new { }, "Reservation deleted.")
            : ServiceResponse<object>.Fail("Reservation not found.");
        Response.Headers["HX-Trigger"] = "refreshReservations";
        return this.ToHtmxResponse(envelope);
    }

    // ---------- mapping ----------

    private static ReservationFormViewModel FromEntity(DhcpMacReservation r) => new()
    {
        Id = r.Id,
        MacAddress = NormalizeMac(r.MacAddress?.ToString()),
        ReservedIp = r.ReservedIp?.ToString() ?? string.Empty,
        Description = r.Description
    };

    private static DhcpMacReservation ToEntity(ReservationFormViewModel f) => new()
    {
        MacAddress = PhysicalAddress.Parse(f.MacAddress.Replace(":", "-").ToUpperInvariant()),
        ReservedIp = IPAddress.Parse(f.ReservedIp),
        Description = f.Description
    };

    private static string NormalizeMac(string? raw) =>
        string.IsNullOrEmpty(raw) ? string.Empty
            : string.Join(":", Enumerable.Range(0, raw.Length / 2)
                .Select(i => raw.Substring(i * 2, 2).ToUpperInvariant()));
}
