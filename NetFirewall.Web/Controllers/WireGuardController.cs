using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Vpn;
using NetFirewall.Services.Daemon;
using NetFirewall.Web.Filters;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Vpn;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// Server settings + apply for the single WireGuard tunnel. Peer CRUD lives
/// in <see cref="WireGuardPeersController"/> nested under this route.
/// </summary>
[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Vpn/WireGuard")]
public sealed class WireGuardController : Controller
{
    private readonly IWireGuardService _wg;
    private readonly IDaemonClient _daemon;
    private readonly ILogger<WireGuardController> _logger;

    public WireGuardController(
        IWireGuardService wg,
        IDaemonClient daemon,
        ILogger<WireGuardController> logger)
    {
        _wg = wg;
        _daemon = daemon;
        _logger = logger;
    }

    [HttpGet("")]
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var server = await _wg.GetServerAsync(ct);
        ViewBag.Server = server;
        ViewBag.Form = server is null ? new WgServerFormViewModel() : ToForm(server);
        return View();
    }

    [HttpGet("status")]
    public async Task<IActionResult> Status(CancellationToken ct)
    {
        var server = await _wg.GetServerAsync(ct);
        if (server is null)
        {
            return PartialView("_Status", new WgStatusViewModel
            {
                Server = null,
                Status = Array.Empty<WgPeerLiveStatus>(),
                Peers = Array.Empty<WgPeer>()
            });
        }

        var peers = await _wg.GetPeersAsync(server.Id, ct);
        var statusEnvelope = await _daemon.GetWireGuardStatusAsync(ct);
        var status = statusEnvelope.Success && statusEnvelope.Data is not null
            ? statusEnvelope.Data
            : Array.Empty<WgPeerLiveStatus>();

        return PartialView("_Status", new WgStatusViewModel
        {
            Server = server,
            Status = status,
            Peers = peers
        });
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(WgServerFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return this.ToHtmxResponse(ServiceResponse<WgServer>.Fail("Form validation failed."));

        try
        {
            var existing = await _wg.GetServerAsync(ct);
            var entity = existing ?? new WgServer();

            // First save (no existing keys): generate via daemon.
            if (string.IsNullOrEmpty(entity.PrivateKey))
            {
                var keys = await _daemon.GenerateWireGuardKeyPairAsync(ct);
                if (!keys.Success || keys.Data is null)
                    return this.ToHtmxResponse(ServiceResponse<WgServer>.Fail($"Key generation failed: {keys.Message}"));
                entity.PrivateKey = keys.Data.PrivateKey;
                entity.PublicKey  = keys.Data.PublicKey;
            }

            entity.Name        = form.Name;
            entity.ListenPort  = form.ListenPort;
            entity.AddressCidr = form.AddressCidr;
            entity.PostUp      = string.IsNullOrWhiteSpace(form.PostUp)   ? null : form.PostUp;
            entity.PostDown    = string.IsNullOrWhiteSpace(form.PostDown) ? null : form.PostDown;
            entity.Enabled     = form.Enabled;

            var saved = await _wg.SaveServerAsync(entity, ct);
            var envelope = ServiceResponse<WgServer>.Ok(saved, "WireGuard server saved.");
            this.AttachToastTrigger(envelope);
            Response.Headers["HX-Trigger"] = "refreshWireGuard";
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "WireGuard server save failed");
            return this.ToHtmxResponse(ServiceResponse<WgServer>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("regenerate-keys"), ValidateAntiForgeryToken, RequireElevated]
    public async Task<IActionResult> RegenerateKeys(CancellationToken ct)
    {
        var server = await _wg.GetServerAsync(ct);
        if (server is null) return this.ToHtmxResponse(ServiceResponse<object>.Fail("No server configured."));

        var keys = await _daemon.GenerateWireGuardKeyPairAsync(ct);
        if (!keys.Success || keys.Data is null)
            return this.ToHtmxResponse(ServiceResponse<object>.Fail($"Key generation failed: {keys.Message}"));

        server.PrivateKey = keys.Data.PrivateKey;
        server.PublicKey  = keys.Data.PublicKey;
        await _wg.SaveServerAsync(server, ct);

        var envelope = ServiceResponse<object>.Ok(new { server.PublicKey },
            "Server keys rotated. Every peer config must be re-issued — old client configs will fail.");
        this.AttachToastTrigger(envelope);
        Response.Headers["HX-Trigger"] = "refreshWireGuard";
        return Json(envelope);
    }

    [HttpPost("apply"), ValidateAntiForgeryToken, RequireElevated]
    public async Task<IActionResult> Apply(CancellationToken ct)
    {
        var envelope = await _daemon.ApplyWireGuardAsync(ct);
        Response.Headers["HX-Trigger"] = "refreshWireGuard";
        return this.ToHtmxResponse(envelope);
    }

    [HttpPost("stop"), ValidateAntiForgeryToken, RequireElevated]
    public async Task<IActionResult> Stop(CancellationToken ct)
    {
        var envelope = await _daemon.StopWireGuardAsync(ct);
        Response.Headers["HX-Trigger"] = "refreshWireGuard";
        return this.ToHtmxResponse(envelope);
    }

    // GET /Vpn/WireGuard/importables — list /etc/wireguard/*.conf candidates.
    // The Index view shows a small picker if the DB is empty (or always, as a
    // way to re-sync after manual edits to the on-disk config).
    [HttpGet("importables")]
    public async Task<IActionResult> Importables(CancellationToken ct)
    {
        var envelope = await _daemon.ListWireGuardImportablesAsync(ct);
        ViewBag.Importables = envelope.Success ? envelope.Data ?? Array.Empty<string>() : Array.Empty<string>();
        ViewBag.Error = envelope.Success ? null : envelope.Message;
        return PartialView("_ImportPicker");
    }

    // POST /Vpn/WireGuard/import/{name} — daemon parses the named config and
    // UPSERTs wg_servers + wg_peers. Idempotent. Does NOT touch the live
    // interface — operator clicks Apply afterwards if they want.
    [HttpPost("import/{name}"), ValidateAntiForgeryToken, RequireElevated]
    public async Task<IActionResult> Import(string name, CancellationToken ct)
    {
        var envelope = await _daemon.ImportWireGuardConfigAsync(name, ct);
        Response.Headers["HX-Trigger"] = "refreshWireGuard";
        // Translate the daemon envelope into a UI-friendly toast. ToHtmxResponse
        // already adds showToast — we just pass through.
        return this.ToHtmxResponse(envelope);
    }

    private static WgServerFormViewModel ToForm(WgServer s) => new()
    {
        Id = s.Id, Name = s.Name, ListenPort = s.ListenPort, AddressCidr = s.AddressCidr,
        PostUp = s.PostUp, PostDown = s.PostDown, Enabled = s.Enabled,
        PrivateKey = s.PrivateKey, PublicKey = s.PublicKey
    };
}
