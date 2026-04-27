using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Web.Helpers;
using NetFirewall.Services.Settings;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// Runtime settings page. Admin only because settings change global behavior
/// (retention windows, default DHCP values, etc).
/// </summary>
[Authorize(Roles = UserRoles.Admin)]
[Route("/Admin/Settings")]
public sealed class SettingsController : Controller
{
    private readonly IAppSettingsService _settings;
    private readonly ILogger<SettingsController> _logger;

    public SettingsController(IAppSettingsService settings, ILogger<SettingsController> logger)
    {
        _settings = settings;
        _logger = logger;
    }

    [HttpGet("")]
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var values = await _settings.GetAllAsync(ct);
        return View(values);
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    [Filters.RequireElevated]
    public async Task<IActionResult> Save(string key, string value, CancellationToken ct)
    {
        try
        {
            var user = User.Identity?.Name;
            await _settings.SetAsync(key, value, user, ct);
            var envelope = ServiceResponse<object>.Ok(new { key, value }, $"Setting '{key}' saved.");
            this.AttachToastTrigger(envelope);
            return Json(envelope);
        }
        catch (ArgumentException ex)
        {
            return this.ToHtmxResponse(ServiceResponse<object>.Fail(ex.Message));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save setting {Key}", key);
            return this.ToHtmxResponse(ServiceResponse<object>.Fail($"Save failed: {ex.Message}"));
        }
    }
}
