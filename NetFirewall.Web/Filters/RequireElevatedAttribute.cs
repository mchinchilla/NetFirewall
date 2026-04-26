using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using NetFirewall.Models.Auth;
using NetFirewall.Web.Auth;

namespace NetFirewall.Web.Filters;

/// <summary>
/// Marks an action that needs a TOTP-verified <c>elevated</c> session. Basic
/// sessions get a 401 with <c>HX-Trigger: showElevationModal</c> carrying the
/// retry instructions — the modal verifies TOTP, calls
/// <c>POST /auth/elevate</c>, then re-fires the original request.
///
/// Apply on every destructive action: network apply, route apply/delete,
/// firewall rule changes, user management mutations, etc.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = false)]
public sealed class RequireElevatedAttribute : Attribute, IAsyncAuthorizationFilter
{
    public Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var user = context.HttpContext.User;
        if (user.Identity?.IsAuthenticated != true)
        {
            // Not even logged in — let the standard cookie challenge handle it.
            context.Result = new ChallengeResult(SessionCookieAuthHandler.SchemeName);
            return Task.CompletedTask;
        }

        var level = user.FindFirstValue(SessionCookieAuthHandler.AuthLevelClaim);
        if (string.Equals(level, AuthLevels.Elevated, StringComparison.OrdinalIgnoreCase))
            return Task.CompletedTask; // pass

        // HTMX: signal the modal with retry info so the original request can be replayed.
        var req = context.HttpContext.Request;
        var retry = new
        {
            url = req.Path + req.QueryString,
            method = req.Method
        };
        var trigger = JsonSerializer.Serialize(new
        {
            showElevationModal = retry
        });

        context.HttpContext.Response.Headers["HX-Trigger"] = trigger;
        context.Result = new ObjectResult(new { needsElevation = true, retry })
        {
            StatusCode = StatusCodes.Status401Unauthorized
        };
        return Task.CompletedTask;
    }
}
