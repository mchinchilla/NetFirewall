using Microsoft.AspNetCore.Http;
using NetFirewall.Services.Daemon;
using NetFirewall.Web.Auth;

namespace NetFirewall.Web.Daemon;

/// <summary>
/// Web-side <see cref="IDaemonSessionTokenProvider"/> — extracts the session
/// token from the inbound request's <c>__Host-NetFw</c> cookie via
/// <see cref="IHttpContextAccessor"/>. Background calls (no HttpContext) get
/// null and the daemon evaluates them as unauthenticated.
/// </summary>
public sealed class WebDaemonSessionTokenProvider : IDaemonSessionTokenProvider
{
    private readonly IHttpContextAccessor _accessor;

    public WebDaemonSessionTokenProvider(IHttpContextAccessor accessor)
    {
        _accessor = accessor;
    }

    public string? GetCurrentToken()
    {
        var ctx = _accessor.HttpContext;
        if (ctx is null) return null;
        return ctx.Request.Cookies.TryGetValue(SessionCookieAuthHandler.CookieName, out var token)
            ? token
            : null;
    }
}
