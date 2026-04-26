using NetFirewall.Models.Auth;
using NetFirewall.Services.Auth;

namespace NetFirewall.Web.Auth;

/// <summary>
/// Centralised writer for the session cookie. Both <c>AuthController</c> and
/// <c>AccountController</c> finish their flows by calling this — keeps cookie
/// options + audit logging in one place so they can't drift.
/// </summary>
public interface ISessionCookieIssuer
{
    Task IssueAsync(HttpContext context, User user, CancellationToken ct = default);
}

public sealed class SessionCookieIssuer : ISessionCookieIssuer
{
    private readonly ISessionService _sessions;
    private readonly IAuthAuditService _audit;

    public SessionCookieIssuer(ISessionService sessions, IAuthAuditService audit)
    {
        _sessions = sessions;
        _audit = audit;
    }

    public async Task IssueAsync(HttpContext context, User user, CancellationToken ct = default)
    {
        var ip = context.Connection.RemoteIpAddress;
        var ua = context.Request.Headers.UserAgent.ToString();

        var (token, session) = await _sessions.IssueAsync(
            user.Id, ip, ua, SessionCookieAuthHandler.BasicLifetime, ct);

        context.Response.Cookies.Append(
            SessionCookieAuthHandler.CookieName,
            token,
            SessionCookieAuthHandler.BuildCookieOptions(session.ExpiresAt));

        await _audit.LogAsync(AuthAuditEvents.LoginSuccess, user.Id, user.Username, ip, ua, ct: ct);
    }
}
