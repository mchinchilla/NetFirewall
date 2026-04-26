using System.Net;

namespace NetFirewall.Services.Auth;

public interface IAuthAuditService
{
    /// <summary>
    /// Append a row to <c>auth_audit_log</c>. Use <see cref="NetFirewall.Models.Auth.AuthAuditEvents"/>
    /// constants for <paramref name="eventType"/>.
    /// </summary>
    Task LogAsync(
        string eventType,
        Guid? userId = null,
        string? username = null,
        IPAddress? ip = null,
        string? userAgent = null,
        object? detail = null,
        CancellationToken ct = default);

    Task<IReadOnlyList<NetFirewall.Models.Auth.AuthAuditEntry>> RecentAsync(int limit = 100, CancellationToken ct = default);
}
