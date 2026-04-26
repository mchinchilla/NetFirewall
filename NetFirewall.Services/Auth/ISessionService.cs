using System.Net;
using NetFirewall.Models.Auth;

namespace NetFirewall.Services.Auth;

public interface ISessionService
{
    /// <summary>
    /// Create a new session for the given user. Returns the plaintext token
    /// (to put in the cookie) and the persisted record. The token is shown
    /// only here — only its SHA-256 hash is stored.
    /// </summary>
    Task<(string Token, UserSession Session)> IssueAsync(
        Guid userId, IPAddress? ip, string? userAgent, TimeSpan basicLifetime, CancellationToken ct = default);

    /// <summary>
    /// Look up a session by its plaintext token (cookie value). Returns null
    /// if expired, revoked, or not found. On hit, updates <c>last_seen_at</c>
    /// and slides the basic-tier expiration forward (sliding window).
    /// </summary>
    Task<UserSession?> ValidateAsync(string token, TimeSpan basicLifetime, CancellationToken ct = default);

    /// <summary>Bump the session to elevated for the given duration.</summary>
    Task ElevateAsync(Guid sessionId, TimeSpan duration, CancellationToken ct = default);

    /// <summary>Revoke a single session (logout).</summary>
    Task RevokeAsync(Guid sessionId, CancellationToken ct = default);

    /// <summary>Revoke every session for a user (e.g. after password change).</summary>
    Task RevokeAllForUserAsync(Guid userId, CancellationToken ct = default);

    /// <summary>List active sessions for the account/security page.</summary>
    Task<IReadOnlyList<UserSession>> ListActiveAsync(Guid userId, CancellationToken ct = default);

    /// <summary>Reap expired or revoked sessions older than the cutoff.</summary>
    Task<int> CleanupAsync(DateTimeOffset olderThan, CancellationToken ct = default);
}
