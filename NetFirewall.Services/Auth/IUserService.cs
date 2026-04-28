using System.Net;
using NetFirewall.Models.Auth;

namespace NetFirewall.Services.Auth;

public interface IUserService
{
    Task<User?> GetByIdAsync(Guid id, CancellationToken ct = default);
    Task<User?> GetByUsernameAsync(string username, CancellationToken ct = default);
    Task<IReadOnlyList<User>> ListAsync(CancellationToken ct = default);
    Task<int> CountAsync(CancellationToken ct = default);

    /// <summary>Persist a new user. Caller hashes the password.</summary>
    Task<User> CreateAsync(User user, CancellationToken ct = default);

    Task UpdatePasswordHashAsync(Guid id, string newHash, CancellationToken ct = default);
    Task SetActiveAsync(Guid id, bool active, CancellationToken ct = default);
    Task SetRoleAsync(Guid id, string role, CancellationToken ct = default);

    /// <summary>
    /// Clear lockout state (failed_login_count = 0, locked_until = NULL) without
    /// stamping a fake login. Used by admin recovery flows — distinct from
    /// <see cref="RecordLoginSuccessAsync"/> which would also update last_login_at,
    /// muddying the audit timeline (no real login happened).
    /// </summary>
    Task ClearLockoutAsync(Guid id, CancellationToken ct = default);

    /// <summary>Record a successful login: clears lockout state, stamps last login.</summary>
    Task RecordLoginSuccessAsync(Guid id, IPAddress? ip, CancellationToken ct = default);

    /// <summary>
    /// Record a failed login attempt; locks the account for <paramref name="lockDuration"/>
    /// once <paramref name="threshold"/> failures pile up.
    /// </summary>
    /// <returns>True iff the user is now locked.</returns>
    Task<bool> RecordLoginFailureAsync(Guid id, IPAddress? ip, int threshold, TimeSpan lockDuration, CancellationToken ct = default);

    /// <summary>
    /// Update the user's profile fields (everything that's NOT auth/role state:
    /// names, email, phone, timezone, locale). Returns the refreshed user.
    /// </summary>
    Task<User> UpdateProfileAsync(Guid id, UserProfileUpdate update, CancellationToken ct = default);
}

/// <summary>Mutable subset of user fields owned by the profile page.</summary>
public sealed record UserProfileUpdate(
    string? FirstName,
    string? LastName,
    string? DisplayName,
    string? Email,
    string? Phone,
    string? Timezone,
    string? Locale);
