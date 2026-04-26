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

    /// <summary>Record a successful login: clears lockout state, stamps last login.</summary>
    Task RecordLoginSuccessAsync(Guid id, IPAddress? ip, CancellationToken ct = default);

    /// <summary>
    /// Record a failed login attempt; locks the account for <paramref name="lockDuration"/>
    /// once <paramref name="threshold"/> failures pile up.
    /// </summary>
    /// <returns>True iff the user is now locked.</returns>
    Task<bool> RecordLoginFailureAsync(Guid id, IPAddress? ip, int threshold, TimeSpan lockDuration, CancellationToken ct = default);
}
