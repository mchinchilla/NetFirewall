using System.Security.Cryptography;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NetFirewall.Services.Auth;

namespace NetFirewall.Web.Auth.Bootstrap;

/// <summary>
/// Hosted service that runs once on startup. If the <c>users</c> table is
/// empty, issues a one-time bootstrap token, writes it to
/// <c>logs/bootstrap-token.txt</c> (mode 0600 best-effort), and stores it in
/// <see cref="IBootstrapTokenStore"/> so the unauthenticated <c>/setup/bootstrap</c>
/// endpoint can validate it. Token is consumed on first successful admin
/// creation; after that, the endpoint returns 404.
/// </summary>
public sealed class BootstrapTokenIssuer : IHostedService
{
    private readonly IServiceProvider _services;
    private readonly ILogger<BootstrapTokenIssuer> _logger;

    public BootstrapTokenIssuer(IServiceProvider services, ILogger<BootstrapTokenIssuer> logger)
    {
        _services = services;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken ct)
    {
        using var scope = _services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<IUserService>();
        var store = scope.ServiceProvider.GetRequiredService<IBootstrapTokenStore>();

        try
        {
            var count = await users.CountAsync(ct);
            if (count > 0)
            {
                _logger.LogInformation("Users table already populated; bootstrap token NOT issued.");
                return;
            }

            var token = GenerateToken();
            store.Issue(token);
            await PersistToFileAsync(token, ct);

            _logger.LogWarning(
                "═══════════════════════════════════════════════════════════════════\n" +
                "  NO USERS EXIST. Bootstrap token issued (one-time):\n" +
                "    {Token}\n" +
                "  Visit /setup/bootstrap?token={Token} to create the first admin.\n" +
                "  Also written to logs/bootstrap-token.txt\n" +
                "═══════════════════════════════════════════════════════════════════",
                token, token);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Bootstrap token issuance failed (DB unreachable?). The setup wizard will be unavailable.");
        }
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;

    private static string GenerateToken()
    {
        var bytes = RandomNumberGenerator.GetBytes(24); // 192 bits
        return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    private async Task PersistToFileAsync(string token, CancellationToken ct)
    {
        try
        {
            const string dir = "logs";
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, "bootstrap-token.txt");
            await File.WriteAllTextAsync(path,
                $"{token}\n\n" +
                $"Issued: {DateTimeOffset.UtcNow:O}\n" +
                $"Use:    /setup/bootstrap?token={token}\n" +
                $"This token is one-time. Delete this file after first use.\n", ct);

            // Best-effort restrictive perms — Windows ignores chmod, that's fine.
#pragma warning disable CA1416
            try { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
            catch { /* not on a unix-y FS */ }
#pragma warning restore CA1416
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not persist bootstrap token to disk; relying on console output.");
        }
    }
}
