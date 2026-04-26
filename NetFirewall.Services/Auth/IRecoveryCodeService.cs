namespace NetFirewall.Services.Auth;

public interface IRecoveryCodeService
{
    /// <summary>
    /// Generate and persist a fresh batch (default 10). Returns the plaintext
    /// codes — present them to the user once; only hashes are kept.
    /// Replaces any previously unused codes for the user.
    /// </summary>
    Task<IReadOnlyList<string>> RegenerateAsync(Guid userId, int count = 10, CancellationToken ct = default);

    /// <summary>How many unused codes the user currently has.</summary>
    Task<int> CountUnusedAsync(Guid userId, CancellationToken ct = default);

    /// <summary>
    /// Verify a recovery code and consume it (single-use). Returns true iff
    /// the code matched an unused entry; the entry is then marked used.
    /// </summary>
    Task<bool> VerifyAndConsumeAsync(Guid userId, string code, CancellationToken ct = default);
}
