namespace NetFirewall.Migrations;

/// <summary>
/// Forward-only schema migration runner. Tracks applied files in
/// <c>__migrations</c>, verifies that previously-applied files have not been
/// edited (sha256 drift detection), and applies each pending file in its own
/// transaction. No down-migrations on purpose: irreversible-by-design avoids
/// the false sense of safety that "rollback" scripts give.
/// </summary>
public interface IMigrationRunner
{
    /// <summary>What's applied, what's pending, and which applied files have drifted.</summary>
    Task<MigrationStatus> StatusAsync(CancellationToken ct = default);

    /// <summary>Apply every pending migration in filename order.</summary>
    Task<UpResult> UpAsync(CancellationToken ct = default);

    /// <summary>
    /// <c>DROP SCHEMA public CASCADE; CREATE SCHEMA public;</c> then run
    /// <see cref="UpAsync"/>. Caller must confirm — this destroys all data.
    /// </summary>
    Task<UpResult> ResetAsync(CancellationToken ct = default);
}

public sealed record Migration(string Id, string Path, string Sql, string Sha256);

public sealed record AppliedMigration(string Id, DateTimeOffset AppliedAt, string Sha256, int DurationMs);

public sealed record DriftedMigration(string Id, string AppliedSha, string CurrentSha);

public sealed record MigrationStatus(
    IReadOnlyList<AppliedMigration> Applied,
    IReadOnlyList<Migration> Pending,
    IReadOnlyList<DriftedMigration> Drifted);

public sealed record UpResult(IReadOnlyList<string> AppliedIds, IReadOnlyList<DriftedMigration> Drifted);
