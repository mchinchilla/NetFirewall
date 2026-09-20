using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics.Doctors;

/// <summary>
/// One rule of a doctor, over whatever context that doctor gathers. Checks are
/// registered in the order they should be reported, run concurrently by
/// <see cref="IDoctorRunner"/>, and must be fail-soft: anything they cannot
/// determine is a <see cref="DiagCheckStatus.Skip"/>, never an exception. A check
/// may emit several rows (one per WAN, per subnet, per peer…).
/// </summary>
public interface IDoctorCheck<in TContext>
{
    string Id { get; }
    string Category { get; }
    Task<IReadOnlyList<DiagCheck>> RunAsync(TContext ctx, CancellationToken ct);
}

/// <summary>Single-row convenience base: fail-soft wrapper plus bound Pass/Warn/Fail/Skip factories.</summary>
public abstract class DoctorCheckBase<TContext> : IDoctorCheck<TContext>
{
    public abstract string Id { get; }
    public abstract string Category { get; }
    public abstract string Title { get; }

    protected abstract Task<DiagCheck> CheckAsync(TContext ctx, CancellationToken ct);

    public async Task<IReadOnlyList<DiagCheck>> RunAsync(TContext ctx, CancellationToken ct)
    {
        try
        {
            return [await CheckAsync(ctx, ct)];
        }
        catch (OperationCanceledException)
        {
            throw; // the runner maps a per-check timeout to Skip
        }
        catch (Exception ex)
        {
            return [Skip($"Check could not run: {ex.Message}")];
        }
    }

    protected DiagCheck Pass(string summary, string? detail = null, IReadOnlyList<DiagEvidence>? evidence = null) =>
        DiagCheck.Pass(Id, Category, Title, summary, detail, evidence);

    protected DiagCheck Warn(string summary, DiagRemedy? remedy = null, string? detail = null, IReadOnlyList<DiagEvidence>? evidence = null) =>
        DiagCheck.Warn(Id, Category, Title, summary, remedy, detail, evidence);

    protected DiagCheck Fail(string summary, DiagRemedy? remedy = null, string? detail = null, IReadOnlyList<DiagEvidence>? evidence = null) =>
        DiagCheck.Fail(Id, Category, Title, summary, remedy, detail, evidence);

    protected DiagCheck Skip(string summary, string? detail = null) =>
        DiagCheck.Skip(Id, Category, Title, summary, detail);
}

/// <summary>
/// Runs a doctor's checks: bounded concurrency (the daemon unit caps tasks), a
/// per-check deadline that degrades to Skip instead of failing the report, and a
/// duration stamp on every row. One implementation for every doctor — VPN, WAN,
/// DHCP and DNS differ only in their checks and their context.
/// </summary>
public interface IDoctorRunner
{
    Task<DiagReport> RunAsync<TContext>(
        string tool,
        string subject,
        TContext context,
        IEnumerable<IDoctorCheck<TContext>> checks,
        CancellationToken ct = default);
}
