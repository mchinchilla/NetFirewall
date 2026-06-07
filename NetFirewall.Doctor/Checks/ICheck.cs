namespace NetFirewall.Doctor.Checks;

/// <summary>Outcome of a single check.</summary>
public enum CheckStatus
{
    Pass,   // requirement satisfied
    Warn,   // non-fatal concern (e.g. dev defaults in prod-looking layout)
    Fail,   // requirement NOT satisfied — deployment is broken
    Skip,   // not applicable here (e.g. linux-only check on macOS, daemon off)
}

/// <summary>
/// Result of one <see cref="ICheck"/>. <see cref="Remedy"/> is a one-line fix hint
/// shown for non-pass rows; <see cref="Detail"/> is optional extra context.
/// </summary>
public sealed record CheckResult(
    CheckStatus Status,
    string Message,
    string? Remedy = null,
    string? Detail = null)
{
    public static CheckResult Pass(string message, string? detail = null) => new(CheckStatus.Pass, message, null, detail);
    public static CheckResult Warn(string message, string? remedy = null, string? detail = null) => new(CheckStatus.Warn, message, remedy, detail);
    public static CheckResult Fail(string message, string? remedy = null, string? detail = null) => new(CheckStatus.Fail, message, remedy, detail);
    public static CheckResult Skip(string message) => new(CheckStatus.Skip, message);
}

/// <summary>
/// One deployment requirement. Implementations MUST be fail-soft — never throw;
/// catch and return <see cref="CheckStatus.Fail"/> or <see cref="CheckStatus.Skip"/>.
/// </summary>
public interface ICheck
{
    /// <summary>Group label, also used by the <c>--service</c> filter (e.g.
    /// "Env", "Master key", "Paths", "systemd", "Daemon", "Database").</summary>
    string Category { get; }

    /// <summary>Human-readable check name shown in the table.</summary>
    string Name { get; }

    /// <summary>Services this check is relevant to (for <c>--service</c> filtering).
    /// Empty = always run.</summary>
    IReadOnlyList<string> Services { get; }

    Task<CheckResult> RunAsync(DoctorContext ctx, CancellationToken ct);
}
