namespace NetFirewall.Doctor.Checks;

/// <summary>
/// Verifies a service's env file contains all required keys with non-placeholder
/// values. The required-key lists are passed in from Program.cs (close to the
/// templates they mirror).
/// </summary>
public sealed class RequiredVarsCheck : ICheck
{
    private readonly string _service;
    private readonly Func<DoctorContext, IReadOnlyDictionary<string, string>?> _env;
    private readonly Func<DoctorContext, string> _path;
    private readonly string[] _required;

    public RequiredVarsCheck(
        string service,
        Func<DoctorContext, IReadOnlyDictionary<string, string>?> env,
        Func<DoctorContext, string> path,
        params string[] required)
    {
        _service = service;
        _env = env;
        _path = path;
        _required = required;
    }

    public string Category => "Env";
    public string Name => $"Required vars ({_service})";
    public IReadOnlyList<string> Services => new[] { _service };

    // A value that's still a template/placeholder counts as missing.
    private static readonly string[] Placeholders = { "__REPLACE__", "__REPLACE_MASTER_KEY__", "placeholder", "" };

    public Task<CheckResult> RunAsync(DoctorContext ctx, CancellationToken ct)
    {
        var env = _env(ctx);
        if (env is null)
            return Task.FromResult(CheckResult.Skip($"{_service}.env not present (see Env files check)"));

        var bad = _required
            .Where(k => !env.TryGetValue(k, out var v) || Placeholders.Contains(v.Trim()))
            .ToList();

        if (bad.Count > 0)
            return Task.FromResult(CheckResult.Fail(
                $"Missing/placeholder: {string.Join(", ", bad)}",
                remedy: $"Set these keys in {_path(ctx)} (re-run install.sh or edit by hand)."));

        return Task.FromResult(CheckResult.Pass($"all {_required.Length} required keys present"));
    }
}
