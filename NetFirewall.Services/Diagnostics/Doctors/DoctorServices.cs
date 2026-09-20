using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Diagnostics.Doctors.Dhcp;
using NetFirewall.Services.Diagnostics.Doctors.Dns;
using NetFirewall.Services.Diagnostics.Doctors.Wan;
using NetFirewall.Services.Settings;

namespace NetFirewall.Services.Diagnostics.Doctors;

// Three thin services: gather the context, hand it and the checks to the shared
// runner. All the fan-out, timeout and Skip logic lives in DoctorRunner.

public interface IWanDoctorService
{
    Task<DiagReport> RunAsync(CancellationToken ct = default);
}

public sealed class WanDoctorService : IWanDoctorService
{
    private readonly IWanDoctorContextFactory _contexts;
    private readonly IEnumerable<IWanDoctorCheck> _checks;
    private readonly IDoctorRunner _runner;
    private readonly IAppSettingsService _settings;

    public WanDoctorService(IWanDoctorContextFactory contexts, IEnumerable<IWanDoctorCheck> checks, IDoctorRunner runner, IAppSettingsService settings)
    {
        _contexts = contexts; _checks = checks; _runner = runner; _settings = settings;
    }

    public async Task<DiagReport> RunAsync(CancellationToken ct = default)
    {
        var target = await DoctorDefaults.ProbeTargetAsync(_settings, ct);
        var ctx = _contexts.Create(target, ct);
        var wans = await ctx.WansAsync();
        var subject = wans.Count == 0 ? "(no WAN)" : string.Join(", ", wans.Select(w => w.Name));
        return await _runner.RunAsync(DiagTools.WanDoctor, subject, ctx, _checks, ct);
    }
}

public interface IDhcpDoctorService
{
    Task<DiagReport> RunAsync(CancellationToken ct = default);
}

public sealed class DhcpDoctorService : IDhcpDoctorService
{
    private readonly IDhcpDoctorContextFactory _contexts;
    private readonly IEnumerable<IDhcpDoctorCheck> _checks;
    private readonly IDoctorRunner _runner;

    public DhcpDoctorService(IDhcpDoctorContextFactory contexts, IEnumerable<IDhcpDoctorCheck> checks, IDoctorRunner runner)
    {
        _contexts = contexts; _checks = checks; _runner = runner;
    }

    public async Task<DiagReport> RunAsync(CancellationToken ct = default)
    {
        var ctx = _contexts.Create(ct);
        var subnets = await ctx.SubnetsAsync();
        var subject = subnets.Count == 0 ? "(no subnets)" : $"{subnets.Count(s => s.Enabled)} enabled subnet(s)";
        return await _runner.RunAsync(DiagTools.DhcpDoctor, subject, ctx, _checks, ct);
    }
}

public interface IDnsDoctorService
{
    Task<DiagReport> RunAsync(CancellationToken ct = default);
}

public sealed class DnsDoctorService : IDnsDoctorService
{
    /// <summary>What the resolver probes resolve. A name that always exists and is cheap to look up.</summary>
    public const string ProbeName = "example.com";

    private readonly IDnsDoctorContextFactory _contexts;
    private readonly IEnumerable<IDnsDoctorCheck> _checks;
    private readonly IDoctorRunner _runner;

    public DnsDoctorService(IDnsDoctorContextFactory contexts, IEnumerable<IDnsDoctorCheck> checks, IDoctorRunner runner)
    {
        _contexts = contexts; _checks = checks; _runner = runner;
    }

    public Task<DiagReport> RunAsync(CancellationToken ct = default) =>
        _runner.RunAsync(DiagTools.DnsDoctor, ProbeName, _contexts.Create(ProbeName, ct), _checks, ct);
}

internal static class DoctorDefaults
{
    public static async Task<string> ProbeTargetAsync(IAppSettingsService settings, CancellationToken ct)
    {
        try
        {
            var t = await settings.GetStringAsync("diagnostics.probe_default_target", ct);
            return string.IsNullOrWhiteSpace(t) ? "1.1.1.1" : t.Trim();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return "1.1.1.1";
        }
    }
}
