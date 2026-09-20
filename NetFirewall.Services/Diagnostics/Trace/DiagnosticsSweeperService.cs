using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.Diagnostics.Trace;

/// <summary>
/// Startup janitor for the invasive tools. If the daemon was killed mid-trace, the
/// temporary <c>ip netfw_diag</c> table survives in the kernel and keeps setting
/// nftrace on matching packets — invisible, and a real cost on a busy box. This
/// deletes it once at startup, before anything else can use the tracer.
/// </summary>
public sealed class DiagnosticsSweeperService : IHostedService
{
    private readonly IProcessRunner _runner;
    private readonly DiagnosticsOptions _opts;
    private readonly ILogger<DiagnosticsSweeperService> _logger;

    public DiagnosticsSweeperService(IProcessRunner runner, IOptions<DiagnosticsOptions> opts, ILogger<DiagnosticsSweeperService> logger)
    {
        _runner = runner;
        _opts = opts.Value;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsLinux()) return;

        try
        {
            var res = await _runner.RunAsync(_opts.NftPath,
                ["delete", "table", "ip", IFlowInspectorService.TraceTableName],
                TimeSpan.FromSeconds(5), cancellationToken);

            // Success means we found and removed leftovers; failure almost always
            // means "no such table", which is the normal, healthy case.
            if (res.Success)
                _logger.LogWarning("Removed a leftover trace table 'ip {Table}' from a previous run", IFlowInspectorService.TraceTableName);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Trace table sweep skipped");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
