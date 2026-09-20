using Microsoft.Extensions.Options;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Network;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.Diagnostics;

public sealed class WgLiveReader : IWgLiveReader
{
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(5);

    private readonly IProcessRunner _runner;
    private readonly INetworkLinkProbe _links;
    private readonly DiagnosticsOptions _opts;

    public WgLiveReader(IProcessRunner runner, INetworkLinkProbe links, IOptions<DiagnosticsOptions> opts)
    {
        _runner = runner;
        _links = links;
        _opts = opts.Value;
    }

    public async Task<WgDump?> DumpAsync(string iface, CancellationToken ct = default)
    {
        // Same guard as the status poll: a stopped tunnel is a normal state, not an exec failure.
        if (!_links.Exists(iface)) return null;
        var run = await _runner.RunAsync(_opts.WgPath, new[] { "show", iface, "dump" }, Budget, ct);
        return run.Success ? WgDumpParser.Parse(run.Output) : null;
    }
}
