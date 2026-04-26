using Microsoft.Extensions.DependencyInjection;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;

namespace NetFirewall.Web.Daemon;

/// <summary>
/// Wraps the real <see cref="INetworkConfigResolver"/> so callers receive a
/// <see cref="DaemonNetworkConfigService"/> instead of the underlying writer.
/// Read-only methods on the writer (preview, file path, validate) still call
/// straight through to the real implementation; only apply / restart hop to
/// the daemon. This keeps controllers and view code unchanged when the
/// daemon is enabled.
/// </summary>
internal sealed class DaemonResolverDecorator : INetworkConfigResolver
{
    private readonly INetworkConfigResolver _inner;
    private readonly IServiceProvider _services;
    private DaemonNetworkConfigService? _cached;

    public DaemonResolverDecorator(INetworkConfigResolver inner, IServiceProvider services)
    {
        _inner = inner;
        _services = services;
    }

    public async Task<INetworkConfigService> ResolveAsync(CancellationToken ct = default)
    {
        if (_cached is not null) return _cached;
        var local = await _inner.ResolveAsync(ct);
        var daemon = _services.GetRequiredService<IDaemonClient>();
        var firewall = _services.GetRequiredService<IFirewallService>();
        _cached = new DaemonNetworkConfigService(daemon, local, firewall);
        return _cached;
    }
}
