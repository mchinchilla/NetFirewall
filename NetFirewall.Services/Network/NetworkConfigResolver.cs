using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.System;

namespace NetFirewall.Services.Network;

public sealed class NetworkConfigResolver : INetworkConfigResolver
{
    private readonly ILinuxDistroService _distroService;
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<NetworkConfigResolver> _logger;
    private INetworkConfigService? _cached;

    public NetworkConfigResolver(
        ILinuxDistroService distroService,
        IServiceProvider serviceProvider,
        ILogger<NetworkConfigResolver> logger)
    {
        _distroService = distroService;
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    public async Task<INetworkConfigService> ResolveAsync(CancellationToken ct = default)
    {
        if (_cached != null) return _cached;

        var distro = await _distroService.DetectDistributionAsync(ct);
        var method = distro.ConfigMethod;

        var resolved = _serviceProvider.GetKeyedService<INetworkConfigService>(method)
                       ?? _serviceProvider.GetRequiredKeyedService<INetworkConfigService>(NetworkConfigMethod.Unknown);

        if (resolved.ConfigMethod != method)
        {
            _logger.LogWarning(
                "No INetworkConfigService registered for {Method}; falling back to {Fallback}",
                method, resolved.ConfigMethod);
        }
        else
        {
            _logger.LogInformation("Resolved network config writer: {Method}", method);
        }

        _cached = resolved;
        return resolved;
    }
}
