namespace NetFirewall.Services.Network;

/// <summary>
/// Picks the right <see cref="INetworkConfigService"/> implementation based on the
/// detected Linux distribution. Backed by keyed DI registrations
/// (one writer per <c>NetworkConfigMethod</c>) so adding a new distro family is just
/// "register a new keyed service".
/// </summary>
public interface INetworkConfigResolver
{
    Task<INetworkConfigService> ResolveAsync(CancellationToken ct = default);
}
