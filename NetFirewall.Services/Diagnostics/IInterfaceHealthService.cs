using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics;

/// <summary>Link-level health from sysfs plus addresses/neighbours from iproute2 JSON. Linux only; empty elsewhere.</summary>
public interface IInterfaceHealthService
{
    /// <summary>Live interface names (<c>/sys/class/net</c>) — the allow-list every interface argument is checked against.</summary>
    Task<IReadOnlySet<string>> ListNamesAsync(CancellationToken ct = default);

    Task<IReadOnlyList<InterfaceHealth>> GetAllAsync(CancellationToken ct = default);

    /// <summary>Null off-Linux; <c>Exists=false</c> when the name is not present.</summary>
    Task<InterfaceHealth?> GetAsync(string iface, CancellationToken ct = default);

    Task<IReadOnlyList<NeighborEntry>> NeighborsAsync(string? iface, CancellationToken ct = default);
}
