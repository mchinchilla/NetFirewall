using NetFirewall.Models.System;

namespace NetFirewall.Services.Network;

public interface ILinuxDistroService
{
    Task<LinuxDistroInfo> DetectDistributionAsync(CancellationToken ct = default);
    Task<IReadOnlyList<InterfaceSuggestion>> DiscoverInterfacesAsync(CancellationToken ct = default);
    Task<InterfaceSuggestion> AnalyzeInterfaceAsync(string name, CancellationToken ct = default);
}
