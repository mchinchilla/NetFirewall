using NetFirewall.Models;
using NetFirewall.Models.Network;
using NetFirewall.Models.System;

namespace NetFirewall.Services.Network;

/// <summary>
/// Renders an unbound forwarder config from a <see cref="DnsForwarderConfig"/>,
/// writes it under /etc/unbound/unbound.conf.d/, then restarts the unbound
/// service. Daemon-only because writing /etc/unbound and running systemctl both
/// need privileges the Web does not (and should not) have.
/// </summary>
public interface IDnsForwarderService
{
    Task<ServiceResponse<NetworkApplyResult>> ApplyAsync(DnsForwarderConfig config, CancellationToken ct = default);
}
