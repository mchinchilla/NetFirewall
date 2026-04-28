using NetFirewall.Models.Dhcp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetFirewall.Services.Dhcp;

public interface IDhcpServerService
{
    /// <summary>
    /// Builds the DHCP response for the given request. The returned buffer is
    /// pool-rented — the caller MUST <c>Dispose</c> it (or use <c>using</c>)
    /// after consuming. <see cref="DhcpResponseBuffer.IsEmpty"/> means "no
    /// response should be sent" (e.g. RELEASE, DECLINE, or failover declined).
    /// </summary>
    Task<DhcpResponseBuffer> CreateDhcpResponseAsync( DhcpRequest request );
}