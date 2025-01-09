using NetFirewall.Models.Dhcp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace NetFirewall.Services.Dhcp;

public interface IDhcpLeasesService
{
    Task<IPAddress?> OfferLeaseAsync( string macAddress, IPAddress? rangeStart, IPAddress rangeEnd );
    Task AssignLeaseAsync( string macAddress, IPAddress ipAddress, int leaseTime );
    Task<bool> CanAssignIpAsync( string macAddress, IPAddress ipAddress );
    Task ReleaseLeaseAsync( string macAddress );
    Task MarkIpAsDeclinedAsync( IPAddress ipAddress );
    Task<IPAddress> GetAssignedIpAsync( string macAddress );
}