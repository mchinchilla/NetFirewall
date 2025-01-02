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
    /// <summary>
    /// Offers an IP address to a client based on its MAC address within the specified range.
    /// </summary>
    /// <param name="macAddress">The MAC address of the client.</param>
    /// <param name="rangeStart">The start of the IP range.</param>
    /// <param name="rangeEnd">The end of the IP range.</param>
    /// <returns>An IP address that can be offered to the client.</returns>
    Task<IPAddress> OfferLease( string macAddress, IPAddress rangeStart, IPAddress rangeEnd );

    /// <summary>
    /// Assigns or renews a lease for the given MAC address with the specified IP.
    /// </summary>
    /// <param name="macAddress">The MAC address of the client.</param>
    /// <param name="ipAddress">The IP address to assign.</param>
    /// <param name="leaseTime">The duration of the lease in seconds.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task AssignLease( string macAddress, IPAddress ipAddress, int leaseTime );

    /// <summary>
    /// Checks if the specified IP can be assigned to the client with the given MAC address.
    /// </summary>
    /// <param name="macAddress">The MAC address of the client requesting the IP.</param>
    /// <param name="ipAddress">The IP address to check.</param>
    /// <returns>True if the IP can be assigned, false otherwise.</returns>
    Task<bool> CanAssignIp( string macAddress, IPAddress ipAddress );

    /// <summary>
    /// Releases the IP lease associated with the given MAC address.
    /// </summary>
    /// <param name="macAddress">The MAC address of the client releasing the IP.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task ReleaseLease( string macAddress );

    /// <summary>
    /// Marks an IP as declined, indicating it should not be offered again until cleared.
    /// </summary>
    /// <param name="ipAddress">The IP address to mark as declined.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task MarkIpAsDeclined( IPAddress ipAddress );

    /// <summary>
    /// Retrieves the currently assigned IP for a given MAC address.
    /// </summary>
    /// <param name="macAddress">The MAC address to look up.</param>
    /// <returns>The assigned IP address or null if no active lease exists.</returns>
    Task<IPAddress> GetAssignedIp( string macAddress );
}