namespace NetFirewall.Models.Dhcp;

public enum DhcpMessageType : byte
{
    /// <summary>
    /// Client broadcasts to locate available servers.
    /// </summary>
    Discover = 1,

    /// <summary>
    /// Server offers an IP address to the client.
    /// </summary>
    Offer = 2,

    /// <summary>
    /// Client requests a specific IP address from the server.
    /// </summary>
    Request = 3,

    /// <summary>
    /// Server acknowledges the client's request, confirming the IP address lease.
    /// </summary>
    Ack = 5,

    /// <summary>
    /// Server sends a negative acknowledgment, denying the IP address request.
    /// </summary>
    Nak = 6,

    /// <summary>
    /// Client informs the server that the IP address is already in use.
    /// </summary>
    Decline = 4,

    /// <summary>
    /// Client releases the IP address back to the server.
    /// </summary>
    Release = 7,

    /// <summary>
    /// Client requests only configuration parameters, not an IP address.
    /// </summary>
    Inform = 8
}