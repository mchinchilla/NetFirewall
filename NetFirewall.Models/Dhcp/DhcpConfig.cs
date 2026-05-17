using System.Net;

namespace NetFirewall.Models.Dhcp;

public class DhcpConfig
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public IPAddress? IpRangeStart { get; set; }
    public IPAddress IpRangeEnd { get; set; } = IPAddress.Any;
    public IPAddress SubnetMask { get; set; } = IPAddress.Any;
    public int LeaseTime { get; set; }
    public IPAddress Gateway { get; set; } = IPAddress.Any;
    public List<IPAddress> DnsServers { get; set; } = new();
    public string BootFileName { get; set; } = string.Empty;
    public string ServerName { get; set; } = string.Empty;
    public IPAddress ServerIp { get; set; } = IPAddress.Any;
}