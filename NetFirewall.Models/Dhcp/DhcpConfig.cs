using System.Net;

namespace NetFirewall.Models.Dhcp;

public class DhcpConfig
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public IPAddress? IpRangeStart { get; set; }
    public IPAddress IpRangeEnd { get; set; }
    public IPAddress SubnetMask { get; set; }
    public int LeaseTime { get; set; }
    public IPAddress Gateway { get; set; }
    public List<IPAddress> DnsServers { get; set; }
    public string BootFileName { get; set; }
    public string ServerName { get; set; }
    public IPAddress ServerIp { get; set; }
}