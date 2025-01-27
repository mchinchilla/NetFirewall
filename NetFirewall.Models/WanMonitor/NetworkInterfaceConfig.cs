namespace NetFirewall.Models;

public class NetworkInterfaceConfig
{
    public string? InterfaceName { get; set; } // Network interface name (e.g., ens192, ens224)
    public string[]? MonitorIPs { get; set; } // IPs to monitor (3 IPs)
    public string InterfaceGateway { get; set; }
}