namespace NetFirewall.Models;

public class NetworkInterfaceConfig
{
    public string? InterfaceName { get; set; }
    public List<string>? MonitorIPs { get; set; } 
    public string? InterfaceGateway { get; set; }
    public bool IsPrimary { get; set; } = false;
}