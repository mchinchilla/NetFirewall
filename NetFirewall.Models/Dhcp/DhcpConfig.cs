using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using RepoDb.Attributes;

namespace NetFirewall.Models.Dhcp;

public class DhcpConfig
{
    [Map( "id" )] 
    public Guid Id { get; set; }
    [Map( "ip_range_start" )] 
    public IPAddress IpRangeStart { get; set; }
    [Map( "ip_range_end" )] 
    public IPAddress IpRangeEnd { get; set; }
    [Map( "subnet_mask" )] 
    public IPAddress SubnetMask { get; set; }
    [Map( "lease_time" )] 
    public int LeaseTime { get; set; }
    [Map( "gateway" )] 
    public IPAddress Gateway { get; set; }
    [Map( "dns_servers" )] 
    public IPAddress[] DnsServers { get; set; }
    [Map( "boot_file_name" )] 
    public string BootFileName { get; set; }
    [Map( "server_name" )] 
    public string ServerName { get; set; }
    [Map( "server_ip" )] 
    public IPAddress ServerIp { get; set; }
    [Map( "description" )] 
    public string Description { get; set; }
}