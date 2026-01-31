using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;
using NpgsqlTypes;
using RepoDb.Attributes;
using RepoDb.Attributes.Parameter.Npgsql;

namespace NetFirewall.Models.Dhcp;

public class DhcpLease
{
    [Map( "id" )] 
    public Guid Id { get; set; }

    [NpgsqlDbType( NpgsqlDbType.MacAddr )]
    [Map( "mac_address" )]
    public PhysicalAddress MacAddress { get; set; }

    [Map( "ip_address" )] 
    public IPAddress IpAddress { get; set; }
    [Map( "start_time" )] 
    public DateTime StartTime { get; set; }
    [Map( "end_time" )] 
    public DateTime EndTime { get; set; }
    [Map( "hostname" )]
    public string? Hostname { get; set; }
}