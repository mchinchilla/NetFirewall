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

public class DhcpMacReservation
{
    [Map( "id" )]
    public Guid Id { get; set; }
    [Map( "mac_address" )]
    [NpgsqlDbType( NpgsqlDbType.MacAddr )]
    public PhysicalAddress MacAddress { get; set; }
    [Map( "ip_address" )]
    public IPAddress ReservedIp { get; set; }

    [Map( "description" )]
    public string? Description { get; set; }
}