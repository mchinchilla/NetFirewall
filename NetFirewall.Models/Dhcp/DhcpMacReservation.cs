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
    public PhysicalAddress MacAddress { get; set; } = PhysicalAddress.None;
    // Column is reserved_ip (00005_dhcp_legacy.sql) — the old ip_address
    // mapping made RepoDb's COPY-based BulkImportReservationsAsync target a
    // nonexistent column (42703) on first use.
    [Map( "reserved_ip" )]
    public IPAddress ReservedIp { get; set; } = IPAddress.Any;

    [Map( "description" )]
    public string? Description { get; set; }
}