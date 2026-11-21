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

    /// <summary>DNS name published for this device (one RFC 1123 label, e.g. "nas"). Null = none.</summary>
    [Map( "hostname" )]
    public string? Hostname { get; set; }

    /// <summary>Lease length for this device in seconds (60 s – 1 year, migration 00051). Null = the subnet's default.</summary>
    [Map( "lease_time" )]
    public int? LeaseTime { get; set; }

    public const int MinLeaseTime = 60;
    public const int MaxLeaseTime = 31_536_000;
}