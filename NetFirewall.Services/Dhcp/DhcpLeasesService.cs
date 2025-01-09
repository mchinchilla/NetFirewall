using RepoDb;
using System;
using System.Net;
using System.Threading.Tasks;
using System.Linq;
using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using Npgsql;
using RepoDb.Enumerations;
using Serilog;

public class DhcpLeasesService : IDhcpLeasesService
{
    private readonly ILogger<DhcpLeasesService> _logger;
    private readonly DbRepository<NpgsqlConnection> _dbRepository;

    public DhcpLeasesService( string connection, ILogger<DhcpLeasesService> logger )
    {
        _logger = logger;
        _dbRepository = new DbRepository<NpgsqlConnection>( connection );
    }

    public async Task<IPAddress?> OfferLeaseAsync( string macAddress, IPAddress? rangeStart, IPAddress rangeEnd )
    {
        try
        {
            var now = DateTime.UtcNow;

            for ( var ip = rangeStart; ( await CompareIpAddressesAsync( ip, rangeEnd ) ) <= 0; ip = IncrementIpAddress( ip ) )
            {
                var ipStr = ip.ToString();
                var query = $"select * from dhcp_leases where ip_address = '{ipStr}' and end_time > '{now:yyyy-MM-dd HH:mm:ss}';";
                _logger.LogDebug( $"OfferLeaseAsync :: {query}" );

                var result = await _dbRepository.ExecuteQueryAsync<DhcpLease>( query );
                if ( !result.Any() )
                {
                    return ip;
                }
            }
        }
        catch ( Exception ex )
        {
            _logger.LogError( ex.Message );
        }
        
        return null;
    }

    public async Task AssignLeaseAsync( string macAddress, IPAddress ipAddress, int leaseTime )
    {
        var now = DateTime.UtcNow;
        var newLease = new DhcpLease
        {
            Id = Guid.NewGuid(),
            MacAddress = PhysicalAddress.Parse( macAddress ),
            IpAddress = ipAddress,
            StartTime = now,
            EndTime = now.AddSeconds( leaseTime )
        };

        await _dbRepository.InsertAsync( tableName: "dhcp_leases", newLease );
    }

    public async Task<bool> CanAssignIpAsync( string macAddress, IPAddress ipAddress )
    {
        var now = DateTime.UtcNow;
        var ipStr = ipAddress.ToString();

        var query = $@"select id from dhcp_leases where ip_address = '{ipStr}' and end_time > '{now:yyyy-MM-dd HH:mm:ss}';";
        _logger.LogDebug( $"CanAssignIpAsync :: {query}" );

        var result = await _dbRepository.ExecuteQueryAsync<DhcpLease>( query );
        if ( !result.Any() )
        {
            return true; // No active lease on this IP
        }

        // Check if the lease on this IP is for the same MAC address
        var leaseQuery = $@"select mac_address from dhcp_leases where ip_address = '{ipStr}' and end_time > '{now:yyyy-MM-dd HH:mm:ss}';";
        _logger.LogDebug( $"CanAssignIpAsync :: leaseQuery => {leaseQuery}"  );

        var leaseResult = await _dbRepository.ExecuteQueryAsync<DhcpLease>( leaseQuery );
        return leaseResult.Any() && leaseResult.First().MacAddress == PhysicalAddress.Parse( macAddress );
    }

    public async Task ReleaseLeaseAsync( string macAddress )
    {
        await _dbRepository.DeleteAsync<DhcpLease>( new QueryField( nameof(DhcpLease.MacAddress), macAddress ) );
    }

    public async Task MarkIpAsDeclinedAsync( IPAddress ipAddress )
    {
        // Here you might want to add logic to mark an IP as declined or add it to some kind of blacklist
        // For simplicity, we'll just delete any active lease for this IP
        await _dbRepository.DeleteAsync<DhcpLease>( new QueryField( nameof(DhcpLease.IpAddress), ipAddress.ToString() ) );
    }

    public async Task<IPAddress> GetAssignedIpAsync( string macAddress )
    {
        var now = DateTime.UtcNow;

        var query = $@"select ip_address from dhcp_leases where mac_address = '{macAddress}'  and end_time > '{now:yyyy-MM-dd HH:mm:ss}';";
        _logger.LogDebug( $"GetAssignedIpAsync :: {query}" );

        var result = await _dbRepository.ExecuteQueryAsync<DhcpLease>( query );
        return result.Any() ? IPAddress.Parse( result.First().IpAddress.ToString() ) : null;
    }

    private IPAddress? IncrementIpAddress( IPAddress? ip )
    {
        byte[] bytes = ip.GetAddressBytes();
        for ( int i = bytes.Length - 1; i >= 0; i-- )
        {
            if ( ++bytes[i] != 0 )
                return new IPAddress( bytes );
        }

        throw new OverflowException( "IP address overflow" );
    }

    private async Task<int> CompareIpAddressesAsync( IPAddress? ip1, IPAddress ip2 )
    {
        byte[] bytes1 = ip1.GetAddressBytes();
        byte[] bytes2 = ip2.GetAddressBytes();

        for ( int i = 0; i < bytes1.Length; i++ )
        {
            int comparison = bytes1[i].CompareTo( bytes2[i] );
            if ( comparison != 0 )
            {
                return await Task.Run( () => comparison );
            }
        }

        return await Task.Run( () => 0 );
    }
}