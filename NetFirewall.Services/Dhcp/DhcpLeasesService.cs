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
            _logger.LogInformation( $"OfferLeaseAsync :: MAC {macAddress}" );

            // First, check for a reserved IP for this MAC address
            _logger.LogInformation( $"OfferLeaseAsync :: Checking for reservation for MAC {macAddress}" );
            // First, check for a reserved IP for this MAC address
            IPAddress? reservedIp = await CheckForReservationAsync( macAddress );
            if ( reservedIp != null )
            {
                _logger.LogInformation( $"Found reserved IP {reservedIp} for MAC {macAddress}" );
                return reservedIp;
            }

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
        try
        {
            _logger.LogInformation( $"AssignLeaseAsync :: Ip: {ipAddress} to MAC {macAddress}" );

            // First, check for a reserved IP for this MAC address
            _logger.LogInformation( $"AssignLeaseAsync :: Checking for reservation for MAC {macAddress}" );
            IPAddress? reservedIp = await CheckForReservationAsync( macAddress );

            if ( reservedIp != null )
            {
                if ( Equals( ipAddress, reservedIp ) )
                {
                    _logger.LogInformation( $"AssignLeaseAsync :: IP {ipAddress} is reserved for MAC {macAddress}, update the lease" );
                    ipAddress = reservedIp;
                }
                else
                {
                    _logger.LogWarning( $"Attempt to assign {ipAddress} to MAC {macAddress} but it has a reservation for {reservedIp}. Using reserved IP." );
                    ipAddress = reservedIp;
                }
            }

            _logger.LogInformation( $"AssignLeaseAsync :: Checking if lease exists for MAC {macAddress}" );
            string query = $"select count(id) from dhcp_leases where mac_address = '{macAddress}';";
            var leaseExists = await _dbRepository.ExecuteScalarAsync<int>( query ) > 0 ? true : false;
            _logger.LogInformation( $"AssignLeaseAsync :: Lease exists?: {leaseExists}" );

            var now = DateTime.UtcNow;
            if ( leaseExists )
            {
                _logger.LogInformation( $"AssignLeaseAsync :: Updating lease for MAC {macAddress}" );
                var newLease = new DhcpLease
                {
                    MacAddress = PhysicalAddress.Parse( macAddress ),
                    IpAddress = ipAddress,
                    StartTime = now,
                    EndTime = now.AddSeconds( leaseTime )
                };

                await _dbRepository.UpdateAsync( tableName: "dhcp_leases", newLease, new [] { new QueryField( "mac_address", Operation.Equal, PhysicalAddress.Parse( macAddress ) ) } );
            }
            else
            {
                _logger.LogInformation( $"AssignLeaseAsync :: Inserting new lease for MAC {macAddress}({ipAddress})" );
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
        }
        catch ( Exception ex )
        {
            _logger.LogError( ex.Message );
        }
    }

    public async Task<bool> CanAssignIpAsync( string macAddress, IPAddress ipAddress )
    {
        try
        {
            _logger.LogInformation( $"AssignLeaseAsync :: Ip: {ipAddress} to MAC {macAddress}" );

            // First, check for a reserved IP for this MAC address
            _logger.LogInformation( $"AssignLeaseAsync :: Checking for reservation for MAC {macAddress}" );
            IPAddress? reservedIp = await CheckForReservationAsync( macAddress );

            if ( reservedIp != null )
            {
                if ( Equals( ipAddress, reservedIp ) )
                {
                    _logger.LogInformation( $"AssignLeaseAsync :: IP {ipAddress} is reserved for MAC {macAddress}, update the lease" );
                    ipAddress = reservedIp;
                }
                else
                {
                    _logger.LogWarning( $"Attempt to assign {ipAddress} to MAC {macAddress} but it has a reservation for {reservedIp}. Using reserved IP." );
                    ipAddress = reservedIp;
                }
            }

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
            _logger.LogDebug( $"CanAssignIpAsync :: leaseQuery => {leaseQuery}" );

            var leaseResult = await _dbRepository.ExecuteQueryAsync<DhcpLease>( leaseQuery );
            return leaseResult.Any() && leaseResult.First().MacAddress == PhysicalAddress.Parse( macAddress );
        }
        catch ( Exception ex )
        {
            _logger.LogError( ex.Message );
            return false;
        }
    }

    public async Task ReleaseLeaseAsync( string macAddress )
    {
        await _dbRepository.DeleteAsync<DhcpLease>( new QueryField( nameof(DhcpLease.MacAddress), macAddress ) );
    }

    public async Task<IPAddress?> CheckForReservationAsync( string macAddress )
    {
        try
        {
            var query = $@"select * from dhcp_mac_reservations where mac_address = '{macAddress}';";

            DhcpMacReservation? result = ( await _dbRepository.ExecuteQueryAsync<DhcpMacReservation>( query ) ).FirstOrDefault();
            if ( result != null )
            {
                return result.ReservedIp;
            }

            return null;
        }
        catch ( Exception ex )
        {
            _logger.LogError( ex.Message );
            return null;
        }
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

    private async Task<int> CompareIpAddressesAsync( IPAddress ip1, IPAddress ip2 )
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