using Npgsql;
using RepoDb;
using System.Net;
using System.Net.NetworkInformation;
using NetFirewall.Models.Dhcp;
using Microsoft.Extensions.Logging;
using RepoDb.Enumerations;

namespace NetFirewall.Services.Dhcp;

public class DhcpLeasesService : IDhcpLeasesService
{
    private readonly NpgsqlConnection _dbRepository;
    private readonly ILogger<DhcpLeasesService> _logger;

    public DhcpLeasesService( ILogger<DhcpLeasesService> logger, NpgsqlConnection connection )
    {
        _logger = logger;
        _dbRepository = connection;
    }

    public async Task<IPAddress> AssignOrGetLeaseAsync( string macAddress, IPAddress rangeStart, IPAddress rangeEnd, DhcpRequest request )
    {
        _logger.LogInformation( $"Assigning or getting DHCP lease for MAC address {macAddress}, dhcp Request: {request.ClientMac}" );
        var now = DateTime.UtcNow;
        try
        {
            var existingLease = ( await _dbRepository.QueryAsync<DhcpLease>( [
                new QueryField( nameof(DhcpLease.MacAddress), macAddress ),
                new QueryField( nameof(DhcpLease.EndTime), now )
            ] ) ).FirstOrDefault();

            if ( existingLease != null )
            {
                // Update the existing lease if it's still active
                existingLease.EndTime = now.AddSeconds( request.LeaseTime );
                existingLease.Hostname = await GetHostnameAsync( request, existingLease.IpAddress );
                await _dbRepository.UpdateAsync( existingLease );
                return existingLease.IpAddress;
            }
            else
            {
                // If no active lease or lease expired, find an available IP
                var newIp = await FindAvailableIpAsync( rangeStart, rangeEnd );
                if ( newIp.Equals( IPAddress.None ) )
                {
                    var newLease = new DhcpLease
                    {
                        Id = Guid.NewGuid(),
                        MacAddress = PhysicalAddress.Parse( macAddress ),
                        IpAddress = newIp,
                        StartTime = now,
                        EndTime = now.AddSeconds( request.LeaseTime ),
                        Hostname = await GetHostnameAsync( request, newIp )
                    };

                    await _dbRepository.InsertAsync( newLease );
                    return await Task.Run( () => newIp );
                }
            }
        }
        catch ( Exception ex )
        {
            _logger.LogError( $"Failed to assign or get DHCP lease: {ex.Message}" );
        }

        return await Task.Run( () => IPAddress.None );
    }

    // Helper method to find an available IP, this is overly simplified
    private async Task<IPAddress> FindAvailableIpAsync( IPAddress start, IPAddress end )
    {
        try
        {
            var now = DateTime.UtcNow;
            for ( var ip = start; ( await CompareIpAddressesAsync( ip, end ) ) <= 0; ip = IncrementIpAddress( ip ) )
            {
                string reqSql = $"select * from dhcp_leases where ip_address = '{start}' and end_time > '{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}'";
                _logger.LogDebug( $"FindAvailableIpAsync => {reqSql}" );
                var leased = ( await _dbRepository.ExistsAsync<DhcpLease>( reqSql ) );
                // var leased = ( await _dbRepository.QueryAsync<DhcpLease>( [
                //     new QueryField( nameof(DhcpLease.IpAddress), ip.ToString() ),
                //     new QueryField( nameof(DhcpLease.EndTime), Operation.GreaterThanOrEqual, now )
                // ] ) ).Any();

                if ( !leased )
                {
                    return await Task.Run( () => ip );
                }
            }
        }
        catch ( Exception ex )
        {
            _logger.LogError( $"Failed to find available IP: {ex.Message}" );
        }

        return await Task.Run( () => IPAddress.None );
    }


    private async Task<string> GetHostnameAsync( DhcpRequest request, IPAddress ip )
    {
        if ( !string.IsNullOrEmpty( request.Hostname ) )
        {
            return await Task.Run( () => request.Hostname ); // Use hostname from DHCP request if available
        }

        try
        {
            // Attempt to resolve hostname via DNS
            var hostEntry = await Dns.GetHostEntryAsync( ip );
            return await Task.Run( () => hostEntry.HostName );
        }
        catch ( Exception ex )
        {
            _logger.LogWarning( $"Failed to resolve hostname for IP {ip}: {ex.Message}" );
            return await Task.Run( () => string.Empty );
        }
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


    private IPAddress IncrementIpAddress( IPAddress ip )
    {
        byte[] bytes = ip.GetAddressBytes();
        for ( int i = bytes.Length - 1; i >= 0; i-- )
        {
            if ( ++bytes[i] != 0 )
                return new IPAddress( bytes );
        }

        throw new OverflowException( "IP address overflow" );
    }

    public async Task<IPAddress> OfferLease( string macAddress, IPAddress rangeStart, IPAddress rangeEnd )
    {
        var now = DateTime.UtcNow;

        for ( var ip = rangeStart; ( await CompareIpAddressesAsync( ip, rangeEnd ) ) <= 0; ip = IncrementIpAddress( ip ) )
        {
            string reqSql = $"select * from dhcp_leases where ip_address = '{rangeStart}' and end_time > '{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}'";
            var lease = ( await _dbRepository.ExecuteQueryAsync<DhcpLease>( reqSql ) ).FirstOrDefault();
            // var lease = ( await _dbRepository.QueryAsync<DhcpLease>( [
            //     new QueryField( nameof(DhcpLease.IpAddress), ip.ToString() ),
            //     new QueryField( nameof(DhcpLease.EndTime), Operation.GreaterThan, now )
            // ] ) ).FirstOrDefault();

            if ( lease == null )
            {
                return ip;
            }
        }

        return null; // No available IP found
    }

    public async Task AssignLease( string macAddress, IPAddress ipAddress, int leaseTime )
    {
        try
        {
            var now = DateTime.UtcNow;
            var newLease = new DhcpLease
            {
                Id = Guid.NewGuid(),
                MacAddress = PhysicalAddress.Parse( macAddress ),
                IpAddress = ipAddress,
                StartTime = now,
                EndTime = now.AddSeconds( leaseTime ),
                Hostname = await GetHostnameAsync( new DhcpRequest { ClientMac = macAddress }, ipAddress )
            };

            var insertedRecord = await _dbRepository.InsertAsync<DhcpLease>( tableName: "dhcp_leases", entity: newLease );

            if ( insertedRecord != null )
            {
                _logger.LogInformation( $"Assigned lease for MAC address {macAddress} with IP {ipAddress}" );
            }
            else
            {
                _logger.LogWarning( $"Failed to assign lease for MAC address {macAddress} with IP {ipAddress}" );
            }
        }
        catch ( Exception ex )
        {
            _logger.LogError( $"Failed to assign DHCP lease: {ex.Message}" );
        }
    }

    public async Task<bool> CanAssignIp( string macAddress, IPAddress ipAddress )
    {
        try
        {
            string reqSql = $"select * from dhcp_leases where ip_address = '{ipAddress}' and end_time > '{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}'";
            _logger.LogDebug( $"CanAssignIp => {reqSql}" );

            var now = DateTime.UtcNow;
            // var lease = ( await _dbRepository.QueryAsync<DhcpLease>(tableName:"dhcp_leases", [
            //     new QueryField( nameof(DhcpLease.IpAddress), ipAddress.ToString() ),
            //     new QueryField( nameof(DhcpLease.EndTime), Operation.GreaterThan, now )
            // ] ) ).FirstOrDefault();
            var lease = ( await _dbRepository.ExecuteQueryAsync<DhcpLease>( reqSql ) ).FirstOrDefault();
            return lease == null || lease.MacAddress == PhysicalAddress.Parse( macAddress );
        }
        catch ( Exception ex )
        {
            _logger.LogError( $"Failed to check if IP can be assigned: {ex.Message}" );
            return false;
        }
    }

    public async Task ReleaseLease( string macAddress )
    {
        try
        {
            string reqSql = $"delete from dhcp_leases where mac_address > '{macAddress}'";
            _logger.LogDebug( $"ReleaseLease => {reqSql}" );
            var resp = ( await _dbRepository.ExecuteQueryAsync<DhcpLease>( reqSql ) ).ToList();
            _logger.LogInformation( $"Deleted {resp.Count} leases for MAC address {macAddress}" );
        }
        catch ( Exception ex )
        {
            _logger.LogError( $"Failed to release DHCP lease: {ex.Message}" );
        }

        // await _dbRepository.DeleteAsync<DhcpLease>( new QueryField( nameof(DhcpLease.MacAddress), macAddress) );
    }

    public async Task MarkIpAsDeclined( IPAddress ipAddress )
    {
        // Here you might want to add logic to mark an IP as declined or add it to some kind of blacklist
        // For simplicity, we'll just delete any active lease for this IP
        string reqSql = $"delete from dhcp_leases where ip_address = '{ipAddress}'";
        _logger.LogDebug( $"MarkIpAsDeclined => {reqSql}" );
        var resp = ( await _dbRepository.ExecuteQueryAsync<DhcpLease>( reqSql ) ).ToList();
        _logger.LogInformation( $"Deleted {resp.Count} leases for IP address {ipAddress}" );

        // await _dbRepository.DeleteAsync<DhcpLease>( new QueryField( nameof(DhcpLease.IpAddress), ipAddress.ToString() ) );
    }

    public async Task<IPAddress> GetAssignedIp( string macAddress )
    {
        string reqSql = $"select * from dhcp_leases where mac_address > '{macAddress}' and end_time > '{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}'";
        _logger.LogDebug( $"GetAssignedIp => {reqSql}" );
        var now = DateTime.UtcNow;
        var lease = ( await _dbRepository.ExecuteQueryAsync<DhcpLease>( reqSql ) ).FirstOrDefault();
        _logger.LogInformation( $"GetAssignedIp => {lease}" );

        // var lease = ( await _dbRepository.QueryAsync<DhcpLease>( [
        //     new QueryField( nameof(DhcpLease.MacAddress), macAddress ),
        //     new QueryField( nameof(DhcpLease.EndTime), Operation.GreaterThan, now )
        // ] ) ).FirstOrDefault();

        return lease!.IpAddress;
    }
}