using NetFirewall.Models.Dhcp;
using Npgsql;
using RepoDb;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NetFirewall.Services.Dhcp;

public class DhcpConfigService : IDhcpConfigService
{
    private readonly NpgsqlConnection _connection;

    public DhcpConfigService( NpgsqlConnection connection )
    {
        _connection = connection;
    }

    public async Task<DhcpConfig> GetConfigAsync()
    {
        // Retrieve configuration from the database
        return ( await Task.Run( () => _connection.QueryAsync<DhcpConfig>( "SELECT * FROM dhcp_config LIMIT 1" ) ) ).FirstOrDefault() ?? new DhcpConfig();
    }
}