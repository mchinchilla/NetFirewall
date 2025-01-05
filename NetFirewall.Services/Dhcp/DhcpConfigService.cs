using NetFirewall.Models.Dhcp;
using Npgsql;
using RepoDb;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Serilog;

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
        DhcpConfig? config = null;
        try
        {
            config = ( await Task.Run( () => _connection.ExecuteQueryAsync<DhcpConfig>("select * from dhcp_config limit 1" ) ) ).FirstOrDefault();
        }
        catch ( Exception ex )
        {
            Log.Error( $"{ex.Message}\n{ex.StackTrace}" );
        }
        return ( config ?? new DhcpConfig());
    }
}