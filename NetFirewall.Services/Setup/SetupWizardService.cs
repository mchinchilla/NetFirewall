using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Dhcp;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.Setup;
using NetFirewall.Services.Dhcp;
using NetFirewall.Services.Firewall;
using Npgsql;

namespace NetFirewall.Services.Setup;

/// <summary>
/// Service for managing the initial setup wizard.
/// </summary>
public class SetupWizardService : ISetupWizardService
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly IFirewallService _firewallService;
    private readonly IDhcpSubnetService _subnetService;
    private readonly ILogger<SetupWizardService> _logger;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    public SetupWizardService(
        NpgsqlDataSource dataSource,
        IFirewallService firewallService,
        IDhcpSubnetService subnetService,
        ILogger<SetupWizardService> logger)
    {
        _dataSource = dataSource;
        _firewallService = firewallService;
        _subnetService = subnetService;
        _logger = logger;
    }

    public async Task<bool> IsWizardCompletedAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = "SELECT is_completed FROM setup_wizard_state LIMIT 1";
        await using var cmd = new NpgsqlCommand(sql, conn);

        var result = await cmd.ExecuteScalarAsync(ct);
        return result is true;
    }

    public async Task<SetupWizardState> GetOrCreateWizardStateAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        // Try to get existing state
        const string selectSql = "SELECT * FROM setup_wizard_state LIMIT 1";
        await using var selectCmd = new NpgsqlCommand(selectSql, conn);
        await using var reader = await selectCmd.ExecuteReaderAsync(ct);

        if (await reader.ReadAsync(ct))
        {
            return new SetupWizardState
            {
                Id = reader.GetGuid(reader.GetOrdinal("id")),
                CurrentStep = reader.GetInt32(reader.GetOrdinal("current_step")),
                IsCompleted = reader.GetBoolean(reader.GetOrdinal("is_completed")),
                InterfacesConfigJson = reader.IsDBNull(reader.GetOrdinal("interfaces_config")) ? null : reader.GetString(reader.GetOrdinal("interfaces_config")),
                LanConfigJson = reader.IsDBNull(reader.GetOrdinal("lan_config")) ? null : reader.GetString(reader.GetOrdinal("lan_config")),
                FirewallConfigJson = reader.IsDBNull(reader.GetOrdinal("firewall_config")) ? null : reader.GetString(reader.GetOrdinal("firewall_config")),
                ServicesConfigJson = reader.IsDBNull(reader.GetOrdinal("services_config")) ? null : reader.GetString(reader.GetOrdinal("services_config")),
                StartedAt = reader.GetDateTime(reader.GetOrdinal("started_at")),
                CompletedAt = reader.IsDBNull(reader.GetOrdinal("completed_at")) ? null : reader.GetDateTime(reader.GetOrdinal("completed_at")),
                UpdatedAt = reader.GetDateTime(reader.GetOrdinal("updated_at"))
            };
        }

        await reader.CloseAsync();

        // Create new state
        var newState = new SetupWizardState
        {
            Id = Guid.NewGuid(),
            CurrentStep = 1,
            IsCompleted = false,
            StartedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };

        const string insertSql = @"
            INSERT INTO setup_wizard_state (id, current_step, is_completed, started_at, updated_at)
            VALUES (@id, @step, @completed, @started, @updated)";

        await using var insertCmd = new NpgsqlCommand(insertSql, conn);
        insertCmd.Parameters.AddWithValue("id", newState.Id);
        insertCmd.Parameters.AddWithValue("step", newState.CurrentStep);
        insertCmd.Parameters.AddWithValue("completed", newState.IsCompleted);
        insertCmd.Parameters.AddWithValue("started", newState.StartedAt);
        insertCmd.Parameters.AddWithValue("updated", newState.UpdatedAt);

        await insertCmd.ExecuteNonQueryAsync(ct);
        _logger.LogInformation("Created new setup wizard state");

        return newState;
    }

    public async Task<SetupWizardState> UpdateWizardStateAsync(SetupWizardState state, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        state.UpdatedAt = DateTime.UtcNow;

        const string sql = @"
            UPDATE setup_wizard_state SET
                current_step = @step,
                is_completed = @completed,
                interfaces_config = @interfaces::jsonb,
                lan_config = @lan::jsonb,
                firewall_config = @firewall::jsonb,
                services_config = @services::jsonb,
                completed_at = @completedAt,
                updated_at = @updated
            WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", state.Id);
        cmd.Parameters.AddWithValue("step", state.CurrentStep);
        cmd.Parameters.AddWithValue("completed", state.IsCompleted);
        cmd.Parameters.AddWithValue("interfaces", state.InterfacesConfigJson ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("lan", state.LanConfigJson ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("firewall", state.FirewallConfigJson ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("services", state.ServicesConfigJson ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("completedAt", state.CompletedAt ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("updated", state.UpdatedAt);

        await cmd.ExecuteNonQueryAsync(ct);
        _logger.LogInformation("Updated wizard state: Step {Step}, Completed: {Completed}", state.CurrentStep, state.IsCompleted);

        return state;
    }

    public Task<IReadOnlyList<DetectedNetworkInterface>> DetectNetworkInterfacesAsync(CancellationToken ct = default)
    {
        var interfaces = NetworkInterface.GetAllNetworkInterfaces()
            .Where(ni => ni.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                        ni.NetworkInterfaceType != NetworkInterfaceType.Tunnel &&
                        !ni.Name.StartsWith("docker") &&
                        !ni.Name.StartsWith("br-") &&
                        !ni.Name.StartsWith("veth"))
            .Select(ni =>
            {
                var ipProps = ni.GetIPProperties();
                var ipv4Address = ipProps.UnicastAddresses
                    .FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork);
                var gateway = ipProps.GatewayAddresses
                    .FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork);

                return new DetectedNetworkInterface
                {
                    Name = ni.Name,
                    Description = ni.Description,
                    MacAddress = FormatMacAddress(ni.GetPhysicalAddress()),
                    Type = ni.NetworkInterfaceType,
                    Status = ni.OperationalStatus,
                    CurrentIpAddress = ipv4Address?.Address.ToString(),
                    CurrentSubnetMask = ipv4Address?.IPv4Mask?.ToString(),
                    CurrentGateway = gateway?.Address.ToString(),
                    HasCarrier = ni.OperationalStatus == OperationalStatus.Up,
                    SpeedMbps = ni.Speed / 1_000_000,
                    SuggestedRole = SuggestRole(ni, gateway != null)
                };
            })
            .OrderBy(i => i.Name)
            .ToList();

        _logger.LogInformation("Detected {Count} network interfaces", interfaces.Count);
        return Task.FromResult<IReadOnlyList<DetectedNetworkInterface>>(interfaces);
    }

    private static string FormatMacAddress(PhysicalAddress address)
    {
        var bytes = address.GetAddressBytes();
        return string.Join(":", bytes.Select(b => b.ToString("X2")));
    }

    private static string SuggestRole(NetworkInterface ni, bool hasGateway)
    {
        // Suggest WAN if it has a gateway (connected to external network)
        if (hasGateway)
            return "wan_primary";

        // Suggest LAN for ethernet without gateway
        if (ni.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
            return "lan";

        // WireGuard interfaces
        if (ni.Name.StartsWith("wg"))
            return "vpn";

        return "disabled";
    }

    public async Task ApplyInterfaceConfigAsync(List<WizardInterfaceConfig> configs, CancellationToken ct = default)
    {
        _logger.LogInformation("Applying interface configuration for {Count} interfaces", configs.Count);

        foreach (var config in configs.Where(c => c.Role != "disabled"))
        {
            // Check if interface exists
            var existing = await _firewallService.GetInterfaceByNameAsync(config.Name, ct);

            var iface = existing ?? new FwInterface();
            iface.Name = config.Name;
            iface.Type = config.Role switch
            {
                "wan_primary" or "wan_secondary" => "WAN",
                "lan" => "LAN",
                "vpn" => "VPN",
                _ => "LAN"
            };
            iface.Role = config.Role;
            iface.Enabled = true;

            if (!config.UseDhcp && !string.IsNullOrEmpty(config.IpAddress))
            {
                iface.IpAddress = IPAddress.Parse(config.IpAddress);
                iface.SubnetMask = string.IsNullOrEmpty(config.SubnetMask) ? null : IPAddress.Parse(config.SubnetMask);
                iface.Gateway = string.IsNullOrEmpty(config.Gateway) ? null : IPAddress.Parse(config.Gateway);
                iface.AddressingMode = "static";
            }
            else
            {
                iface.AddressingMode = "dhcp";
            }

            if (existing != null)
            {
                await _firewallService.UpdateInterfaceAsync(iface, ct);
                _logger.LogInformation("Updated interface {Name} as {Role}", config.Name, config.Role);
            }
            else
            {
                await _firewallService.CreateInterfaceAsync(iface, ct);
                _logger.LogInformation("Created interface {Name} as {Role}", config.Name, config.Role);
            }
        }
    }

    public async Task ApplyLanConfigAsync(List<WizardLanConfig> configs, CancellationToken ct = default)
    {
        _logger.LogInformation("Applying LAN/DHCP configuration for {Count} interfaces", configs.Count);

        foreach (var config in configs.Where(c => c.EnableDhcp))
        {
            // Get the interface
            var iface = await _firewallService.GetInterfaceByNameAsync(config.InterfaceName, ct);
            if (iface == null)
            {
                _logger.LogWarning("Interface {Name} not found, skipping DHCP config", config.InterfaceName);
                continue;
            }

            // Create subnet
            var subnet = new DhcpSubnet
            {
                Id = Guid.NewGuid(),
                Name = $"{config.InterfaceName} Subnet",
                Network = config.NetworkCidr,
                SubnetMask = IPAddress.Parse(config.SubnetMask),
                Router = IPAddress.Parse(config.ServerIp),
                DnsServers = new[] { IPAddress.Parse(config.ServerIp) },
                DefaultLeaseTime = config.LeaseTime,
                MaxLeaseTime = config.LeaseTime * 2,
                DomainName = config.DomainName,
                InterfaceId = iface.Id,
                Enabled = true
            };

            var createdSubnet = await _subnetService.CreateSubnetAsync(subnet, ct);
            _logger.LogInformation("Created DHCP subnet {Name} for {Interface}", subnet.Name, config.InterfaceName);

            // Create pool
            var pool = new DhcpPool
            {
                Id = Guid.NewGuid(),
                SubnetId = createdSubnet.Id,
                Name = "Default Pool",
                RangeStart = IPAddress.Parse(config.DhcpRangeStart),
                RangeEnd = IPAddress.Parse(config.DhcpRangeEnd),
                AllowUnknownClients = true,
                Priority = 100,
                Enabled = true
            };

            await _subnetService.CreatePoolAsync(pool, ct);
            _logger.LogInformation("Created DHCP pool {Start}-{End} for {Interface}",
                config.DhcpRangeStart, config.DhcpRangeEnd, config.InterfaceName);
        }
    }

    public async Task ApplyFirewallConfigAsync(WizardFirewallConfig config, List<WizardInterfaceConfig> interfaces, CancellationToken ct = default)
    {
        _logger.LogInformation("Applying firewall configuration");

        var wanInterfaces = interfaces.Where(i => i.Role is "wan_primary" or "wan_secondary").ToList();
        var lanInterfaces = interfaces.Where(i => i.Role == "lan").ToList();

        // Get interface IDs from database
        var allDbInterfaces = await _firewallService.GetInterfacesAsync(ct);
        var dbInterfaceMap = allDbInterfaces.ToDictionary(i => i.Name, i => i.Id);

        int priority = 10;

        // NAT/Masquerade rules for each WAN
        if (config.EnableNat)
        {
            foreach (var wan in wanInterfaces)
            {
                if (!dbInterfaceMap.TryGetValue(wan.Name, out var wanId)) continue;

                foreach (var lan in lanInterfaces)
                {
                    // Calculate LAN network from IP/mask
                    var lanNetwork = CalculateNetwork(lan.IpAddress, lan.SubnetMask);
                    if (lanNetwork == null) continue;

                    var natRule = new FwNatRule
                    {
                        Type = "masquerade",
                        Description = $"NAT {lan.Name} to {wan.Name}",
                        SourceNetwork = lanNetwork,
                        OutputInterfaceId = wanId,
                        Enabled = true,
                        Priority = priority++
                    };
                    await _firewallService.CreateNatRuleAsync(natRule, ct);
                    _logger.LogInformation("Created NAT rule: {Desc}", natRule.Description);
                }
            }
        }

        // Input filter rules
        priority = 10;

        // Allow established connections
        var establishedRule = new FwFilterRule
        {
            Chain = "input",
            Description = "Allow established/related connections",
            Action = "accept",
            ConnectionState = ["established", "related"],
            Enabled = true,
            Priority = priority++
        };
        await _firewallService.CreateFilterRuleAsync(establishedRule, ct);

        // Allow loopback
        var loopbackRule = new FwFilterRule
        {
            Chain = "input",
            Description = "Allow loopback",
            Action = "accept",
            SourceAddresses = ["127.0.0.0/8"],
            Enabled = true,
            Priority = priority++
        };
        await _firewallService.CreateFilterRuleAsync(loopbackRule, ct);

        if (config.AllowIcmp)
        {
            var icmpRule = new FwFilterRule
            {
                Chain = "input",
                Description = "Allow ICMP ping",
                Action = "accept",
                Protocol = "icmp",
                Enabled = true,
                Priority = priority++
            };
            await _firewallService.CreateFilterRuleAsync(icmpRule, ct);
        }

        if (config.AllowSsh)
        {
            var sshRule = new FwFilterRule
            {
                Chain = "input",
                Description = "Allow SSH",
                Action = "accept",
                Protocol = "tcp",
                DestinationPorts = ["22"],
                ConnectionState = ["new"],
                Enabled = true,
                Priority = priority++
            };
            await _firewallService.CreateFilterRuleAsync(sshRule, ct);
        }

        if (config.AllowDhcp)
        {
            foreach (var lan in lanInterfaces)
            {
                if (!dbInterfaceMap.TryGetValue(lan.Name, out var lanId)) continue;

                var dhcpRule = new FwFilterRule
                {
                    Chain = "input",
                    Description = $"Allow DHCP on {lan.Name}",
                    Action = "accept",
                    Protocol = "udp",
                    DestinationPorts = ["67", "68"],
                    InterfaceInId = lanId,
                    Enabled = true,
                    Priority = priority++
                };
                await _firewallService.CreateFilterRuleAsync(dhcpRule, ct);
            }
        }

        if (config.AllowDns)
        {
            foreach (var lan in lanInterfaces)
            {
                if (!dbInterfaceMap.TryGetValue(lan.Name, out var lanId)) continue;

                var dnsRule = new FwFilterRule
                {
                    Chain = "input",
                    Description = $"Allow DNS on {lan.Name}",
                    Action = "accept",
                    Protocol = "udp",
                    DestinationPorts = ["53"],
                    InterfaceInId = lanId,
                    Enabled = true,
                    Priority = priority++
                };
                await _firewallService.CreateFilterRuleAsync(dnsRule, ct);
            }
        }

        if (config.AllowWebInterface)
        {
            foreach (var lan in lanInterfaces)
            {
                if (!dbInterfaceMap.TryGetValue(lan.Name, out var lanId)) continue;

                var webRule = new FwFilterRule
                {
                    Chain = "input",
                    Description = $"Allow Web UI on {lan.Name}",
                    Action = "accept",
                    Protocol = "tcp",
                    DestinationPorts = [config.WebInterfacePort.ToString()],
                    InterfaceInId = lanId,
                    ConnectionState = ["new"],
                    Enabled = true,
                    Priority = priority++
                };
                await _firewallService.CreateFilterRuleAsync(webRule, ct);
            }
        }

        // Default drop for input
        var dropInputRule = new FwFilterRule
        {
            Chain = "input",
            Description = "Drop all other input",
            Action = "drop",
            Enabled = true,
            Priority = 1000
        };
        await _firewallService.CreateFilterRuleAsync(dropInputRule, ct);

        // Forward rules
        if (config.ForwardLanToWan)
        {
            priority = 10;

            // Allow established
            var fwdEstablished = new FwFilterRule
            {
                Chain = "forward",
                Description = "Allow established/related forwards",
                Action = "accept",
                ConnectionState = ["established", "related"],
                Enabled = true,
                Priority = priority++
            };
            await _firewallService.CreateFilterRuleAsync(fwdEstablished, ct);

            // Allow LAN to WAN
            foreach (var lan in lanInterfaces)
            {
                if (!dbInterfaceMap.TryGetValue(lan.Name, out var lanId)) continue;

                foreach (var wan in wanInterfaces)
                {
                    if (!dbInterfaceMap.TryGetValue(wan.Name, out var wanId)) continue;

                    var fwdRule = new FwFilterRule
                    {
                        Chain = "forward",
                        Description = $"Forward {lan.Name} to {wan.Name}",
                        Action = "accept",
                        InterfaceInId = lanId,
                        InterfaceOutId = wanId,
                        ConnectionState = ["new"],
                        Enabled = true,
                        Priority = priority++
                    };
                    await _firewallService.CreateFilterRuleAsync(fwdRule, ct);
                }
            }
        }

        _logger.LogInformation("Firewall configuration applied");
    }

    private static string? CalculateNetwork(string? ipAddress, string? subnetMask)
    {
        if (string.IsNullOrEmpty(ipAddress) || string.IsNullOrEmpty(subnetMask))
            return null;

        try
        {
            var ip = IPAddress.Parse(ipAddress);
            var mask = IPAddress.Parse(subnetMask);

            var ipBytes = ip.GetAddressBytes();
            var maskBytes = mask.GetAddressBytes();
            var networkBytes = new byte[4];

            for (int i = 0; i < 4; i++)
                networkBytes[i] = (byte)(ipBytes[i] & maskBytes[i]);

            var network = new IPAddress(networkBytes);
            var cidr = maskBytes.Sum(b => Convert.ToString(b, 2).Count(c => c == '1'));

            return $"{network}/{cidr}";
        }
        catch
        {
            return null;
        }
    }

    public Task ApplyServicesConfigAsync(WizardServicesConfig config, CancellationToken ct = default)
    {
        _logger.LogInformation("Applying services configuration");

        // For now, just log the configuration
        // Actual implementation would configure DNS forwarder, WireGuard, QoS

        if (config.EnableDnsForwarder)
        {
            _logger.LogInformation("DNS Forwarder enabled with upstream: {Dns1}, {Dns2}",
                config.UpstreamDns1, config.UpstreamDns2);
        }

        if (config.EnableWireGuard)
        {
            _logger.LogInformation("WireGuard enabled on port {Port} with subnet {Subnet}",
                config.WireGuardPort, config.WireGuardSubnet);
        }

        if (config.EnableQos)
        {
            _logger.LogInformation("QoS enabled with Download: {Down}Mbps, Upload: {Up}Mbps",
                config.DownloadBandwidthMbps, config.UploadBandwidthMbps);
        }

        return Task.CompletedTask;
    }

    public async Task CompleteWizardAsync(CancellationToken ct = default)
    {
        var state = await GetOrCreateWizardStateAsync(ct);
        state.IsCompleted = true;
        state.CompletedAt = DateTime.UtcNow;
        await UpdateWizardStateAsync(state, ct);
        _logger.LogInformation("Setup wizard completed");
    }

    public async Task ResetWizardAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = "DELETE FROM setup_wizard_state";
        await using var cmd = new NpgsqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync(ct);

        _logger.LogInformation("Setup wizard reset");
    }
}
