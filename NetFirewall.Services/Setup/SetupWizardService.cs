using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Dhcp;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.Network;
using NetFirewall.Models.Setup;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Daemon;
using NetFirewall.Services.Dhcp;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Services.Vpn;
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
    private readonly ILinuxDistroService _distro;
    private readonly IDaemonClient _daemon;
    private readonly IWireGuardService _wireguard;
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
        ILinuxDistroService distro,
        IDaemonClient daemon,
        IWireGuardService wireguard,
        ILogger<SetupWizardService> logger)
    {
        _dataSource = dataSource;
        _firewallService = firewallService;
        _subnetService = subnetService;
        _distro = distro;
        _daemon = daemon;
        _wireguard = wireguard;
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

    public async Task<IReadOnlyList<DetectedNetworkInterface>> DetectNetworkInterfacesAsync(CancellationToken ct = default)
    {
        // We deliberately avoid System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces():
        // on Linux hosts with IPv6 disabled at the kernel level (e.g. /proc/sys/net/ipv6/conf/all/disable_ipv6=1),
        // the runtime throws NetworkInformationException(97, EAFNOSUPPORT) from LinuxNetworkInterface
        // (dotnet/runtime#40305). Firewall appliances commonly disable IPv6, so the broken API would crash
        // the wizard on exactly the hosts that need it. Sysfs (/sys/class/net) has no IPv6 dependency.
        // Prefer the DAEMON for discovery (rule #8: the Web shouldn't shell out to
        // `ip`). The Web runs unprivileged under ProtectSystem=strict with a minimal
        // PATH, so its in-process `ip addr show` / `ip route` calls in
        // LinuxDistroService.GetIpInfoAsync silently fail (exception swallowed at
        // Debug) — that's why the current IP / mask / gateway came back empty in the
        // form even though MAC/MTU (read straight from sysfs) populated. The daemon
        // runs as root with full PATH, so the same discovery code returns the live
        // addresses. Fall back to the local distro service if the daemon is down
        // (e.g. dev without the daemon) so the wizard still renders.
        IReadOnlyList<Models.System.InterfaceSuggestion> suggestions;
        try
        {
            var daemonResp = await _daemon.DiscoverInterfacesAsync(ct);
            if (daemonResp.Success && daemonResp.Data is { Count: > 0 })
            {
                suggestions = daemonResp.Data;
            }
            else
            {
                _logger.LogWarning("Daemon interface discovery returned no data ({Msg}); falling back to local sysfs discovery",
                    daemonResp.Message);
                suggestions = await _distro.DiscoverInterfacesAsync(ct);
            }
        }
        catch (Exception daemonEx)
        {
            _logger.LogWarning(daemonEx, "Daemon interface discovery failed; falling back to local sysfs discovery");
            try
            {
                suggestions = await _distro.DiscoverInterfacesAsync(ct);
            }
            catch (Exception ex)
            {
                // Defense in depth: if even sysfs reads fail (non-Linux host, restricted FS), render the wizard
                // with an empty list rather than a 500. The Step 1 view already has an empty-state message.
                _logger.LogError(ex, "Interface discovery failed; falling back to empty list so the wizard still renders");
                return Array.Empty<DetectedNetworkInterface>();
            }
        }

        var interfaces = suggestions
            .Where(s => !string.IsNullOrEmpty(s.Name))
            .Where(s => !IsServiceManagedInterface(s.Name))
            .Select(s => new DetectedNetworkInterface
            {
                Name = s.Name,
                Description = s.Reason ?? string.Empty,
                MacAddress = (s.MacAddress ?? string.Empty).ToUpperInvariant(),
                Type = s.IsVirtual ? NetworkInterfaceType.Tunnel : NetworkInterfaceType.Ethernet,
                Status = s.IsUp ? OperationalStatus.Up : OperationalStatus.Down,
                CurrentIpAddress = s.CurrentIp?.ToString(),
                CurrentSubnetMask = CidrToDottedMask(s.CurrentSubnet),
                CurrentGateway = s.CurrentGateway?.ToString(),
                HasCarrier = s.IsUp,
                SpeedMbps = 0,
                SuggestedRole = MapSuggestedRole(s),
                Confidence = s.Confidence,
                Reason = s.Reason,
                Mtu = s.Mtu,
                IsVirtual = s.IsVirtual,
                DetectedAddressingMode = s.AddressingMode
            })
            .OrderBy(i => i.Name)
            .ToList();

        _logger.LogInformation("Detected {Count} network interfaces via sysfs", interfaces.Count);
        return interfaces;
    }

    /// <summary>
    /// Interfaces the wizard's Step 1 must NOT offer for manual NIC config: they
    /// are created and owned by a SERVICE, not the network-interface layer.
    /// Configuring wg0/tun0/etc. here would write ifupdown/netplan config and an
    /// fw_interfaces row that the owning subsystem (WireGuard, container runtime,
    /// bridge) then fights with — and if the service is never enabled it leaves
    /// orphan config behind. The VPN subsystem (IWireGuardService /
    /// IVpnRoutingService) owns wg*; Docker owns docker*/br-/veth*; tun/tap are
    /// app-managed point-to-point devices.
    /// </summary>
    private static bool IsServiceManagedInterface(string name) =>
        name.StartsWith("wg",     StringComparison.OrdinalIgnoreCase) ||   // WireGuard (wg0, wg1, …)
        name.StartsWith("tun",    StringComparison.OrdinalIgnoreCase) ||   // OpenVPN / generic tunnels
        name.StartsWith("tap",    StringComparison.OrdinalIgnoreCase) ||   // L2 tap devices
        name.StartsWith("docker", StringComparison.OrdinalIgnoreCase) ||   // Docker bridge
        name.StartsWith("br-",    StringComparison.OrdinalIgnoreCase) ||   // Docker/user bridges
        name.StartsWith("veth",   StringComparison.OrdinalIgnoreCase) ||   // container veth pairs
        name.StartsWith("virbr",  StringComparison.OrdinalIgnoreCase) ||   // libvirt bridge
        name.StartsWith("vnet",   StringComparison.OrdinalIgnoreCase) ||   // libvirt/QEMU vNICs
        name.StartsWith("zt",     StringComparison.OrdinalIgnoreCase) ||   // ZeroTier
        name.StartsWith("tailscale", StringComparison.OrdinalIgnoreCase) || // Tailscale
        name.StartsWith("ppp",    StringComparison.OrdinalIgnoreCase);     // PPP (managed by pppd/the WAN dialer)

    private static string MapSuggestedRole(Models.System.InterfaceSuggestion s) => (s.SuggestedType, s.SuggestedRole) switch
    {
        ("WAN", "secondary_wan") => "wan_secondary",
        ("WAN", _)               => "wan_primary",
        ("VPN", _)               => "vpn",
        ("LAN", _)               => "lan",
        _                        => s.CurrentGateway != null ? "wan_primary" : "lan"
    };

    /// <summary>Convert "192.168.1.0/24" → "255.255.255.0" so the form pre-fills a valid IPv4 mask.</summary>
    private static string? CidrToDottedMask(string? cidr)
    {
        if (string.IsNullOrEmpty(cidr)) return null;
        var slash = cidr.IndexOf('/');
        if (slash < 0 || !int.TryParse(cidr.AsSpan(slash + 1), out var prefix) || prefix < 0 || prefix > 32)
            return null;
        var mask = prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix);
        return $"{(byte)(mask >> 24)}.{(byte)(mask >> 16)}.{(byte)(mask >> 8)}.{(byte)mask}";
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
            iface.Mtu = config.Mtu;

            // MAC override (clone/spoof). Empty → keep the NIC's hardware MAC. The
            // daemon applies it on the interface when this config is pushed.
            if (!string.IsNullOrWhiteSpace(config.MacAddress))
                iface.MacAddress = config.MacAddress.Trim();

            iface.AddressingMode = config.AddressingMode switch
            {
                "static" => "static",
                "disabled" => "disabled",
                _ => "dhcp"
            };

            if (iface.AddressingMode == "static" && !string.IsNullOrEmpty(config.IpAddress))
            {
                iface.IpAddress = IPAddress.Parse(config.IpAddress);
                iface.SubnetMask = string.IsNullOrEmpty(config.SubnetMask) ? null : IPAddress.Parse(config.SubnetMask);
                iface.Gateway = string.IsNullOrEmpty(config.Gateway) ? null : IPAddress.Parse(config.Gateway);
            }
            else if (iface.AddressingMode == "dhcp")
            {
                // DHCP: clear any prior static values so reconfig doesn't leave stale IP rows.
                iface.IpAddress = null;
                iface.SubnetMask = null;
                iface.Gateway = null;
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

    public async Task ApplyServicesConfigAsync(WizardServicesConfig config, CancellationToken ct = default)
    {
        _logger.LogInformation("Applying services configuration (DNS={Dns}, WG={Wg}, QoS={Qos})",
            config.EnableDnsForwarder, config.EnableWireGuard, config.EnableQos);

        // ── DNS forwarder ───────────────────────────────────────────────
        if (config.EnableDnsForwarder)
        {
            var dnsResp = await _daemon.ApplyDnsAsync(new DnsForwarderConfig
            {
                Enabled = true,
                UpstreamDns1 = config.UpstreamDns1,
                UpstreamDns2 = config.UpstreamDns2
            }, ct);

            if (!dnsResp.Success)
                throw new InvalidOperationException($"DNS forwarder apply failed: {dnsResp.Message}");

            _logger.LogInformation("DNS forwarder applied: {Msg}", dnsResp.Message);
        }

        // ── WireGuard ───────────────────────────────────────────────────
        if (config.EnableWireGuard)
        {
            if (string.IsNullOrWhiteSpace(config.WireGuardSubnet))
                throw new InvalidOperationException("WireGuard subnet is required when WireGuard is enabled.");

            // First-class server IP inside the WG /24 = .1 (e.g. 10.100.0.1/24).
            // We don't reuse an existing server here — the wizard is the bootstrap path;
            // editing an existing server happens via the dedicated VPN page later.
            var addressCidr = NormalizeWireGuardServerAddress(config.WireGuardSubnet);

            var keypair = await _daemon.GenerateWireGuardKeyPairAsync(ct);
            if (!keypair.Success || keypair.Data is null)
                throw new InvalidOperationException($"WireGuard keypair generation failed: {keypair.Message}");

            var server = await _wireguard.GetServerAsync(ct) ?? new WgServer { Name = "wg0", Mode = "server" };
            server.Mode = "server";
            server.PrivateKey = keypair.Data.PrivateKey;
            server.PublicKey  = keypair.Data.PublicKey;
            server.AddressCidr = addressCidr;
            server.ListenPort = config.WireGuardPort;
            server.Enabled = true;
            await _wireguard.SaveServerAsync(server, ct);

            var wgResp = await _daemon.ApplyWireGuardAsync(ct);
            if (!wgResp.Success)
                throw new InvalidOperationException($"WireGuard apply failed: {wgResp.Message}");

            _logger.LogInformation("WireGuard server applied on port {Port}, address {Addr}", server.ListenPort, server.AddressCidr);
        }

        // ── QoS / tc HTB ────────────────────────────────────────────────
        if (config.EnableQos)
        {
            if (config.DownloadBandwidthMbps is null || config.UploadBandwidthMbps is null)
                throw new InvalidOperationException("Download + upload bandwidth are required when QoS is enabled.");

            // Apply egress shaping on each WAN interface — total upload bw is what
            // the kernel can actually control on egress. Download shaping (ingress)
            // needs IFB and is left as a follow-up.
            var wans = (await _firewallService.GetInterfacesAsync(ct))
                .Where(i => string.Equals(i.Type, "WAN", StringComparison.OrdinalIgnoreCase) && i.Enabled)
                .ToList();
            if (wans.Count == 0)
            {
                _logger.LogWarning("QoS enabled but no WAN interfaces configured — skipping tc apply.");
            }
            else
            {
                foreach (var wan in wans)
                {
                    var qosConfig = new FwQosConfig
                    {
                        Id = Guid.NewGuid(),
                        InterfaceId = wan.Id,
                        TotalBandwidthMbps = config.UploadBandwidthMbps.Value,
                        Enabled = true
                    };
                    var saved = await _firewallService.CreateQosConfigAsync(qosConfig, ct);

                    // Two HTB classes — operator refines later in Firewall → QoS.
                    await _firewallService.CreateQosClassAsync(new FwQosClass
                    {
                        Id = Guid.NewGuid(),
                        QosConfigId = saved.Id,
                        Name = "high-priority",
                        GuaranteedMbps = Math.Max(1, config.UploadBandwidthMbps.Value / 2),
                        CeilingMbps = config.UploadBandwidthMbps.Value,
                        Priority = 1
                    }, ct);
                    await _firewallService.CreateQosClassAsync(new FwQosClass
                    {
                        Id = Guid.NewGuid(),
                        QosConfigId = saved.Id,
                        Name = "default",
                        GuaranteedMbps = Math.Max(1, config.UploadBandwidthMbps.Value / 2),
                        CeilingMbps = config.UploadBandwidthMbps.Value,
                        Priority = 2
                    }, ct);
                }

                var qosResp = await _daemon.ApplyQosAsync(ct);
                if (!qosResp.Success)
                    throw new InvalidOperationException($"QoS apply failed: {qosResp.Message}");

                _logger.LogInformation("QoS applied to {Count} WAN interface(s) at {Up}Mbps", wans.Count, config.UploadBandwidthMbps);
            }
        }
    }

    /// <summary>"10.100.0.0/24" → "10.100.0.1/24" so the wg interface gets an address that isn't the network base.</summary>
    private static string NormalizeWireGuardServerAddress(string subnet)
    {
        var slash = subnet.IndexOf('/');
        if (slash < 0) return subnet;
        if (!IPAddress.TryParse(subnet[..slash], out var net)) return subnet;
        var b = net.GetAddressBytes();
        if (b.Length != 4) return subnet;
        // Server takes .1 of the network — unless the operator already set a host bit.
        if (b[3] == 0) b[3] = 1;
        return $"{new IPAddress(b)}{subnet[slash..]}";
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

    // ------------------------------------------------------------------
    // Typed step accessors. Wrap the JSON columns so callers (controllers,
    // background jobs) never deal with serialization themselves.
    // ------------------------------------------------------------------

    public async Task<List<WizardInterfaceConfig>?> GetStep1InterfacesAsync(CancellationToken ct = default)
    {
        var state = await GetOrCreateWizardStateAsync(ct);
        return Deserialize<List<WizardInterfaceConfig>>(state.InterfacesConfigJson);
    }

    public async Task<List<WizardLanConfig>?> GetStep2LanAsync(CancellationToken ct = default)
    {
        var state = await GetOrCreateWizardStateAsync(ct);
        return Deserialize<List<WizardLanConfig>>(state.LanConfigJson);
    }

    public async Task<WizardFirewallConfig?> GetStep3FirewallAsync(CancellationToken ct = default)
    {
        var state = await GetOrCreateWizardStateAsync(ct);
        return Deserialize<WizardFirewallConfig>(state.FirewallConfigJson);
    }

    public async Task<WizardServicesConfig?> GetStep4ServicesAsync(CancellationToken ct = default)
    {
        var state = await GetOrCreateWizardStateAsync(ct);
        return Deserialize<WizardServicesConfig>(state.ServicesConfigJson);
    }

    public async Task SaveStep1InterfacesAsync(List<WizardInterfaceConfig> configs, CancellationToken ct = default)
    {
        var state = await GetOrCreateWizardStateAsync(ct);
        state.InterfacesConfigJson = JsonSerializer.Serialize(configs, JsonOptions);
        if (state.CurrentStep < 2) state.CurrentStep = 2;
        await UpdateWizardStateAsync(state, ct);
    }

    public async Task SaveStep2LanAsync(List<WizardLanConfig> configs, CancellationToken ct = default)
    {
        var state = await GetOrCreateWizardStateAsync(ct);
        state.LanConfigJson = JsonSerializer.Serialize(configs, JsonOptions);
        if (state.CurrentStep < 3) state.CurrentStep = 3;
        await UpdateWizardStateAsync(state, ct);
    }

    public async Task SaveStep3FirewallAsync(WizardFirewallConfig config, CancellationToken ct = default)
    {
        var state = await GetOrCreateWizardStateAsync(ct);
        state.FirewallConfigJson = JsonSerializer.Serialize(config, JsonOptions);
        if (state.CurrentStep < 4) state.CurrentStep = 4;
        await UpdateWizardStateAsync(state, ct);
    }

    public async Task SaveStep4ServicesAsync(WizardServicesConfig config, CancellationToken ct = default)
    {
        var state = await GetOrCreateWizardStateAsync(ct);
        state.ServicesConfigJson = JsonSerializer.Serialize(config, JsonOptions);
        if (state.CurrentStep < 5) state.CurrentStep = 5;
        await UpdateWizardStateAsync(state, ct);
    }

    public async Task SetCurrentStepAsync(int step, CancellationToken ct = default)
    {
        if (step < 1 || step > 5) throw new ArgumentOutOfRangeException(nameof(step));
        var state = await GetOrCreateWizardStateAsync(ct);
        if (state.CurrentStep == step) return;
        state.CurrentStep = step;
        await UpdateWizardStateAsync(state, ct);
    }

    private static T? Deserialize<T>(string? json) where T : class
        => string.IsNullOrEmpty(json) ? null : JsonSerializer.Deserialize<T>(json, JsonOptions);
}
