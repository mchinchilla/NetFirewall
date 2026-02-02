using System.Buffers;
using System.Net;
using System.Runtime.CompilerServices;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Dhcp;

namespace NetFirewall.Services.Dhcp;

/// <summary>
/// High-performance DHCP server service with multi-subnet support and failover.
/// </summary>
public sealed class DhcpServerService : IDhcpServerService
{
    private readonly IDhcpLeasesService _dhcpLeasesService;
    private readonly IDhcpSubnetService _dhcpSubnetService;
    private readonly IFailoverService? _failoverService;
    private readonly ILogger<DhcpServerService> _logger;
    private readonly DhcpConfig _fallbackConfig;

    // Pre-allocated response types
    private static readonly byte[] OfferMessageType = [(byte)DhcpMessageType.Offer];
    private static readonly byte[] AckMessageType = [(byte)DhcpMessageType.Ack];
    private static readonly byte[] NakMessageType = [(byte)DhcpMessageType.Nak];

    // Magic cookie bytes
    private static readonly byte[] MagicCookie = [99, 130, 83, 99];

    // PXE options (pre-computed)
    private static readonly byte[] PxeArchTypeLegacy = [0x00, 0x00]; // BIOS x86
    private static readonly byte[] PxeArchTypeUefi64 = [0x00, 0x07]; // UEFI x64
    private static readonly byte[] PxeNetInterface = [0x01]; // Ethernet
    private static readonly byte[] PxeDiscoveryControl = [0x03];

    // Buffer pool for packet construction
    private readonly ArrayPool<byte> _bufferPool = ArrayPool<byte>.Shared;

    public DhcpServerService(
        IDhcpLeasesService dhcpLeasesService,
        IDhcpSubnetService dhcpSubnetService,
        ILogger<DhcpServerService> logger,
        IOptions<DhcpConfig> dhcpConfig,
        IFailoverService? failoverService = null)
    {
        _dhcpLeasesService = dhcpLeasesService;
        _dhcpSubnetService = dhcpSubnetService;
        _failoverService = failoverService;
        _logger = logger;

        // Fallback config if no subnets are defined
        var config = dhcpConfig.Value;
        if (config.ServerIp == null || config.IpRangeStart == null)
        {
            _fallbackConfig = CreateDefaultConfig();
        }
        else
        {
            _fallbackConfig = config;
        }
    }

    private static DhcpConfig CreateDefaultConfig() => new()
    {
        IpRangeStart = IPAddress.Parse("192.168.99.100"),
        IpRangeEnd = IPAddress.Parse("192.168.99.199"),
        ServerIp = IPAddress.Parse("192.168.99.1"),
        SubnetMask = IPAddress.Parse("255.255.255.0"),
        Gateway = IPAddress.Parse("192.168.99.1"),
        DnsServers = [IPAddress.Parse("1.1.1.1"), IPAddress.Parse("8.8.8.8")],
        LeaseTime = 86400
    };

    public async Task<byte[]> CreateDhcpResponseAsync(DhcpRequest request)
    {
        try
        {
            _logger.LogDebug("[SERVICE] Processing {MessageType} from {Mac}",
                request.MessageType, request.ClientMac);

            // Find the appropriate subnet for this request
            var subnet = await _dhcpSubnetService.FindSubnetForRequestAsync(request).ConfigureAwait(false);

            if (subnet != null)
            {
                _logger.LogDebug(
                    "[SERVICE] Found subnet: {SubnetName} ({Network}) for {Mac}",
                    subnet.Name, subnet.Network, request.ClientMac);
            }
            else
            {
                _logger.LogWarning(
                    "[SERVICE] No subnet found for {Mac} - will use fallback config. " +
                    "CiAddr={CiAddr}, GiAddr={GiAddr}, RequestedIp={RequestedIp}",
                    request.ClientMac,
                    request.CiAddr,
                    request.GiAddr,
                    request.RequestedIp);
            }

            // Match client class for conditional options
            var clientClass = await _dhcpSubnetService.MatchClientClassAsync(request).ConfigureAwait(false);

            if (clientClass != null)
            {
                _logger.LogDebug("[SERVICE] Matched client class: {ClassName} for {Mac}",
                    clientClass.Name, request.ClientMac);
            }

            var response = request.MessageType switch
            {
                DhcpMessageType.Discover => await HandleDiscoverAsync(request, subnet, clientClass).ConfigureAwait(false),
                DhcpMessageType.Request => await HandleRequestAsync(request, subnet, clientClass).ConfigureAwait(false),
                DhcpMessageType.Release => await HandleReleaseAsync(request).ConfigureAwait(false),
                DhcpMessageType.Decline => await HandleDeclineAsync(request).ConfigureAwait(false),
                DhcpMessageType.Inform => HandleInform(request, subnet, clientClass),
                _ => CreateNakResponse(request, subnet)
            };

            if (response.Length == 0)
            {
                _logger.LogWarning(
                    "[SERVICE] Empty response generated for {MessageType} from {Mac}",
                    request.MessageType, request.ClientMac);
            }

            return response;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[SERVICE] Error creating DHCP response for {Mac}: {Message}",
                request.ClientMac, ex.Message);
            return CreateNakResponse(request, null);
        }
    }

    private async Task<byte[]> HandleDiscoverAsync(DhcpRequest request, DhcpSubnet? subnet, DhcpClass? clientClass)
    {
        _logger.LogDebug("[DISCOVER] Processing DISCOVER from {Mac}, Hostname: {Hostname}",
            request.ClientMac, request.Hostname ?? "(none)");

        // Check failover - should we handle this request?
        if (_failoverService != null && _failoverService.IsEnabled)
        {
            if (!_failoverService.CanServe)
            {
                _logger.LogDebug("[DISCOVER] Failover state prevents serving DISCOVER from {Mac}", request.ClientMac);
                return []; // Don't respond, let peer handle it
            }

            if (!_failoverService.ShouldHandleRequest(request.ClientMac, request.RequestedIp))
            {
                _logger.LogDebug("[DISCOVER] Load balancing: peer should handle DISCOVER from {Mac}", request.ClientMac);
                return []; // Let peer handle based on load balancing
            }
        }

        IPAddress? offeredIp;
        DhcpPool? pool = null;

        if (subnet != null)
        {
            _logger.LogDebug("[DISCOVER] Using subnet '{SubnetName}' for {Mac}",
                subnet.Name, request.ClientMac);

            // Multi-subnet mode: find IP in subnet's pools
            (offeredIp, pool) = await _dhcpSubnetService.FindAvailableIpInSubnetAsync(
                subnet, request.ClientMac, request).ConfigureAwait(false);

            if (offeredIp != null)
            {
                _logger.LogDebug("[DISCOVER] Found IP {Ip} in pool '{PoolName}' for {Mac}",
                    offeredIp, pool?.Name ?? "unknown", request.ClientMac);
            }
            else
            {
                _logger.LogWarning(
                    "[DISCOVER] No IP available in subnet '{SubnetName}' pools for {Mac}. " +
                    "Check pool configuration and exclusions.",
                    subnet.Name, request.ClientMac);
            }
        }
        else
        {
            // Fallback mode: use legacy service
            _logger.LogDebug(
                "[DISCOVER] No subnet found, using fallback config. Range: {Start} - {End}",
                _fallbackConfig.IpRangeStart, _fallbackConfig.IpRangeEnd);

            offeredIp = await _dhcpLeasesService.OfferLeaseAsync(
                request.ClientMac,
                _fallbackConfig.IpRangeStart,
                _fallbackConfig.IpRangeEnd!
            ).ConfigureAwait(false);

            if (offeredIp != null)
            {
                _logger.LogDebug("[DISCOVER] Fallback offered IP {Ip} to {Mac}",
                    offeredIp, request.ClientMac);
            }
            else
            {
                _logger.LogWarning(
                    "[DISCOVER] Fallback mode: No IP available in range {Start}-{End} for {Mac}",
                    _fallbackConfig.IpRangeStart, _fallbackConfig.IpRangeEnd, request.ClientMac);
            }
        }

        if (offeredIp == null)
        {
            _logger.LogWarning(
                "[DISCOVER] FAILED - No IP available for {Mac} in subnet '{Subnet}'. Sending NAK.",
                request.ClientMac, subnet?.Name ?? "fallback");
            return CreateNakResponse(request, subnet);
        }

        _logger.LogInformation(
            "[DISCOVER] SUCCESS - Offering {Ip} to {Mac} (Hostname: {Hostname}) from {Subnet}/{Pool}",
            offeredIp, request.ClientMac, request.Hostname ?? "(none)",
            subnet?.Name ?? "fallback", pool?.Name ?? "default");

        return ConstructDhcpPacket(request, offeredIp, DhcpMessageType.Offer, subnet, clientClass);
    }

    private async Task<byte[]> HandleRequestAsync(DhcpRequest request, DhcpSubnet? subnet, DhcpClass? clientClass)
    {
        _logger.LogDebug("[REQUEST] Processing REQUEST from {Mac}, RequestedIP: {RequestedIp}",
            request.ClientMac, request.RequestedIp);

        // Check failover - should we handle this request?
        if (_failoverService != null && _failoverService.IsEnabled)
        {
            if (!_failoverService.CanServe)
            {
                _logger.LogDebug("[REQUEST] Failover state prevents serving REQUEST from {Mac}", request.ClientMac);
                return []; // Don't respond
            }

            if (!_failoverService.ShouldHandleRequest(request.ClientMac, request.RequestedIp))
            {
                _logger.LogDebug("[REQUEST] Load balancing: peer should handle REQUEST from {Mac}", request.ClientMac);
                return []; // Let peer handle
            }
        }

        var requestedIp = request.RequestedIp;

        if (requestedIp == null)
        {
            _logger.LogDebug("[REQUEST] No RequestedIP in request, looking up existing lease for {Mac}",
                request.ClientMac);
            requestedIp = await _dhcpLeasesService.GetAssignedIpAsync(request.ClientMac).ConfigureAwait(false);

            if (requestedIp != null)
            {
                _logger.LogDebug("[REQUEST] Found existing lease: {Ip} for {Mac}", requestedIp, request.ClientMac);
            }
            else
            {
                _logger.LogWarning("[REQUEST] No existing lease found for {Mac}", request.ClientMac);
            }
        }

        if (requestedIp != null)
        {
            _logger.LogDebug("[REQUEST] Checking if {Ip} can be assigned to {Mac}",
                requestedIp, request.ClientMac);

            var canAssign = await _dhcpLeasesService.CanAssignIpAsync(request.ClientMac, requestedIp).ConfigureAwait(false);

            if (canAssign)
            {
                var leaseTime = subnet?.DefaultLeaseTime ?? _fallbackConfig.LeaseTime;

                _logger.LogDebug("[REQUEST] Assigning lease: {Ip} to {Mac} for {LeaseTime}s",
                    requestedIp, request.ClientMac, leaseTime);

                await _dhcpLeasesService.AssignLeaseAsync(
                    request.ClientMac,
                    requestedIp,
                    leaseTime
                ).ConfigureAwait(false);

                _logger.LogInformation(
                    "[REQUEST] SUCCESS - Assigned {Ip} to {Mac} (Hostname: {Hostname}) for {LeaseTime}s",
                    requestedIp, request.ClientMac, request.Hostname ?? "(none)", leaseTime);

                // Notify failover peer of binding update
                if (_failoverService != null && _failoverService.IsEnabled)
                {
                    var update = new FailoverBindingUpdate
                    {
                        IpAddress = requestedIp,
                        MacAddress = request.ClientMac,
                        StartTime = DateTime.UtcNow,
                        EndTime = DateTime.UtcNow.AddSeconds(leaseTime),
                        BindingState = FailoverBindingState.Active,
                        ClientHostname = request.Hostname
                    };

                    // Fire and forget - don't block response to client
                    _ = _failoverService.SendBindingUpdateAsync(update);
                }

                return ConstructDhcpPacket(request, requestedIp, DhcpMessageType.Ack, subnet, clientClass);
            }
            else
            {
                _logger.LogWarning(
                    "[REQUEST] DENIED - Cannot assign {Ip} to {Mac}. IP may be in use by another client or reserved.",
                    requestedIp, request.ClientMac);
            }
        }

        _logger.LogWarning("[REQUEST] FAILED - Sending NAK to {Mac} for IP: {Ip}",
            request.ClientMac, requestedIp);
        return CreateNakResponse(request, subnet);
    }

    private async Task<byte[]> HandleReleaseAsync(DhcpRequest request)
    {
        // Get the lease before releasing to notify failover peer
        var assignedIp = await _dhcpLeasesService.GetAssignedIpAsync(request.ClientMac).ConfigureAwait(false);

        await _dhcpLeasesService.ReleaseLeaseAsync(request.ClientMac).ConfigureAwait(false);

        // Notify failover peer of release
        if (_failoverService != null && _failoverService.IsEnabled && assignedIp != null)
        {
            _ = _failoverService.SendBindingReleaseAsync(assignedIp, request.ClientMac);
        }

        if (_logger.IsEnabled(LogLevel.Debug))
        {
            _logger.LogDebug("Released lease for {Mac}", request.ClientMac);
        }
        return [];
    }

    private async Task<byte[]> HandleDeclineAsync(DhcpRequest request)
    {
        if (request.RequestedIp != null)
        {
            await _dhcpLeasesService.MarkIpAsDeclinedAsync(request.RequestedIp).ConfigureAwait(false);
            _logger.LogWarning("IP {Ip} declined by {Mac}", request.RequestedIp, request.ClientMac);
        }
        return [];
    }

    private byte[] HandleInform(DhcpRequest request, DhcpSubnet? subnet, DhcpClass? clientClass)
    {
        var clientIp = request.RequestedIp ?? request.CiAddr ?? IPAddress.Any;
        return ConstructDhcpPacket(request, clientIp, DhcpMessageType.Ack, subnet, clientClass, includeLeaseTime: false);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private byte[] CreateNakResponse(DhcpRequest request, DhcpSubnet? subnet)
    {
        return ConstructDhcpPacket(request, IPAddress.Any, DhcpMessageType.Nak, subnet, null, includeLeaseTime: false);
    }

    private byte[] ConstructDhcpPacket(
        DhcpRequest request,
        IPAddress assignedIp,
        DhcpMessageType messageType,
        DhcpSubnet? subnet,
        DhcpClass? clientClass,
        bool includeLeaseTime = true)
    {
        // Get effective configuration from subnet or fallback
        var serverIp = subnet?.Router ?? _fallbackConfig.ServerIp!;
        var subnetMask = subnet?.SubnetMask ?? _fallbackConfig.SubnetMask!;
        var router = subnet?.Router ?? _fallbackConfig.Gateway!;
        var dnsServers = subnet?.DnsServers ?? _fallbackConfig.DnsServers.ToArray();
        var leaseTime = subnet?.DefaultLeaseTime ?? _fallbackConfig.LeaseTime;
        var domainName = subnet?.DomainName;
        var ntpServers = subnet?.NtpServers;
        var winsServers = subnet?.WinsServers;
        var bootFilename = GetBootFilename(request, subnet, clientClass);
        var tftpServer = clientClass?.NextServer?.ToString() ?? subnet?.TftpServer;

        // Rent buffer from pool (max DHCP packet is ~576 bytes, allocate 1024 for safety)
        var buffer = _bufferPool.Rent(1024);

        try
        {
            int offset = 0;

            // Fixed header (236 bytes)
            buffer[offset++] = 2; // op = BOOTREPLY
            buffer[offset++] = 1; // htype = Ethernet
            buffer[offset++] = 6; // hlen = 6 bytes MAC
            buffer[offset++] = 0; // hops

            // XID (4 bytes)
            request.Xid.CopyTo(buffer, offset);
            offset += 4;

            // Secs (2 bytes)
            buffer[offset++] = 0;
            buffer[offset++] = 0;

            // Flags (2 bytes) - preserve client flags
            buffer[offset++] = (byte)(request.Flags >> 8);
            buffer[offset++] = (byte)(request.Flags & 0xFF);

            // ciaddr (4 bytes)
            var ciaddr = request.CiAddr ?? IPAddress.Any;
            ciaddr.GetAddressBytes().CopyTo(buffer, offset);
            offset += 4;

            // yiaddr (4 bytes)
            assignedIp.GetAddressBytes().CopyTo(buffer, offset);
            offset += 4;

            // siaddr (4 bytes) - TFTP server
            var siaddr = tftpServer != null && IPAddress.TryParse(tftpServer, out var tftpIp)
                ? tftpIp
                : serverIp;
            siaddr.GetAddressBytes().CopyTo(buffer, offset);
            offset += 4;

            // giaddr (4 bytes)
            var giaddr = request.GiAddr ?? IPAddress.Any;
            giaddr.GetAddressBytes().CopyTo(buffer, offset);
            offset += 4;

            // chaddr (16 bytes) - clear all 16 bytes first, then write MAC
            buffer.AsSpan(offset, 16).Clear();
            ParseMacToBytes(request.ClientMac, buffer.AsSpan(offset, 6));
            offset += 16;

            // sname (64 bytes) - MUST clear entire field (ArrayPool doesn't guarantee zeroed memory)
            buffer.AsSpan(offset, 64).Clear();
            if (!string.IsNullOrEmpty(tftpServer))
            {
                var tftpBytes = Encoding.ASCII.GetBytes(tftpServer);
                var copyLen = Math.Min(tftpBytes.Length, 63);
                tftpBytes.AsSpan(0, copyLen).CopyTo(buffer.AsSpan(offset));
            }
            offset += 64;

            // file (128 bytes) - MUST clear entire field (ArrayPool doesn't guarantee zeroed memory)
            buffer.AsSpan(offset, 128).Clear();
            if (!string.IsNullOrEmpty(bootFilename))
            {
                var bootBytes = Encoding.ASCII.GetBytes(bootFilename);
                var copyLen = Math.Min(bootBytes.Length, 127);
                bootBytes.AsSpan(0, copyLen).CopyTo(buffer.AsSpan(offset));
            }
            offset += 128;

            // Magic cookie
            MagicCookie.CopyTo(buffer, offset);
            offset += 4;

            // DHCP Options
            offset = WriteOptions(buffer, offset, messageType, request, subnet, clientClass,
                serverIp, subnetMask, router, dnsServers, leaseTime,
                domainName, ntpServers, winsServers, bootFilename, includeLeaseTime);

            // End option
            buffer[offset++] = (byte)DhcpOptionCode.End;

            // Copy to correctly-sized array
            var result = new byte[offset];
            Buffer.BlockCopy(buffer, 0, result, 0, offset);
            return result;
        }
        finally
        {
            _bufferPool.Return(buffer);
        }
    }

    private static string? GetBootFilename(DhcpRequest request, DhcpSubnet? subnet, DhcpClass? clientClass)
    {
        // Priority: class override > PXE detection > subnet config
        if (clientClass?.BootFilename != null)
        {
            return clientClass.BootFilename;
        }

        if (request.IsPxeRequest && subnet != null)
        {
            // Detect UEFI vs Legacy BIOS from vendor class
            var isUefi = request.VendorClassIdentifier?.Contains("00007") == true ||
                         request.VendorClassIdentifier?.Contains("00009") == true ||
                         request.VendorClassIdentifier?.Contains("Arch:00007") == true;

            if (isUefi && !string.IsNullOrEmpty(subnet.BootFilenameUefi))
            {
                return subnet.BootFilenameUefi;
            }
        }

        return subnet?.BootFilename ?? request.File;
    }

    private int WriteOptions(
        byte[] buffer, int offset,
        DhcpMessageType messageType,
        DhcpRequest request,
        DhcpSubnet? subnet,
        DhcpClass? clientClass,
        IPAddress serverIp,
        IPAddress subnetMask,
        IPAddress router,
        IPAddress[]? dnsServers,
        int leaseTime,
        string? domainName,
        IPAddress[]? ntpServers,
        IPAddress[]? winsServers,
        string? bootFilename,
        bool includeLeaseTime)
    {
        // Message Type (required)
        offset = WriteOption(buffer, offset, DhcpOptionCode.MessageType,
            messageType switch
            {
                DhcpMessageType.Offer => OfferMessageType,
                DhcpMessageType.Ack => AckMessageType,
                _ => NakMessageType
            });

        // For NAK, only include message type and server identifier
        if (messageType == DhcpMessageType.Nak)
        {
            offset = WriteOption(buffer, offset, DhcpOptionCode.ServerIdentifier, serverIp.GetAddressBytes());
            return offset;
        }

        // Server Identifier
        offset = WriteOption(buffer, offset, DhcpOptionCode.ServerIdentifier, serverIp.GetAddressBytes());

        // Subnet Mask
        offset = WriteOption(buffer, offset, DhcpOptionCode.SubnetMask, subnetMask.GetAddressBytes());

        // Router/Gateway
        offset = WriteOption(buffer, offset, DhcpOptionCode.Router, router.GetAddressBytes());

        // Broadcast Address (calculate from network + inverted mask)
        if (subnet?.Broadcast != null)
        {
            offset = WriteOption(buffer, offset, DhcpOptionCode.BroadcastAddress, subnet.Broadcast.GetAddressBytes());
        }

        // DNS Servers
        if (dnsServers is { Length: > 0 })
        {
            var dnsBytes = new byte[dnsServers.Length * 4];
            for (int i = 0; i < dnsServers.Length; i++)
            {
                dnsServers[i].GetAddressBytes().CopyTo(dnsBytes, i * 4);
            }
            offset = WriteOption(buffer, offset, DhcpOptionCode.DNS, dnsBytes);
        }

        // Domain Name (Option 15)
        if (!string.IsNullOrEmpty(domainName))
        {
            offset = WriteOption(buffer, offset, DhcpOptionCode.DomainName, Encoding.ASCII.GetBytes(domainName));
        }

        // Hostname (Option 12) - Echo back client's hostname if provided
        if (!string.IsNullOrEmpty(request.Hostname))
        {
            offset = WriteOption(buffer, offset, DhcpOptionCode.HostName, Encoding.ASCII.GetBytes(request.Hostname));
        }

        // Domain Search List (Option 119) - RFC 1035 encoded
        if (!string.IsNullOrEmpty(subnet?.DomainSearchList))
        {
            var domainSearchBytes = DhcpOptionExtensions.EncodeDomainSearchList(subnet.DomainSearchList);
            if (domainSearchBytes.Length > 0)
            {
                offset = WriteOption(buffer, offset, DhcpOptionCode.DomainSearch, domainSearchBytes);
            }
        }

        // Classless Static Routes (Option 121) - RFC 3442 encoded
        if (!string.IsNullOrEmpty(subnet?.StaticRoutesJson))
        {
            var routesBytes = DhcpOptionExtensions.EncodeClasslessStaticRoutes(subnet.StaticRoutesJson);
            if (routesBytes.Length > 0)
            {
                offset = WriteOption(buffer, offset, DhcpOptionCode.ClasslessStaticRoute, routesBytes);
            }
        }

        // Time Offset (Option 2) - Seconds offset from UTC
        if (subnet?.TimeOffset.HasValue == true)
        {
            offset = WriteOption(buffer, offset, DhcpOptionCode.TimeOffset,
                GetNetworkOrderInt32Bytes(subnet.TimeOffset.Value));
        }

        // POSIX Timezone (Option 100)
        if (!string.IsNullOrEmpty(subnet?.PosixTimezone))
        {
            offset = WriteOption(buffer, offset, DhcpOptionCode.POSIXTimeZone,
                Encoding.ASCII.GetBytes(subnet.PosixTimezone));
        }

        // NTP Servers
        if (ntpServers is { Length: > 0 })
        {
            var ntpBytes = new byte[ntpServers.Length * 4];
            for (int i = 0; i < ntpServers.Length; i++)
            {
                ntpServers[i].GetAddressBytes().CopyTo(ntpBytes, i * 4);
            }
            offset = WriteOption(buffer, offset, DhcpOptionCode.NTPServers, ntpBytes);
        }

        // WINS/NetBIOS Servers
        if (winsServers is { Length: > 0 })
        {
            var winsBytes = new byte[winsServers.Length * 4];
            for (int i = 0; i < winsServers.Length; i++)
            {
                winsServers[i].GetAddressBytes().CopyTo(winsBytes, i * 4);
            }
            offset = WriteOption(buffer, offset, DhcpOptionCode.NetBIOSOverTCPIPNameServer, winsBytes);
            // Set NetBIOS node type to hybrid (0x08)
            offset = WriteOption(buffer, offset, DhcpOptionCode.NetBIOSOverTCPIPNodeType, [0x08]);
        }

        // Interface MTU
        if (subnet?.InterfaceMtu.HasValue == true)
        {
            var mtuBytes = new byte[2];
            mtuBytes[0] = (byte)(subnet.InterfaceMtu.Value >> 8);
            mtuBytes[1] = (byte)(subnet.InterfaceMtu.Value & 0xFF);
            offset = WriteOption(buffer, offset, DhcpOptionCode.InterfaceMTU, mtuBytes);
        }

        // Lease timing options
        if (includeLeaseTime)
        {
            offset = WriteOption(buffer, offset, DhcpOptionCode.IPAddressLeaseTime,
                GetNetworkOrderInt32Bytes(leaseTime));
            offset = WriteOption(buffer, offset, DhcpOptionCode.RenewalTimeValue,
                GetNetworkOrderInt32Bytes(leaseTime / 2));
            offset = WriteOption(buffer, offset, DhcpOptionCode.RebindingTimeValue,
                GetNetworkOrderInt32Bytes((leaseTime * 7) / 8));
        }

        // PXE/BOOTP options
        if (request.IsPxeRequest || request.IsBootp)
        {
            if (!string.IsNullOrEmpty(bootFilename))
            {
                offset = WriteOption(buffer, offset, DhcpOptionCode.BootFileName,
                    Encoding.ASCII.GetBytes(bootFilename));
            }

            var tftpServer = clientClass?.NextServer?.ToString() ?? subnet?.TftpServer;
            if (!string.IsNullOrEmpty(tftpServer))
            {
                offset = WriteOption(buffer, offset, DhcpOptionCode.TFTPServerName,
                    Encoding.ASCII.GetBytes(tftpServer));
            }

            if (request.IsPxeRequest)
            {
                // Detect architecture and send appropriate PXE options
                var isUefi = request.VendorClassIdentifier?.Contains("00007") == true ||
                             request.VendorClassIdentifier?.Contains("Arch:00007") == true;

                offset = WriteOption(buffer, offset, DhcpOptionCode.PxeClientArchType,
                    isUefi ? PxeArchTypeUefi64 : PxeArchTypeLegacy);
                offset = WriteOption(buffer, offset, DhcpOptionCode.PxeClientNetworkInterface, PxeNetInterface);
                offset = WriteOption(buffer, offset, DhcpOptionCode.PxeDiscoveryControl, PxeDiscoveryControl);
            }
        }

        return offset;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int WriteOption(byte[] buffer, int offset, DhcpOptionCode code, ReadOnlySpan<byte> data)
    {
        buffer[offset++] = (byte)code;
        buffer[offset++] = (byte)data.Length;
        data.CopyTo(buffer.AsSpan(offset));
        return offset + data.Length;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte[] GetNetworkOrderInt32Bytes(int value)
    {
        // Convert to network byte order (big-endian) by extracting bytes from MSB to LSB
        // DO NOT use IPAddress.HostToNetworkOrder here - manual extraction is clearer and correct
        return
        [
            (byte)((value >> 24) & 0xFF),
            (byte)((value >> 16) & 0xFF),
            (byte)((value >> 8) & 0xFF),
            (byte)(value & 0xFF)
        ];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void ParseMacToBytes(string macAddress, Span<byte> destination)
    {
        int byteIndex = 0;
        int charIndex = 0;

        while (byteIndex < 6 && charIndex < macAddress.Length)
        {
            byte high = ParseHexChar(macAddress[charIndex++]);
            byte low = ParseHexChar(macAddress[charIndex++]);
            destination[byteIndex++] = (byte)((high << 4) | low);

            if (charIndex < macAddress.Length && macAddress[charIndex] == ':')
            {
                charIndex++;
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte ParseHexChar(char c)
    {
        return c switch
        {
            >= '0' and <= '9' => (byte)(c - '0'),
            >= 'A' and <= 'F' => (byte)(c - 'A' + 10),
            >= 'a' and <= 'f' => (byte)(c - 'a' + 10),
            _ => 0
        };
    }
}
