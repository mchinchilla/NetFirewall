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
    // Options 119 / 121 are encoded from the CACHED subnet's text (option 121 through a JSON
    // parse). Memoize by string instance: the subnet cache hands every packet the same string
    // until the next refresh, so each value is encoded once and dropped with the old cache.
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<string, byte[]> DomainSearchEncoded = new();
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<string, byte[]> StaticRoutesEncoded = new();

    private static byte[] EncodedOnce(System.Runtime.CompilerServices.ConditionalWeakTable<string, byte[]> memo, string text, Func<string, byte[]> encode) =>
        memo.GetValue(text, s => encode(s));

    private readonly IInterfaceAddressProvider? _interfaceAddresses;
    private readonly IDdnsUpdateQueue? _ddnsQueue;
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


    // Buffer pool for packet construction
    private readonly ArrayPool<byte> _bufferPool = ArrayPool<byte>.Shared;

    public DhcpServerService(
        IDhcpLeasesService dhcpLeasesService,
        IDhcpSubnetService dhcpSubnetService,
        ILogger<DhcpServerService> logger,
        IOptions<DhcpConfig> dhcpConfig,
        IFailoverService? failoverService = null,
        IInterfaceAddressProvider? interfaceAddresses = null,
        IDdnsUpdateQueue? ddnsQueue = null)
    {
        _interfaceAddresses = interfaceAddresses;
        _ddnsQueue = ddnsQueue;
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

    public async Task<DhcpResponseBuffer> CreateDhcpResponseAsync(DhcpRequest request)
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
                DhcpMessageType.Release => await HandleReleaseAsync(request, subnet).ConfigureAwait(false),
                DhcpMessageType.Decline => await HandleDeclineAsync(request, subnet).ConfigureAwait(false),
                DhcpMessageType.Inform => HandleInform(request, subnet, clientClass),
                // Unknown / BOOTP / server-to-server types: no reply (a NAK only ever answers a REQUEST).
                _ => DhcpResponseBuffer.Empty
            };

            if (response.IsEmpty)
            {
                _logger.LogWarning(
                    "[SERVICE] Empty response generated for {MessageType} from {Mac}",
                    request.MessageType, request.ClientMac);
            }

            return response;
        }
        catch (Exception ex)
        {
            // Silence, never a NAK: a NAK makes a RENEWING client drop its address at once, so a
            // database blip would knock every renewing client off the network. Without a reply the
            // client keeps its lease and retries (RFC 2131 §4.4.5).
            _logger.LogError(ex, "[SERVICE] Error creating DHCP response for {Mac} — not replying: {Message}",
                request.ClientMac, ex.Message);
            return DhcpResponseBuffer.Empty;
        }
    }

    private async Task<DhcpResponseBuffer> HandleDiscoverAsync(DhcpRequest request, DhcpSubnet? subnet, DhcpClass? clientClass)
    {
        _logger.LogDebug("[DISCOVER] Processing DISCOVER from {Mac}, Hostname: {Hostname}",
            request.ClientMac, request.Hostname ?? "(none)");

        // Check failover - should we handle this request?
        if (_failoverService != null && _failoverService.IsEnabled)
        {
            if (!_failoverService.CanServe)
            {
                _logger.LogDebug("[DISCOVER] Failover state prevents serving DISCOVER from {Mac}", request.ClientMac);
                return DhcpResponseBuffer.Empty; // Don't respond, let peer handle it
            }

            if (!_failoverService.ShouldHandleRequest(request.ClientMac, request.RequestedIp))
            {
                _logger.LogDebug("[DISCOVER] Load balancing: peer should handle DISCOVER from {Mac}", request.ClientMac);
                return DhcpResponseBuffer.Empty; // Let peer handle based on load balancing
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
            // RFC 2131: a NAK only ever answers a REQUEST. With nothing to offer the server stays
            // silent — the client retries and another server (if any) can answer.
            _logger.LogWarning(
                "[DISCOVER] No IP available for {Mac} in subnet '{Subnet}' — pool exhausted, not replying.",
                request.ClientMac, subnet?.Name ?? "fallback");
            return DhcpResponseBuffer.Empty;
        }

        _logger.LogInformation(
            "[DISCOVER] SUCCESS - Offering {Ip} to {Mac} (Hostname: {Hostname}) from {Subnet}/{Pool}",
            offeredIp, request.ClientMac, request.Hostname ?? "(none)",
            subnet?.Name ?? "fallback", pool?.Name ?? "default");

        return ConstructDhcpPacket(request, offeredIp, DhcpMessageType.Offer, subnet, clientClass);
    }

    private async Task<DhcpResponseBuffer> HandleRequestAsync(DhcpRequest request, DhcpSubnet? subnet, DhcpClass? clientClass)
    {
        _logger.LogDebug("[REQUEST] Processing REQUEST from {Mac}, RequestedIP: {RequestedIp}",
            request.ClientMac, request.RequestedIp);

        // RFC 2131 §4.3.2: a SELECTING client addresses its REQUEST to one
        // server via option 54. If that's not us, the client accepted another
        // server's offer — we must stay silent, not ACK/NAK on its behalf.
        var ourServerIp = ServerIdentifierFor(request, subnet);
        if (request.ServerIdentifier != null &&
            ourServerIp != null &&
            !request.ServerIdentifier.Equals(ourServerIp))
        {
            _logger.LogDebug(
                "[REQUEST] REQUEST from {Mac} addressed to server {Server} (we are {Us}) — ignoring",
                request.ClientMac, request.ServerIdentifier, ourServerIp);
            return DhcpResponseBuffer.Empty;
        }

        // Check failover - should we handle this request?
        if (_failoverService != null && _failoverService.IsEnabled)
        {
            if (!_failoverService.CanServe)
            {
                _logger.LogDebug("[REQUEST] Failover state prevents serving REQUEST from {Mac}", request.ClientMac);
                return DhcpResponseBuffer.Empty; // Don't respond
            }

            if (!_failoverService.ShouldHandleRequest(request.ClientMac, request.RequestedIp))
            {
                _logger.LogDebug("[REQUEST] Load balancing: peer should handle REQUEST from {Mac}", request.ClientMac);
                return DhcpResponseBuffer.Empty; // Let peer handle
            }
        }

        var requestedIp = request.RequestedIp;

        // A malformed option 50 of 0.0.0.0 is "no address", not a request for
        // the zero address — treat it like an absent option.
        if (requestedIp != null && requestedIp.Equals(IPAddress.Any))
        {
            requestedIp = null;
        }

        if (requestedIp == null)
        {
            // RENEWING / REBINDING: the client omits option 50 and puts its
            // current address in ciaddr instead (RFC 2131 §4.3.2). Trust
            // ciaddr first; fall back to our lease table for clients that
            // send neither.
            if (request.CiAddr != null && !request.CiAddr.Equals(IPAddress.Any))
            {
                _logger.LogDebug("[REQUEST] Renewal without option 50 — using CiAddr {Ip} for {Mac}",
                    request.CiAddr, request.ClientMac);
                requestedIp = request.CiAddr;
            }
        }

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

            // RFC 2131 §4.3.2: an address on the wrong network (a laptop arriving from another
            // LAN does INIT-REBOOT for its old IP) or one we'd never hand out MUST be NAKed —
            // ACKing it left the client with a foreign address and no connectivity.
            var verdict = subnet is not null
                ? await _dhcpSubnetService.CheckRequestedIpAsync(subnet, request.ClientMac, requestedIp).ConfigureAwait(false)
                : InFallbackRange(requestedIp) ? RequestedIpVerdict.Allowed : RequestedIpVerdict.WrongNetwork;
            if (verdict != RequestedIpVerdict.Allowed)
            {
                _logger.LogWarning("[REQUEST] NAK {Ip} for {Mac}: {Verdict} in subnet '{Subnet}'",
                    requestedIp, request.ClientMac, verdict, subnet?.Name ?? "fallback");
                return CreateNakResponse(request, subnet);
            }

            var canAssign = await _dhcpLeasesService.CanAssignIpAsync(request.ClientMac, requestedIp).ConfigureAwait(false);

            if (canAssign)
            {
                var leaseTime = subnet?.DefaultLeaseTime ?? _fallbackConfig.LeaseTime;

                _logger.LogDebug("[REQUEST] Assigning lease: {Ip} to {Mac} for {LeaseTime}s",
                    requestedIp, request.ClientMac, leaseTime);

                await _dhcpLeasesService.AssignLeaseAsync(
                    request.ClientMac,
                    requestedIp,
                    leaseTime,
                    request.Hostname
                ).ConfigureAwait(false);

                _logger.LogInformation(
                    "[REQUEST] SUCCESS - Assigned {Ip} to {Mac} (Hostname: {Hostname}) for {LeaseTime}s",
                    requestedIp, request.ClientMac, request.Hostname ?? "(none)", leaseTime);

                // DNS registration AFTER the ACK, off the packet path (the worker checks the subnet's
                // DDNS config; a slow DNS server can't delay this reply).
                if (!string.IsNullOrWhiteSpace(request.Hostname))
                    _ddnsQueue?.TryEnqueue(new DdnsWork(DdnsAction.Register, request.ClientMac, requestedIp, request.Hostname, subnet?.Id));

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

    /// <summary>RELEASE / DECLINE carry option 54: one addressed to ANOTHER server is not ours to act on.</summary>
    private bool AddressedToAnotherServer(DhcpRequest request, DhcpSubnet? subnet) =>
        request.ServerIdentifier is { } sid && !sid.Equals(IPAddress.Any)
        && !sid.Equals(ServerIdentifierFor(request, subnet));

    private async Task<DhcpResponseBuffer> HandleReleaseAsync(DhcpRequest request, DhcpSubnet? subnet)
    {
        if (AddressedToAnotherServer(request, subnet))
        {
            _logger.LogDebug("[RELEASE] From {Mac} for server {Server} — not ours, ignoring", request.ClientMac, request.ServerIdentifier);
            return DhcpResponseBuffer.Empty;
        }

        // Get the lease before releasing to notify failover peer
        var assignedIp = await _dhcpLeasesService.GetAssignedIpAsync(request.ClientMac).ConfigureAwait(false);

        // The client releases the address in ciaddr — only if that's the one we gave it (a stale or
        // spoofed RELEASE must not free the client's current lease).
        if (assignedIp is null
            || (request.CiAddr is { } ci && !ci.Equals(IPAddress.Any) && !ci.Equals(assignedIp)))
        {
            _logger.LogDebug("[RELEASE] {Mac} released {Ip} but holds {Assigned} — ignoring", request.ClientMac, request.CiAddr, assignedIp);
            return DhcpResponseBuffer.Empty;
        }

        await _dhcpLeasesService.ReleaseLeaseAsync(request.ClientMac).ConfigureAwait(false);
        _ddnsQueue?.TryEnqueue(new DdnsWork(DdnsAction.Remove, request.ClientMac, assignedIp, null, subnet?.Id));

        // Notify failover peer of release
        if (_failoverService != null && _failoverService.IsEnabled && assignedIp != null)
        {
            _ = _failoverService.SendBindingReleaseAsync(assignedIp, request.ClientMac);
        }

        if (_logger.IsEnabled(LogLevel.Debug))
        {
            _logger.LogDebug("Released lease for {Mac}", request.ClientMac);
        }
        return DhcpResponseBuffer.Empty; // RFC 2131: server doesn't reply to RELEASE
    }

    private async Task<DhcpResponseBuffer> HandleDeclineAsync(DhcpRequest request, DhcpSubnet? subnet)
    {
        var declined = request.RequestedIp;
        if (declined is null || declined.Equals(IPAddress.Any) || AddressedToAnotherServer(request, subnet))
            return DhcpResponseBuffer.Empty; // RFC 2131: server doesn't reply to DECLINE

        // A client can only decline the address WE assigned it. Declining used to quarantine any
        // IP and delete whatever lease held it — one bogus DECLINE knocked another client's lease out.
        var assigned = await _dhcpLeasesService.GetAssignedIpAsync(request.ClientMac).ConfigureAwait(false);
        if (assigned is null || !assigned.Equals(declined))
        {
            _logger.LogWarning("[DECLINE] {Mac} declined {Ip}, which is not its lease ({Assigned}) — ignoring",
                request.ClientMac, declined, assigned);
            return DhcpResponseBuffer.Empty;
        }

        await _dhcpLeasesService.MarkIpAsDeclinedAsync(declined).ConfigureAwait(false);
        _logger.LogWarning("IP {Ip} declined by {Mac} (address conflict) — quarantined", declined, request.ClientMac);
        return DhcpResponseBuffer.Empty; // RFC 2131: server doesn't reply to DECLINE
    }

    /// <summary>
    /// Option 54 — an address of THIS server the client can reach (RFC 2131 §4.1): on a directly
    /// attached subnet, our address on the receiving interface inside that subnet; for a relayed
    /// client, the interface address the relay talks to. It used to be the subnet's Router, which
    /// is wrong whenever the gateway is another box (and always for relayed subnets): unicast
    /// renewals went to the wrong host and leases only refreshed at T2 by broadcast.
    /// Falls back to the Router / configured ServerIp when the interface is unknown.
    /// </summary>
    internal IPAddress ServerIdentifierFor(DhcpRequest request, DhcpSubnet? subnet)
    {
        if (_interfaceAddresses is not null && !string.IsNullOrEmpty(request.SourceInterfaceName))
        {
            var addresses = _interfaceAddresses.GetIPv4(request.SourceInterfaceName);
            var relayed = request.GiAddr is { } gi && !gi.Equals(IPAddress.Any);
            if (!relayed && subnet is not null
                && DhcpSubnetService.TryParseCidr(subnet.Network, subnet.SubnetMask) is { } cidr)
            {
                Span<byte> b = stackalloc byte[4];
                foreach (var (address, _) in addresses)
                    if (address.TryWriteBytes(b, out var n) && n == 4 && DhcpSubnetService.IpMatchesNetwork(b, cidr))
                        return address;
            }
            if (addresses.Count > 0) return addresses[0].Address;
        }
        return subnet?.Router ?? _fallbackConfig.ServerIp!;
    }

    /// <summary>Fallback mode (no subnets configured): only the configured range is ours.</summary>
    private bool InFallbackRange(IPAddress ip) =>
        _fallbackConfig.IpRangeStart is { } start && _fallbackConfig.IpRangeEnd is { } end
        && ToUInt(ip) is { } v && ToUInt(start) is { } s && ToUInt(end) is { } e && v >= s && v <= e;

    private static uint? ToUInt(IPAddress ip)
    {
        Span<byte> b = stackalloc byte[4];
        return ip.TryWriteBytes(b, out var n) && n == 4 ? System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(b) : null;
    }

    private DhcpResponseBuffer HandleInform(DhcpRequest request, DhcpSubnet? subnet, DhcpClass? clientClass)
    {
        // RFC 2131 §3.4: an INFORM client has an address already and puts it in
        // ciaddr — option 50 is not part of INFORM. The ACK's yiaddr must be 0;
        // ciaddr is echoed by ConstructDhcpPacket and drives unicast routing.
        return ConstructDhcpPacket(request, IPAddress.Any, DhcpMessageType.Ack, subnet, clientClass, includeLeaseTime: false);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private DhcpResponseBuffer CreateNakResponse(DhcpRequest request, DhcpSubnet? subnet)
    {
        return ConstructDhcpPacket(request, IPAddress.Any, DhcpMessageType.Nak, subnet, null, includeLeaseTime: false);
    }

    private DhcpResponseBuffer ConstructDhcpPacket(
        DhcpRequest request,
        IPAddress assignedIp,
        DhcpMessageType messageType,
        DhcpSubnet? subnet,
        DhcpClass? clientClass,
        bool includeLeaseTime = true)
    {
        // Get effective configuration from subnet or fallback
        var serverIp = ServerIdentifierFor(request, subnet);
        var subnetMask = subnet?.SubnetMask ?? _fallbackConfig.SubnetMask!;
        var router = subnet?.Router ?? _fallbackConfig.Gateway!;
        var dnsServers = subnet?.DnsServers ?? _fallbackConfig.DnsServers.ToArray();
        var leaseTime = subnet?.DefaultLeaseTime ?? _fallbackConfig.LeaseTime;
        var domainName = subnet?.DomainName;
        var ntpServers = subnet?.NtpServers;
        var winsServers = subnet?.WinsServers;
        // RFC 2131 Table 3: a DHCPNAK carries no ciaddr, siaddr, sname or file.
        var isNak = messageType == DhcpMessageType.Nak;
        var bootFilename = isNak ? null : GetBootFilename(request, subnet, clientClass);
        var tftpServer = isNak ? null : clientClass?.NextServer?.ToString() ?? subnet?.TftpServer;

        // Rent buffer from pool. Caller (the worker) owns the rental from this
        // point on — DhcpResponseBuffer carries it to the wire and Disposes
        // back to the pool after send. We deliberately don't allocate a
        // right-sized copy at the end (saves ~280B/packet vs the old design).
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

            // Flags (2 bytes) - preserve client flags. A NAK sent through a relay MUST set the
            // broadcast bit (RFC 2131 §4.3.2): the client may have no usable address any more.
            var flags = request.Flags;
            if (isNak && request.GiAddr is { } relay && !relay.Equals(IPAddress.Any)) flags |= 0x8000;
            buffer[offset++] = (byte)(flags >> 8);
            buffer[offset++] = (byte)(flags & 0xFF);

            // ciaddr (4 bytes) — zero in a NAK
            var ciaddr = isNak ? IPAddress.Any : request.CiAddr ?? IPAddress.Any;
            ciaddr.GetAddressBytes().CopyTo(buffer, offset);
            offset += 4;

            // yiaddr (4 bytes)
            assignedIp.GetAddressBytes().CopyTo(buffer, offset);
            offset += 4;

            // siaddr (4 bytes) - TFTP server
            var siaddr = isNak ? IPAddress.Any
                : tftpServer != null && IPAddress.TryParse(tftpServer, out var tftpIp) ? tftpIp
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

            // RFC 6842: a client that sent a client identifier (61) gets it back — without it,
            // clients that key on client-id can discard the reply as not theirs.
            if (request.ClientIdentifier is { Length: > 0 and <= 255 } clientId)
                offset = WriteOption(buffer, offset, DhcpOptionCode.ClientIdentifier, clientId);

            // RFC 3046 §2.2: echo the relay's option 82 verbatim, as the last option. Cisco/Juniper
            // relays check for it by default and DROP replies without it — relayed clients never
            // got a lease. (OFFER, ACK and NAK all pass through here.)
            if (request.RelayAgentInformation is { Length: > 0 } relayInfo)
                offset = WriteOption(buffer, offset, DhcpOptionCode.RelayAgentInformation, relayInfo);

            // End option
            buffer[offset++] = (byte)DhcpOptionCode.End;

            // RFC 1542 §2.1: BOOTP messages are at least 300 bytes; some relays and older clients
            // drop shorter ones (a NAK was ~250). Pad with zeros (the pool buffer isn't zeroed).
            const int MinBootpMessage = 300;
            if (offset < MinBootpMessage)
            {
                buffer.AsSpan(offset, MinBootpMessage - offset).Clear();
                offset = MinBootpMessage;
            }

            // Hand the rental + length to the caller. No copy, no return-to-
            // pool here — the consumer's Dispose() does that after send.
            return new DhcpResponseBuffer(buffer, offset, _bufferPool);
        }
        catch
        {
            // Build failure: return the rental ourselves so it doesn't leak.
            _bufferPool.Return(buffer);
            throw;
        }
    }

    private static string? GetBootFilename(DhcpRequest request, DhcpSubnet? subnet, DhcpClass? clientClass) =>
        PxeBoot.BootFile(request, subnet, clientClass);

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
        var optionsStart = offset;

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
            var domainSearchBytes = EncodedOnce(DomainSearchEncoded, subnet.DomainSearchList, DhcpOptionExtensions.EncodeDomainSearchList);
            if (domainSearchBytes.Length > 0)
            {
                offset = WriteOption(buffer, offset, DhcpOptionCode.DomainSearch, domainSearchBytes);
            }
        }

        // Classless Static Routes (Option 121) - RFC 3442 encoded
        if (!string.IsNullOrEmpty(subnet?.StaticRoutesJson))
        {
            var routesBytes = EncodedOnce(StaticRoutesEncoded, subnet.StaticRoutesJson, DhcpOptionExtensions.EncodeClasslessStaticRoutes);
            if (routesBytes.Length > 0)
            {
                // RFC 3442: a client that understands 121 MUST ignore option 3 (Router). Without a
                // 0.0.0.0/0 entry here, configuring one static route took the default gateway away
                // from every Linux/macOS/Android/Windows client on the subnet.
                Span<byte> withDefault = stackalloc byte[routesBytes.Length + 5];
                offset = WriteOption(buffer, offset, DhcpOptionCode.ClasslessStaticRoute,
                    WithDefaultRoute(routesBytes, router, withDefault));
            }
        }

        // Time Offset (Option 2) - Seconds offset from UTC
        if (subnet?.TimeOffset.HasValue == true)
        {
            offset = WriteInt32Option(buffer, offset, DhcpOptionCode.TimeOffset, subnet.TimeOffset.Value);
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
            offset = WriteInt32Option(buffer, offset, DhcpOptionCode.IPAddressLeaseTime, leaseTime);
            offset = WriteInt32Option(buffer, offset, DhcpOptionCode.RenewalTimeValue, leaseTime / 2);
            offset = WriteInt32Option(buffer, offset, DhcpOptionCode.RebindingTimeValue, (int)((long)leaseTime * 7 / 8)); // long: leaseTime * 7 overflowed above ~306M s
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
                // PXE 2.1: the offer must say "PXEClient" (60) and how to boot (43: use the file,
                // skip boot-server discovery). Options 93/94 are CLIENT options and were wrongly
                // sent back; 97 is the client's UUID — echoed, never invented.
                offset = WriteOption(buffer, offset, DhcpOptionCode.VendorClassIdentifier, PxeBoot.PxeClientClass);
                offset = WriteOption(buffer, offset, DhcpOptionCode.VendorSpecificInformation, PxeBoot.VendorOptions);
                if (request.ClientMachineId is { Length: > 0 } uuid)
                    offset = WriteOption(buffer, offset, DhcpOptionCode.ClientMachineIdentifier, uuid);
            }
        }

        // Operator-defined options last (a NAK carries none). Host > class > subnet/global.
        if (messageType != DhcpMessageType.Nak)
            offset = WriteCustomOptions(buffer, optionsStart, offset, request, subnet, clientClass);

        return offset;
    }

    /// <summary>
    /// Custom options (dhcp_custom_options) for this client, most specific scope first. A code the
    /// server already wrote (router, DNS, lease times, PXE…) is skipped — those stay governed by the
    /// subnet's own fields — and so is any code a more specific scope already supplied. Room is
    /// kept for client-id, relay info and End; an option that doesn't fit is skipped, logged.
    /// </summary>
    private int WriteCustomOptions(byte[] buffer, int optionsStart, int offset, DhcpRequest request, DhcpSubnet? subnet, DhcpClass? clientClass)
    {
        if (subnet is null) return offset;
        subnet.HostOptions.TryGetValue(request.ClientMac, out var host);
        var cls = clientClass?.CustomOptions;
        if (host is null && (cls is null || cls.Count == 0) && subnet.CustomOptions.Count == 0) return offset;

        Span<bool> written = stackalloc bool[256];
        for (var i = optionsStart; i < offset;)
        {
            var code = buffer[i];
            if (code == 0) { i++; continue; }
            if (code == 255 || i + 1 >= offset) break;
            written[code] = true;
            i += 2 + buffer[i + 1];
        }

        // What must still follow: client-id, option 82, End (+ slack).
        var reserve = 1 + 4 + (request.ClientIdentifier?.Length + 2 ?? 0) + (request.RelayAgentInformation?.Length + 2 ?? 0);
        var limit = buffer.Length - reserve;

        foreach (var scope in new[] { host, cls, subnet.CustomOptions })
        {
            if (scope is null) continue;
            foreach (var o in scope)
            {
                if (o.OptionCode is < 1 or > 254 || written[o.OptionCode] || o.OptionValue.Length is 0 or > 255) continue;
                if (offset + 2 + o.OptionValue.Length > limit)
                {
                    _logger.LogWarning("[OPTIONS] Custom option {Code} for {Mac} doesn't fit in the reply — skipped", o.OptionCode, request.ClientMac);
                    continue;
                }
                offset = WriteOption(buffer, offset, (DhcpOptionCode)o.OptionCode, o.OptionValue);
                written[o.OptionCode] = true;
            }
        }
        return offset;
    }

    /// <summary>
    /// The RFC 3442 route list with a default route via <paramref name="router"/> appended — unless it
    /// already has one, or there is no IPv4 router to point it at. Pure; <paramref name="scratch"/>
    /// must hold routes + 5 bytes.
    /// </summary>
    internal static ReadOnlySpan<byte> WithDefaultRoute(ReadOnlySpan<byte> routes, IPAddress? router, Span<byte> scratch)
    {
        for (var i = 0; i < routes.Length;)
        {
            var width = routes[i];
            if (width == 0) return routes;                 // already carries 0.0.0.0/0
            i += 1 + (width + 7) / 8 + 4;                  // width, significant octets, gateway
        }
        if (router is null || !router.TryWriteBytes(scratch[(routes.Length + 1)..], out var n) || n != 4)
            return routes;
        routes.CopyTo(scratch);
        scratch[routes.Length] = 0;                        // width 0 = default route, no destination octets
        return scratch[..(routes.Length + 5)];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int WriteOption(byte[] buffer, int offset, DhcpOptionCode code, ReadOnlySpan<byte> data)
    {
        // A DHCP option length is one byte. Payloads > 255 (e.g. a runaway
        // domain-search list from config) would silently truncate the length
        // byte and emit a corrupt packet every client mis-parses. Throwing is
        // caught by CreateDhcpResponseAsync's catch-all → logged NAK, which is
        // recoverable; a corrupt OFFER is not.
        if (data.Length > 255)
            throw new InvalidOperationException(
                $"DHCP option {code} payload is {data.Length} bytes (max 255) — check subnet/class configuration.");

        buffer[offset++] = (byte)code;
        buffer[offset++] = (byte)data.Length;
        data.CopyTo(buffer.AsSpan(offset));
        return offset + data.Length;
    }

    /// <summary>
    /// Writes a DHCP option whose payload is a single big-endian Int32 (lease
    /// time, renewal time, time offset, etc.) directly into the response buffer
    /// — no intermediate <c>byte[4]</c> allocation. Each OFFER/ACK invokes this
    /// 3+ times; the previous <c>GetNetworkOrderInt32Bytes</c> helper allocated
    /// a 4-byte array per call (~60 KB/s GC pressure at 5k req/s sustained).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int WriteInt32Option(byte[] buffer, int offset, DhcpOptionCode code, int value)
    {
        buffer[offset++] = (byte)code;
        buffer[offset++] = 4;
        buffer[offset++] = (byte)((value >> 24) & 0xFF);
        buffer[offset++] = (byte)((value >> 16) & 0xFF);
        buffer[offset++] = (byte)((value >> 8) & 0xFF);
        buffer[offset++] = (byte)(value & 0xFF);
        return offset;
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
