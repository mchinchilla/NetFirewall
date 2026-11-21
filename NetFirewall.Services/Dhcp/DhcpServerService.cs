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
    private readonly IDhcpReservationCache? _reservations;
    private readonly IDhcpBlocklistCache? _blocklist;
    private readonly IDhcpRelayTrustCache? _relayTrust;
    // Static: the service is SCOPED (one instance per packet), so an instance field would reset
    // every packet and the throttles would never engage.
    private static long _lastRelayDropLogTicks;
    private static long _lastSizeDropLogTicks;

    /// <summary>True at most once a minute per <paramref name="lastTicks"/> slot.</summary>
    private static bool OncePerMinute(ref long lastTicks)
    {
        var now = Environment.TickCount64;
        var last = Interlocked.Read(ref lastTicks);
        if (last != 0 && now - last < 60_000) return false;
        return Interlocked.CompareExchange(ref lastTicks, now, last) == last;
    }
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
        IDdnsUpdateQueue? ddnsQueue = null,
        IDhcpReservationCache? reservations = null,
        IDhcpBlocklistCache? blocklist = null,
        IDhcpRelayTrustCache? relayTrust = null)
    {
        _reservations = reservations;
        _blocklist = blocklist;
        _relayTrust = relayTrust;
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

            // Blocked device (dhcp_mac_blocklist): no reply to anything, not even a NAK.
            if (_blocklist is not null && await _blocklist.IsBlockedAsync(request.ClientMac).ConfigureAwait(false))
            {
                _logger.LogDebug("[BLOCKLIST] {MessageType} from blocked {Mac} — ignored", request.MessageType, request.ClientMac);
                return DhcpResponseBuffer.Empty;
            }

            // Trusted-relay list (dhcp_relay_agents): only listed relays are answered once one is trusted.
            if (_relayTrust is not null)
            {
                var policy = await _relayTrust.GetPolicyAsync().ConfigureAwait(false);
                switch (policy.Evaluate(request.GiAddr, request.RelayAgentInformation is { Length: > 0 }))
                {
                    case DhcpRelayVerdict.Drop:
                        LogRelayDrop(request);
                        return DhcpResponseBuffer.Empty;
                    case DhcpRelayVerdict.AcceptIgnoringOption82:
                        request.RelayAgentInfoTrusted = false;
                        break;
                }
            }

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

    /// <summary>At most one warning a minute: a misconfigured relay would otherwise flood the log.</summary>
    private void LogRelayDrop(DhcpRequest request)
    {
        if (!OncePerMinute(ref _lastRelayDropLogTicks))
        {
            _logger.LogDebug("[RELAY] Dropped {MessageType} from {Mac} via untrusted relay {Relay}", request.MessageType, request.ClientMac, request.GiAddr);
            return;
        }
        _logger.LogWarning(
            "[RELAY] Dropped {MessageType} from {Mac} relayed by {Relay}, which is not a trusted relay (DHCP → Access control). Further drops this minute are logged at Debug.",
            request.MessageType, request.ClientMac, request.GiAddr);
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

        var offerLease = await LeaseTimeForAsync(request, subnet).ConfigureAwait(false);
        return ConstructDhcpPacket(request, offeredIp, DhcpMessageType.Offer, subnet, clientClass, offerLease);
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
                var leaseTime = await LeaseTimeForAsync(request, subnet).ConfigureAwait(false);

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

                return ConstructDhcpPacket(request, requestedIp, DhcpMessageType.Ack, subnet, clientClass, leaseTime);
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
        return ConstructDhcpPacket(request, IPAddress.Any, DhcpMessageType.Ack, subnet, clientClass, leaseTime: null);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private DhcpResponseBuffer CreateNakResponse(DhcpRequest request, DhcpSubnet? subnet)
    {
        return ConstructDhcpPacket(request, IPAddress.Any, DhcpMessageType.Nak, subnet, null, leaseTime: null);
    }

    /// <summary>
    /// Lease length for this client: the reservation's own lease time (migration 00051) when it has
    /// one, else the subnet's default, else the fallback config. Resolved ONCE per exchange — the
    /// stored lease, option 51 and the failover binding must all agree.
    /// </summary>
    private async ValueTask<int> LeaseTimeForAsync(DhcpRequest request, DhcpSubnet? subnet)
    {
        if (_reservations is not null
            && await _reservations.GetLeaseTimeAsync(request.ClientMac).ConfigureAwait(false) is { } perHost)
            return perHost;
        return subnet?.DefaultLeaseTime ?? _fallbackConfig.LeaseTime;
    }

    /// <summary>
    /// Bytes of DHCP message (BOOTP header + options, no IP/UDP) this client accepts. RFC 2131 §2: a
    /// client must accept a 576-octet IP datagram — 548 bytes of DHCP after the 20-byte IP and 8-byte
    /// UDP headers. Option 57 (RFC 2132 §9.10, minimum legal value 576) raises it; it is read as the
    /// whole datagram, as ISC dhcpd and dnsmasq do. Capped at the reply buffer.
    /// </summary>
    internal static int ReplyLimit(DhcpRequest request, int bufferLength)
    {
        const int MinDatagram = 576, IpUdpHeaders = 28;
        var datagram = request.MaxMessageSize is { } m && m >= MinDatagram ? m : MinDatagram;
        return Math.Min(datagram - IpUdpHeaders, bufferLength);
    }

    private const int ReplyBufferSize = 1024;

    private DhcpResponseBuffer ConstructDhcpPacket(
        DhcpRequest request,
        IPAddress assignedIp,
        DhcpMessageType messageType,
        DhcpSubnet? subnet,
        DhcpClass? clientClass,
        int? leaseTime)
    {
        // Get effective configuration from subnet or fallback
        var serverIp = ServerIdentifierFor(request, subnet);
        var subnetMask = subnet?.SubnetMask ?? _fallbackConfig.SubnetMask!;
        var router = subnet?.Router ?? _fallbackConfig.Gateway!;
        var dnsServers = subnet?.DnsServers ?? _fallbackConfig.DnsServers.ToArray();
        // RFC 2131 Table 3: a DHCPNAK carries no ciaddr, siaddr, sname or file.
        var isNak = messageType == DhcpMessageType.Nak;
        var bootFilename = isNak ? null : GetBootFilename(request, subnet, clientClass);
        var tftpServer = isNak || request.IsHttpBoot ? null : clientClass?.NextServer?.ToString() ?? subnet?.TftpServer;

        // Rent buffer from pool. Caller (the worker) owns the rental from this
        // point on — DhcpResponseBuffer carries it to the wire and Disposes
        // back to the pool after send. We deliberately don't allocate a
        // right-sized copy at the end (saves ~280B/packet vs the old design).
        var buffer = _bufferPool.Rent(ReplyBufferSize);

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
            offset = WriteIp(buffer, offset, ciaddr);

            // yiaddr (4 bytes)
            offset = WriteIp(buffer, offset, assignedIp);

            // siaddr (4 bytes) - TFTP server
            var siaddr = isNak ? IPAddress.Any
                : tftpServer != null && IPAddress.TryParse(tftpServer, out var tftpIp) ? tftpIp
                : serverIp;
            offset = WriteIp(buffer, offset, siaddr);

            // giaddr (4 bytes)
            offset = WriteIp(buffer, offset, request.GiAddr ?? IPAddress.Any);

            // chaddr (16 bytes) - clear all 16 bytes first, then write MAC
            buffer.AsSpan(offset, 16).Clear();
            ParseMacToBytes(request.ClientMac, buffer.AsSpan(offset, 6));
            offset += 16;

            // sname (64 bytes) - MUST clear entire field (ArrayPool doesn't guarantee zeroed memory)
            buffer.AsSpan(offset, 64).Clear();
            if (!string.IsNullOrEmpty(tftpServer) && tftpServer.Length <= 63)
                Encoding.ASCII.GetBytes(tftpServer, buffer.AsSpan(offset, 63));
            offset += 64;

            // file (128 bytes) - MUST clear entire field. A name that doesn't fit (an HTTP boot URL,
            // an iPXE script URL) is NOT truncated into it — a cut URL boots nothing; it travels in
            // option 67 instead, which every PXE/HTTP client reads.
            buffer.AsSpan(offset, 128).Clear();
            if (!string.IsNullOrEmpty(bootFilename) && bootFilename.Length <= 127)
                Encoding.ASCII.GetBytes(bootFilename, buffer.AsSpan(offset, 127));
            offset += 128;

            // Magic cookie
            MagicCookie.CopyTo(buffer, offset);
            offset += 4;

            // What must still follow the options: client-id (61), relay info (82), End.
            var reserve = 1 + (request.ClientIdentifier is { Length: > 0 and <= 255 } cid ? cid.Length + 2 : 0)
                            + (request.RelayAgentInformation is { Length: > 0 } ri ? ri.Length + 2 : 0);
            var limit = ReplyLimit(request, ReplyBufferSize) - reserve;

            // DHCP Options
            Span<bool> governed = stackalloc bool[256];
            var writer = new OptionWriter(buffer, offset, limit, request.ParameterRequestList, governed);
            WriteOptions(ref writer, messageType, request, subnet, clientClass,
                serverIp, subnetMask, router, dnsServers, leaseTime, bootFilename, tftpServer);
            offset = writer.Offset;

            if (writer.Dropped > 0)
            {
                // Once a minute at Warning (a heavy option set hits every client that sends no 57), else Debug.
                if (OncePerMinute(ref _lastSizeDropLogTicks))
                    _logger.LogWarning("[OPTIONS] {Count} option(s) for {Mac} didn't fit in the {Limit}-byte reply it accepts — skipped. Further cases this minute are logged at Debug.",
                        writer.Dropped, request.ClientMac, limit + reserve);
                else
                    _logger.LogDebug("[OPTIONS] {Count} option(s) for {Mac} didn't fit in the {Limit}-byte reply — skipped",
                        writer.Dropped, request.ClientMac, limit + reserve);
            }

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

    /// <summary>
    /// Writes options into the reply. Two kinds:
    /// <list type="bullet">
    /// <item><b>Always</b> — 53, 54, 1, 3, the lease times, and the boot options for a PXE/HTTP/BOOTP
    /// client. Sent whatever the client asked for; they fit by construction (they come first).</item>
    /// <item><b>Requested</b> — everything else the subnet configures: sent only when the client's
    /// parameter request list (55) names it — or when it sent no list (older clients, BOOTP) — and
    /// only while it fits in the size the client accepts (57).</item>
    /// </list>
    /// Every code the server configures is marked <c>Governed</c> even when skipped, so a custom
    /// option can't slip the same code in through the back door.
    /// </summary>
    private ref struct OptionWriter
    {
        private readonly byte[] _buffer;
        private readonly ReadOnlySpan<byte> _prl;
        private readonly int _limit;
        public readonly Span<bool> Governed;
        public int Offset;
        public int Dropped;

        public OptionWriter(byte[] buffer, int offset, int limit, ReadOnlySpan<byte> prl, Span<bool> governed)
        {
            _buffer = buffer;
            Offset = offset;
            _limit = limit;
            _prl = prl;
            Governed = governed;
        }

        /// <summary>No list (or an empty one) = the client takes whatever we send.</summary>
        public readonly bool Requested(int code) => _prl.IsEmpty || _prl.IndexOf((byte)code) >= 0;

        public readonly bool HasPrl => !_prl.IsEmpty;

        public readonly bool Fits(int length) => Offset + 2 + length <= _limit;

        /// <summary>The server owns <paramref name="code"/>; true when the client wants it.</summary>
        public bool Take(DhcpOptionCode code)
        {
            Governed[(byte)code] = true;
            return Requested((byte)code);
        }

        public void Always(DhcpOptionCode code, scoped ReadOnlySpan<byte> data)
        {
            Governed[(byte)code] = true;
            Offset = WriteOption(_buffer, Offset, code, data);
        }

        public void AlwaysInt32(DhcpOptionCode code, int value)
        {
            Governed[(byte)code] = true;
            Offset = WriteInt32Option(_buffer, Offset, code, value);
        }

        /// <summary>Writes a requested option when it fits; counts it as dropped otherwise.</summary>
        public void Put(DhcpOptionCode code, scoped ReadOnlySpan<byte> data)
        {
            if (data.Length > 255)   // let WriteOption throw its configuration error
            {
                Offset = WriteOption(_buffer, Offset, code, data);
                return;
            }
            if (!Fits(data.Length)) { Dropped++; return; }
            Offset = WriteOption(_buffer, Offset, code, data);
        }

        public void PutInt32(DhcpOptionCode code, int value)
        {
            if (!Fits(4)) { Dropped++; return; }
            Offset = WriteInt32Option(_buffer, Offset, code, value);
        }
    }

    private void WriteOptions(
        ref OptionWriter w,
        DhcpMessageType messageType,
        DhcpRequest request,
        DhcpSubnet? subnet,
        DhcpClass? clientClass,
        IPAddress serverIp,
        IPAddress subnetMask,
        IPAddress router,
        IPAddress[]? dnsServers,
        int? leaseTime,
        string? bootFilename,
        string? tftpServer)
    {
        Span<byte> scratch = stackalloc byte[255];

        // Message Type (required)
        w.Always(DhcpOptionCode.MessageType,
            messageType switch
            {
                DhcpMessageType.Offer => OfferMessageType,
                DhcpMessageType.Ack => AckMessageType,
                _ => NakMessageType
            });

        // Server Identifier — and for a NAK, nothing else.
        w.Always(DhcpOptionCode.ServerIdentifier, Ip4(serverIp, scratch));
        if (messageType == DhcpMessageType.Nak) return;

        w.Always(DhcpOptionCode.SubnetMask, Ip4(subnetMask, scratch));
        w.Always(DhcpOptionCode.Router, Ip4(router, scratch));

        // Lease timing — right after the essentials so a small reply never loses it.
        if (leaseTime is { } lease)
        {
            w.AlwaysInt32(DhcpOptionCode.IPAddressLeaseTime, lease);
            w.AlwaysInt32(DhcpOptionCode.RenewalTimeValue, lease / 2);
            w.AlwaysInt32(DhcpOptionCode.RebindingTimeValue, (int)((long)lease * 7 / 8)); // long: lease * 7 overflowed above ~306M s
        }

        // Boot options for a boot client, before anything optional (they are what it came for).
        if (request.IsPxeRequest || request.IsHttpBoot || request.IsBootp)
        {
            if (!string.IsNullOrEmpty(bootFilename))
                w.Always(DhcpOptionCode.BootFileName, Ascii(bootFilename, scratch));

            if (!string.IsNullOrEmpty(tftpServer))
                w.Always(DhcpOptionCode.TFTPServerName, Ascii(tftpServer, scratch));

            if (request.IsHttpBoot)
            {
                // UEFI spec (HTTP Boot chapter): an HTTP boot client only accepts an offer that says "HTTPClient"
                // (60) and carries the boot URI. No option 43 — that is PXE boot-server discovery.
                // No URI configured = a plain address offer, no boot.
                if (!string.IsNullOrEmpty(bootFilename))
                    w.Always(DhcpOptionCode.VendorClassIdentifier, PxeBoot.HttpClientClass);
            }
            else if (request.IsPxeRequest)
            {
                // PXE 2.1: the offer must say "PXEClient" (60) and how to boot (43: use the file,
                // skip boot-server discovery). Options 93/94 are CLIENT options and were wrongly
                // sent back; 97 is the client's UUID — echoed, never invented.
                w.Always(DhcpOptionCode.VendorClassIdentifier, PxeBoot.PxeClientClass);
                w.Always(DhcpOptionCode.VendorSpecificInformation, PxeBoot.VendorOptions);
                if (request.ClientMachineId is { Length: > 0 } uuid)
                    w.Always(DhcpOptionCode.ClientMachineIdentifier, uuid);
            }
        }

        // ---- Requested options: only what the client asked for (55), while it fits (57) ----

        if (subnet?.Broadcast != null && w.Take(DhcpOptionCode.BroadcastAddress))
            w.Put(DhcpOptionCode.BroadcastAddress, Ip4(subnet.Broadcast, scratch));

        if (dnsServers is { Length: > 0 } && w.Take(DhcpOptionCode.DNS))
            w.Put(DhcpOptionCode.DNS, IpList(dnsServers, scratch));

        if (!string.IsNullOrEmpty(subnet?.DomainName) && w.Take(DhcpOptionCode.DomainName))
            w.Put(DhcpOptionCode.DomainName, Ascii(subnet.DomainName, scratch));

        // Hostname (12) — echo the client's own name back.
        if (!string.IsNullOrEmpty(request.Hostname) && w.Take(DhcpOptionCode.HostName))
            w.Put(DhcpOptionCode.HostName, Ascii(request.Hostname, scratch));

        // Domain Search List (Option 119) - RFC 1035 encoded
        if (!string.IsNullOrEmpty(subnet?.DomainSearchList))
        {
            var domainSearchBytes = EncodedOnce(DomainSearchEncoded, subnet.DomainSearchList, DhcpOptionExtensions.EncodeDomainSearchList);
            if (domainSearchBytes.Length > 0 && w.Take(DhcpOptionCode.DomainSearch))
                w.Put(DhcpOptionCode.DomainSearch, domainSearchBytes);
        }

        // Classless Static Routes (Option 121) - RFC 3442 encoded
        if (!string.IsNullOrEmpty(subnet?.StaticRoutesJson))
        {
            var routesBytes = EncodedOnce(StaticRoutesEncoded, subnet.StaticRoutesJson, DhcpOptionExtensions.EncodeClasslessStaticRoutes);
            if (routesBytes.Length > 0 && w.Take(DhcpOptionCode.ClasslessStaticRoute))
            {
                // RFC 3442: a client that understands 121 MUST ignore option 3 (Router). Without a
                // 0.0.0.0/0 entry here, configuring one static route took the default gateway away
                // from every Linux/macOS/Android/Windows client on the subnet.
                Span<byte> withDefault = stackalloc byte[routesBytes.Length + 5];
                w.Put(DhcpOptionCode.ClasslessStaticRoute, WithDefaultRoute(routesBytes, router, withDefault));
            }
        }

        // Time Offset (Option 2) - Seconds offset from UTC
        if (subnet?.TimeOffset is { } timeOffset && w.Take(DhcpOptionCode.TimeOffset))
            w.PutInt32(DhcpOptionCode.TimeOffset, timeOffset);

        // POSIX Timezone (Option 100)
        if (!string.IsNullOrEmpty(subnet?.PosixTimezone) && w.Take(DhcpOptionCode.POSIXTimeZone))
            w.Put(DhcpOptionCode.POSIXTimeZone, Ascii(subnet.PosixTimezone, scratch));

        if (subnet?.NtpServers is { Length: > 0 } ntpServers && w.Take(DhcpOptionCode.NTPServers))
            w.Put(DhcpOptionCode.NTPServers, IpList(ntpServers, scratch));

        // WINS/NetBIOS Servers, with node type hybrid (0x08) alongside.
        if (subnet?.WinsServers is { Length: > 0 } winsServers)
        {
            if (w.Take(DhcpOptionCode.NetBIOSOverTCPIPNameServer))
                w.Put(DhcpOptionCode.NetBIOSOverTCPIPNameServer, IpList(winsServers, scratch));
            if (w.Take(DhcpOptionCode.NetBIOSOverTCPIPNodeType))
                w.Put(DhcpOptionCode.NetBIOSOverTCPIPNodeType, [0x08]);
        }

        // Interface MTU
        if (subnet?.InterfaceMtu is { } mtu && w.Take(DhcpOptionCode.InterfaceMTU))
            w.Put(DhcpOptionCode.InterfaceMTU, [(byte)(mtu >> 8), (byte)(mtu & 0xFF)]);

        // The echoes written after the options are the server's too.
        if (request.ClientIdentifier is { Length: > 0 }) w.Governed[(byte)DhcpOptionCode.ClientIdentifier] = true;
        if (request.RelayAgentInformation is { Length: > 0 }) w.Governed[(byte)DhcpOptionCode.RelayAgentInformation] = true;

        // Operator-defined options last. Host > class > subnet/global.
        WriteCustomOptions(ref w, request, subnet, clientClass);
    }

    /// <summary>
    /// Custom options (dhcp_custom_options) for this client, most specific scope first. A code the
    /// server governs (router, DNS, lease times, PXE…, written or not) is skipped — those stay
    /// governed by the subnet's own fields — and so is any code a more specific scope already
    /// supplied. Custom options are NOT filtered by the parameter request list (there is no
    /// per-option "always send" flag, and devices rely on unrequested ones such as 43 for APs);
    /// when the client sent a list, the ones it asked for go first so a small reply keeps them.
    /// One that doesn't fit is skipped and logged.
    /// </summary>
    private void WriteCustomOptions(ref OptionWriter w, DhcpRequest request, DhcpSubnet? subnet, DhcpClass? clientClass)
    {
        if (subnet is null) return;
        subnet.HostOptions.TryGetValue(request.ClientMac, out var host);
        var cls = clientClass?.CustomOptions;
        if (host is null && (cls is null || cls.Count == 0) && subnet.CustomOptions.Count == 0) return;

        Span<bool> written = stackalloc bool[256];
        for (var pass = 0; pass < (w.HasPrl ? 2 : 1); pass++)
        {
            var requestedPass = pass == 0;
            WriteScope(ref w, host, requestedPass, written, request.ClientMac);
            WriteScope(ref w, cls, requestedPass, written, request.ClientMac);
            WriteScope(ref w, subnet.CustomOptions, requestedPass, written, request.ClientMac);
        }
    }

    private void WriteScope(ref OptionWriter w, IReadOnlyList<DhcpCustomOption>? scope, bool requestedPass, scoped Span<bool> written, string mac)
    {
        if (scope is null) return;
        foreach (var o in scope)
        {
            if (o.OptionCode is < 1 or > 254 || w.Governed[o.OptionCode] || written[o.OptionCode]
                || o.OptionValue.Length is 0 or > 255) continue;
            // With a request list: pass 1 = asked for, pass 2 = the rest. Without one: one pass.
            if (w.HasPrl && w.Requested(o.OptionCode) != requestedPass) continue;
            written[o.OptionCode] = true;   // a more specific scope that didn't fit still wins its code
            if (!w.Fits(o.OptionValue.Length))
            {
                w.Dropped++;   // reported once, throttled, by ConstructDhcpPacket
                continue;
            }
            w.Put((DhcpOptionCode)o.OptionCode, o.OptionValue);
        }
    }

    private static ReadOnlySpan<byte> Ip4(IPAddress ip, Span<byte> scratch) =>
        ip.TryWriteBytes(scratch, out var n) && n == 4 ? scratch[..4] : ip.GetAddressBytes();

    /// <summary>Up to 63 IPv4 addresses (one option's worth), packed.</summary>
    private static ReadOnlySpan<byte> IpList(IPAddress[] ips, Span<byte> scratch)
    {
        var n = 0;
        foreach (var ip in ips)
        {
            if (n + 4 > scratch.Length) break;
            if (ip.TryWriteBytes(scratch[n..], out var w) && w == 4) n += 4;
        }
        return scratch[..n];
    }

    /// <summary>ASCII into <paramref name="scratch"/>; a string over 255 comes back whole so WriteOption raises its error.</summary>
    private static ReadOnlySpan<byte> Ascii(string text, Span<byte> scratch) =>
        text.Length <= scratch.Length ? scratch[..Encoding.ASCII.GetBytes(text, scratch)] : Encoding.ASCII.GetBytes(text);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int WriteIp(byte[] buffer, int offset, IPAddress ip)
    {
        if (!ip.TryWriteBytes(buffer.AsSpan(offset, 4), out var n) || n != 4)
            buffer.AsSpan(offset, 4).Clear();
        return offset + 4;
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
