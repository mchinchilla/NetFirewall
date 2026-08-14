using System.Buffers;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Dhcp;
using Npgsql;

namespace NetFirewall.Services.Dhcp;

/// <summary>
/// RFC 2136 Dynamic DNS Update service implementation.
/// Supports TSIG authentication (RFC 2845) for secure updates.
/// </summary>
public sealed class DdnsService : IDdnsService
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly ILogger<DdnsService> _logger;
    private readonly ArrayPool<byte> _bufferPool = ArrayPool<byte>.Shared;

    // Cache for DDNS configs. One immutable snapshot swapped atomically:
    // the previous clear-then-repopulate pattern had a window where a
    // concurrent reader saw an empty cache and silently skipped DDNS for a
    // lease; it also re-queried the DB on EVERY call for subnets that only
    // have the global config (the common case) because a per-subnet miss
    // wasn't distinguishable from a cold cache.
    private sealed record ConfigSnapshot(Dictionary<Guid, DdnsConfig> BySubnet, DdnsConfig? Global, DateTime Expiry);
    private static ConfigSnapshot _configs = new(new Dictionary<Guid, DdnsConfig>(), null, DateTime.MinValue);
    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(5);

    /// <summary>Test hook: drops the process-wide config snapshot so each test
    /// starts cold. The cache is intentionally static (shared across scoped
    /// service instances), which leaks between tests otherwise.</summary>
    internal static void ResetConfigCacheForTests() =>
        _configs = new ConfigSnapshot(new Dictionary<Guid, DdnsConfig>(), null, DateTime.MinValue);

    // DNS constants
    private const ushort DnsTypeA = 1;
    private const ushort DnsTypePtr = 12;
    private const ushort DnsTypeSoa = 6;
    private const ushort DnsTypeAny = 255;
    private const ushort DnsClassIn = 1;
    private const ushort DnsClassAny = 255;
    private const ushort DnsClassNone = 254;

    // DNS UPDATE opcodes
    private const byte OpcodeUpdate = 5;

    // DNS response codes
    private const int RcodeNoError = 0;
    private const int RcodeFormErr = 1;
    private const int RcodeServFail = 2;
    private const int RcodeNxDomain = 3;
    private const int RcodeNotImpl = 4;
    private const int RcodeRefused = 5;
    private const int RcodeYxDomain = 6;
    private const int RcodeYxRrset = 7;
    private const int RcodeNxRrset = 8;
    private const int RcodeNotAuth = 9;
    private const int RcodeNotZone = 10;

    public DdnsService(NpgsqlDataSource dataSource, ILogger<DdnsService> logger)
    {
        _dataSource = dataSource;
        _logger = logger;
    }

    public async Task<DdnsUpdateResult> UpdateLeaseRecordsAsync(
        string hostname,
        IPAddress ipAddress,
        string macAddress,
        DdnsConfig config,
        CancellationToken cancellationToken = default)
    {
        if (!config.Enabled || string.IsNullOrEmpty(hostname))
        {
            return DdnsUpdateResult.Disabled();
        }

        var fqdn = BuildFqdn(hostname, config.ForwardZone);
        var result = new DdnsUpdateResult { Fqdn = fqdn };

        // Forward record (A)
        if (config.EnableForward && !string.IsNullOrEmpty(config.ForwardZone))
        {
            try
            {
                result.ForwardSuccess = await AddForwardRecordAsync(
                    hostname, ipAddress, config, macAddress, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                result.ForwardError = ex.Message;
                _logger.LogWarning(ex, "Failed to add forward record for {Hostname}", hostname);
            }
        }
        else
        {
            result.ForwardSuccess = true;
        }

        // Reverse record (PTR)
        if (config.EnableReverse)
        {
            try
            {
                result.ReverseSuccess = await AddReverseRecordAsync(
                    ipAddress, fqdn, config, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                result.ReverseError = ex.Message;
                _logger.LogWarning(ex, "Failed to add reverse record for {Ip}", ipAddress);
            }
        }
        else
        {
            result.ReverseSuccess = true;
        }

        if (result.Success)
        {
            _logger.LogInformation("DDNS update succeeded for {Fqdn} -> {Ip}", fqdn, ipAddress);
        }

        return result;
    }

    public async Task<DdnsUpdateResult> RemoveLeaseRecordsAsync(
        string hostname,
        IPAddress ipAddress,
        DdnsConfig config,
        CancellationToken cancellationToken = default)
    {
        if (!config.Enabled || string.IsNullOrEmpty(hostname))
        {
            return DdnsUpdateResult.Disabled();
        }

        var fqdn = BuildFqdn(hostname, config.ForwardZone);
        var result = new DdnsUpdateResult { Fqdn = fqdn };

        if (config.EnableForward && !string.IsNullOrEmpty(config.ForwardZone))
        {
            try
            {
                result.ForwardSuccess = await RemoveForwardRecordAsync(
                    hostname, ipAddress, config, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                result.ForwardError = ex.Message;
            }
        }
        else
        {
            result.ForwardSuccess = true;
        }

        if (config.EnableReverse)
        {
            try
            {
                result.ReverseSuccess = await RemoveReverseRecordAsync(
                    ipAddress, config, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                result.ReverseError = ex.Message;
            }
        }
        else
        {
            result.ReverseSuccess = true;
        }

        if (result.Success)
        {
            _logger.LogInformation("DDNS removal succeeded for {Fqdn}", fqdn);
        }

        return result;
    }

    public async Task<bool> AddForwardRecordAsync(
        string hostname,
        IPAddress ipAddress,
        DdnsConfig config,
        string macAddress,
        CancellationToken cancellationToken = default)
    {
        if (config.DnsServer == null || string.IsNullOrEmpty(config.ForwardZone))
        {
            return false;
        }

        var fqdn = BuildFqdn(hostname, config.ForwardZone);

        // Build UPDATE packet for A record
        var packet = BuildUpdatePacket(
            zone: config.ForwardZone,
            name: fqdn,
            type: DnsTypeA,
            ttl: config.Ttl,
            rdata: ipAddress.GetAddressBytes(),
            isDelete: false,
            config: config);

        return await SendUpdateAsync(config.DnsServer, config.DnsPort, packet, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<bool> AddReverseRecordAsync(
        IPAddress ipAddress,
        string fqdn,
        DdnsConfig config,
        CancellationToken cancellationToken = default)
    {
        if (config.DnsServer == null)
        {
            return false;
        }

        var reverseZone = config.ReverseZone ?? GenerateReverseZone(ipAddress);
        var ptrName = GeneratePtrName(ipAddress);

        // Build UPDATE packet for PTR record
        var packet = BuildUpdatePacket(
            zone: reverseZone,
            name: ptrName,
            type: DnsTypePtr,
            ttl: config.Ttl,
            rdata: EncodeDomainName(fqdn),
            isDelete: false,
            config: config);

        return await SendUpdateAsync(config.DnsServer, config.DnsPort, packet, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<bool> RemoveForwardRecordAsync(
        string hostname,
        IPAddress ipAddress,
        DdnsConfig config,
        CancellationToken cancellationToken = default)
    {
        if (config.DnsServer == null || string.IsNullOrEmpty(config.ForwardZone))
        {
            return false;
        }

        var fqdn = BuildFqdn(hostname, config.ForwardZone);

        // Build DELETE packet for A record
        var packet = BuildUpdatePacket(
            zone: config.ForwardZone,
            name: fqdn,
            type: DnsTypeA,
            ttl: 0,
            rdata: ipAddress.GetAddressBytes(),
            isDelete: true,
            config: config);

        return await SendUpdateAsync(config.DnsServer, config.DnsPort, packet, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<bool> RemoveReverseRecordAsync(
        IPAddress ipAddress,
        DdnsConfig config,
        CancellationToken cancellationToken = default)
    {
        if (config.DnsServer == null)
        {
            return false;
        }

        var reverseZone = config.ReverseZone ?? GenerateReverseZone(ipAddress);
        var ptrName = GeneratePtrName(ipAddress);

        // Build DELETE packet for PTR record (delete any PTR for this name)
        var packet = BuildUpdatePacket(
            zone: reverseZone,
            name: ptrName,
            type: DnsTypePtr,
            ttl: 0,
            rdata: [],
            isDelete: true,
            config: config);

        return await SendUpdateAsync(config.DnsServer, config.DnsPort, packet, cancellationToken)
            .ConfigureAwait(false);
    }

    public async Task<DdnsConfig?> GetConfigForSubnetAsync(
        Guid? subnetId,
        CancellationToken cancellationToken = default)
    {
        // Check cache — a fresh snapshot answers definitively, including
        // "this subnet has no override, use the global config" and "there is
        // no config at all" (null), without touching the DB.
        var snapshot = _configs;
        if (DateTime.UtcNow < snapshot.Expiry)
        {
            return Resolve(snapshot, subnetId);
        }

        // Refresh cache
        await RefreshCacheAsync(cancellationToken).ConfigureAwait(false);
        return Resolve(_configs, subnetId);

        static DdnsConfig? Resolve(ConfigSnapshot snap, Guid? id) =>
            id.HasValue && snap.BySubnet.TryGetValue(id.Value, out var cfg) ? cfg : snap.Global;
    }

    private async Task RefreshCacheAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken)
                .ConfigureAwait(false);

            await using var cmd = new NpgsqlCommand(
                "SELECT id, subnet_id, enable_forward, enable_reverse, forward_zone, reverse_zone, " +
                "dns_server, dns_port, tsig_key_name, tsig_key_secret, tsig_algorithm, ttl, " +
                "update_style, override_client_update, allow_client_updates, conflict_resolution, enabled " +
                "FROM dhcp_ddns_config WHERE enabled = true", connection);

            await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

            // Build into locals and swap the snapshot once at the end —
            // readers never observe a half-built cache, and a failed refresh
            // leaves the previous (stale but usable) snapshot in place.
            var bySubnet = new Dictionary<Guid, DdnsConfig>();
            DdnsConfig? global = null;

            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var config = new DdnsConfig
                {
                    Id = reader.GetGuid(0),
                    SubnetId = reader.IsDBNull(1) ? null : reader.GetGuid(1),
                    EnableForward = reader.GetBoolean(2),
                    EnableReverse = reader.GetBoolean(3),
                    ForwardZone = reader.IsDBNull(4) ? null : reader.GetString(4),
                    ReverseZone = reader.IsDBNull(5) ? null : reader.GetString(5),
                    DnsServer = reader.IsDBNull(6) ? null : (IPAddress)reader.GetValue(6),
                    DnsPort = reader.GetInt32(7),
                    TsigKeyName = reader.IsDBNull(8) ? null : reader.GetString(8),
                    TsigKeySecret = reader.IsDBNull(9) ? null : reader.GetString(9),
                    TsigAlgorithm = reader.GetString(10),
                    Ttl = reader.GetInt32(11),
                    UpdateStyle = reader.GetString(12),
                    OverrideClientUpdate = reader.GetBoolean(13),
                    AllowClientUpdates = reader.GetBoolean(14),
                    ConflictResolution = reader.GetString(15),
                    Enabled = reader.GetBoolean(16)
                };

                if (config.SubnetId.HasValue)
                {
                    bySubnet[config.SubnetId.Value] = config;
                }
                else
                {
                    global = config;
                }
            }

            _configs = new ConfigSnapshot(bySubnet, global, DateTime.UtcNow.Add(CacheDuration));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to refresh DDNS config cache");
        }
    }

    private byte[] BuildUpdatePacket(
        string zone,
        string name,
        ushort type,
        int ttl,
        byte[] rdata,
        bool isDelete,
        DdnsConfig config)
    {
        // Worst case (long zone + long name + TSIG key/algorithm names + MAC)
        // far exceeds the old 512-byte rental, which threw IndexOutOfRange on
        // legitimate configs. 2048 covers every combination of 255-byte names.
        var buffer = _bufferPool.Rent(2048);
        try
        {
            int offset = 0;

            // Transaction ID (random)
            var txId = (ushort)Random.Shared.Next(0, 65536);
            buffer[offset++] = (byte)(txId >> 8);
            buffer[offset++] = (byte)(txId & 0xFF);

            // Flags: QR=0, Opcode=UPDATE(5), Z=0
            buffer[offset++] = (byte)(OpcodeUpdate << 3);
            buffer[offset++] = 0;

            // ZOCOUNT = 1
            buffer[offset++] = 0;
            buffer[offset++] = 1;

            // PRCOUNT = 0 (prerequisites)
            buffer[offset++] = 0;
            buffer[offset++] = 0;

            // UPCOUNT = 1 (updates)
            buffer[offset++] = 0;
            buffer[offset++] = 1;

            // ADCOUNT starts at 0 — RFC 2845 §3.4.1 computes the TSIG digest
            // over the message as it exists WITHOUT the TSIG RR (including
            // this count). AddTsigRecord bumps it after signing.
            var hasTsig = !string.IsNullOrEmpty(config.TsigKeyName) &&
                          !string.IsNullOrEmpty(config.TsigKeySecret);
            buffer[offset++] = 0;
            buffer[offset++] = 0;

            // Zone section
            offset = WriteDomainName(buffer, offset, zone);
            buffer[offset++] = 0; // TYPE = SOA
            buffer[offset++] = (byte)DnsTypeSoa;
            buffer[offset++] = 0; // CLASS = IN
            buffer[offset++] = (byte)DnsClassIn;

            // Update section
            offset = WriteDomainName(buffer, offset, name);

            // TYPE
            buffer[offset++] = (byte)(type >> 8);
            buffer[offset++] = (byte)(type & 0xFF);

            if (isDelete)
            {
                // For delete: CLASS=NONE or ANY, TTL=0
                if (rdata.Length == 0)
                {
                    // Delete all RRs of this type
                    buffer[offset++] = (byte)(DnsClassAny >> 8);
                    buffer[offset++] = (byte)(DnsClassAny & 0xFF);
                }
                else
                {
                    // Delete specific RR
                    buffer[offset++] = (byte)(DnsClassNone >> 8);
                    buffer[offset++] = (byte)(DnsClassNone & 0xFF);
                }
            }
            else
            {
                // For add: CLASS=IN
                buffer[offset++] = (byte)(DnsClassIn >> 8);
                buffer[offset++] = (byte)(DnsClassIn & 0xFF);
            }

            // TTL (4 bytes)
            buffer[offset++] = (byte)(ttl >> 24);
            buffer[offset++] = (byte)(ttl >> 16);
            buffer[offset++] = (byte)(ttl >> 8);
            buffer[offset++] = (byte)(ttl & 0xFF);

            // RDLENGTH and RDATA
            buffer[offset++] = (byte)(rdata.Length >> 8);
            buffer[offset++] = (byte)(rdata.Length & 0xFF);
            rdata.CopyTo(buffer, offset);
            offset += rdata.Length;

            // Add TSIG if configured
            if (hasTsig)
            {
                offset = AddTsigRecord(buffer, offset, config, txId);
            }

            // Copy to result
            var result = new byte[offset];
            Buffer.BlockCopy(buffer, 0, result, 0, offset);
            return result;
        }
        finally
        {
            _bufferPool.Return(buffer);
        }
    }

    private const ushort TsigFudgeSeconds = 300;

    /// <summary>
    /// Computes the RFC 2845 §3.4 request MAC: HMAC over the DNS message as it
    /// exists WITHOUT the TSIG RR, followed by the TSIG "variables" in
    /// canonical wire form (key name, class ANY, TTL 0, algorithm name,
    /// 48-bit time, fudge, error, other-len). The previous implementation
    /// hashed the half-built buffer — including two unwritten placeholder
    /// bytes of ArrayPool garbage — so every TSIG-signed update failed
    /// BADSIG, nondeterministically.
    /// </summary>
    internal static byte[] ComputeTsigMac(
        ReadOnlySpan<byte> messageWithoutTsig,
        string keyName,
        string algorithm,
        byte[] keySecret,
        long timeSigned,
        ushort fudge)
    {
        var keyNameWire = EncodeDomainName(keyName);
        var algorithmWire = EncodeDomainName(algorithm);

        var digest = new byte[messageWithoutTsig.Length + keyNameWire.Length + 2 + 4 +
                              algorithmWire.Length + 6 + 2 + 2 + 2];
        int o = 0;
        messageWithoutTsig.CopyTo(digest);
        o += messageWithoutTsig.Length;
        keyNameWire.CopyTo(digest, o);
        o += keyNameWire.Length;
        digest[o++] = (byte)(DnsClassAny >> 8);           // CLASS = ANY
        digest[o++] = (byte)(DnsClassAny & 0xFF);
        o += 4;                                            // TTL = 0 (already zeroed)
        algorithmWire.CopyTo(digest, o);
        o += algorithmWire.Length;
        digest[o++] = (byte)(timeSigned >> 40);            // Time signed (48-bit)
        digest[o++] = (byte)(timeSigned >> 32);
        digest[o++] = (byte)(timeSigned >> 24);
        digest[o++] = (byte)(timeSigned >> 16);
        digest[o++] = (byte)(timeSigned >> 8);
        digest[o++] = (byte)timeSigned;
        digest[o++] = (byte)(fudge >> 8);                  // Fudge
        digest[o++] = (byte)fudge;
        digest[o++] = 0; digest[o++] = 0;                  // Error = 0
        digest[o++] = 0; digest[o++] = 0;                  // Other len = 0

        using var hmac = CreateHmac(algorithm, keySecret);
        return hmac.ComputeHash(digest);
    }

    private int AddTsigRecord(byte[] buffer, int offset, DdnsConfig config, ushort txId)
    {
        // TSIG record (RFC 2845)
        var keyName = config.TsigKeyName!;
        var keySecret = Convert.FromBase64String(config.TsigKeySecret!);
        var algorithm = config.TsigAlgorithm;
        var timeSigned = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // Sign FIRST — over the message as built so far (ADCOUNT still 0) plus
        // the TSIG variables — then append the TSIG RR and bump ARCOUNT.
        var mac = ComputeTsigMac(buffer.AsSpan(0, offset), keyName, algorithm, keySecret,
            timeSigned, TsigFudgeSeconds);

        // The final message DOES count the TSIG RR in ADCOUNT (header bytes 10-11).
        buffer[11] = 1;

        // Name
        offset = WriteDomainName(buffer, offset, keyName);

        // Type = TSIG (250)
        buffer[offset++] = 0;
        buffer[offset++] = 250;

        // Class = ANY
        buffer[offset++] = (byte)(DnsClassAny >> 8);
        buffer[offset++] = (byte)(DnsClassAny & 0xFF);

        // TTL = 0
        buffer[offset++] = 0;
        buffer[offset++] = 0;
        buffer[offset++] = 0;
        buffer[offset++] = 0;

        // RDATA (compute later for length)
        var rdataStart = offset;
        offset += 2; // Reserve for RDLENGTH

        // Algorithm name
        offset = WriteDomainName(buffer, offset, algorithm);

        // Time signed (6 bytes - seconds since epoch)
        buffer[offset++] = (byte)(timeSigned >> 40);
        buffer[offset++] = (byte)(timeSigned >> 32);
        buffer[offset++] = (byte)(timeSigned >> 24);
        buffer[offset++] = (byte)(timeSigned >> 16);
        buffer[offset++] = (byte)(timeSigned >> 8);
        buffer[offset++] = (byte)(timeSigned & 0xFF);

        // Fudge (2 bytes)
        buffer[offset++] = (byte)(TsigFudgeSeconds >> 8);
        buffer[offset++] = (byte)(TsigFudgeSeconds & 0xFF);

        // MAC size + MAC
        buffer[offset++] = (byte)(mac.Length >> 8);
        buffer[offset++] = (byte)(mac.Length & 0xFF);
        mac.CopyTo(buffer, offset);
        offset += mac.Length;

        // Original ID
        buffer[offset++] = (byte)(txId >> 8);
        buffer[offset++] = (byte)(txId & 0xFF);

        // Error = 0
        buffer[offset++] = 0;
        buffer[offset++] = 0;

        // Other len = 0
        buffer[offset++] = 0;
        buffer[offset++] = 0;

        // Update RDLENGTH
        var rdataLen = offset - rdataStart - 2;
        buffer[rdataStart] = (byte)(rdataLen >> 8);
        buffer[rdataStart + 1] = (byte)(rdataLen & 0xFF);

        return offset;
    }

    private static HMAC CreateHmac(string algorithm, byte[] key)
    {
        return algorithm.ToLowerInvariant() switch
        {
            "hmac-md5.sig-alg.reg.int" or "hmac-md5" => new HMACMD5(key),
            "hmac-sha1" => new HMACSHA1(key),
            "hmac-sha256" => new HMACSHA256(key),
            "hmac-sha512" => new HMACSHA512(key),
            _ => new HMACSHA256(key)
        };
    }

    private async Task<bool> SendUpdateAsync(
        IPAddress server,
        int port,
        byte[] packet,
        CancellationToken cancellationToken)
    {
        try
        {
            using var udp = new UdpClient();

            // Connect() filters inbound datagrams to the DNS server's address —
            // an unconnected socket completes ReceiveAsync on ANY stray packet.
            var endpoint = new IPEndPoint(server, port);
            udp.Connect(endpoint);

            // Socket.ReceiveTimeout only applies to synchronous receives;
            // ReceiveAsync ignores it, so a dead/filtered DNS server (UDP, no
            // ICMP) used to hang the awaiting lease-commit path forever and
            // back up the DHCP packet channel. Linked CTS enforces the 5s.
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(5));

            await udp.SendAsync(packet, timeoutCts.Token).ConfigureAwait(false);

            var response = await udp.ReceiveAsync(timeoutCts.Token).ConfigureAwait(false);

            // Parse response
            if (response.Buffer.Length < 12)
            {
                _logger.LogWarning("Invalid DNS response: too short");
                return false;
            }

            // The response must answer OUR transaction — ignore mismatches.
            if (response.Buffer[0] != packet[0] || response.Buffer[1] != packet[1])
            {
                _logger.LogWarning("DNS UPDATE response transaction ID mismatch — discarding");
                return false;
            }

            // Check RCODE (last 4 bits of byte 3)
            var rcode = response.Buffer[3] & 0x0F;

            if (rcode == RcodeNoError)
            {
                return true;
            }

            var errorMessage = rcode switch
            {
                RcodeFormErr => "Format error",
                RcodeServFail => "Server failure",
                RcodeNxDomain => "Name does not exist",
                RcodeNotImpl => "Not implemented",
                RcodeRefused => "Refused (check TSIG key)",
                RcodeYxDomain => "Name exists when it should not",
                RcodeYxRrset => "RRset exists when it should not",
                RcodeNxRrset => "RRset does not exist",
                RcodeNotAuth => "Not authoritative",
                RcodeNotZone => "Name not in zone",
                _ => $"Unknown error ({rcode})"
            };

            _logger.LogWarning("DNS UPDATE failed: {Error}", errorMessage);
            return false;
        }
        catch (SocketException ex)
        {
            _logger.LogWarning(ex, "DNS UPDATE socket error to {Server}", server);
            return false;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    private static int WriteDomainName(byte[] buffer, int offset, string name)
    {
        var labels = name.TrimEnd('.').Split('.');
        foreach (var label in labels)
        {
            if (label.Length > 63)
                throw new ArgumentException($"Label too long: {label}");

            buffer[offset++] = (byte)label.Length;
            var bytes = Encoding.ASCII.GetBytes(label.ToLowerInvariant());
            bytes.CopyTo(buffer, offset);
            offset += bytes.Length;
        }
        buffer[offset++] = 0; // Root label
        return offset;
    }

    private static byte[] EncodeDomainName(string name)
    {
        using var ms = new MemoryStream();
        var labels = name.TrimEnd('.').Split('.');
        foreach (var label in labels)
        {
            ms.WriteByte((byte)label.Length);
            var bytes = Encoding.ASCII.GetBytes(label.ToLowerInvariant());
            ms.Write(bytes, 0, bytes.Length);
        }
        ms.WriteByte(0);
        return ms.ToArray();
    }

    internal static string BuildFqdn(string hostname, string? zone)
    {
        if (string.IsNullOrEmpty(zone))
            return hostname;

        hostname = hostname.TrimEnd('.');
        zone = zone.TrimEnd('.');

        // Label-boundary check: "myexample.com" does NOT belong to zone
        // "example.com" even though it string-EndsWith it — qualifying it as
        // already-in-zone sent updates for names outside the zone (NOTZONE).
        if (hostname.Equals(zone, StringComparison.OrdinalIgnoreCase) ||
            hostname.EndsWith("." + zone, StringComparison.OrdinalIgnoreCase))
            return hostname + ".";

        return $"{hostname}.{zone}.";
    }

    private static string GenerateReverseZone(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        // For /24 networks, use first 3 octets
        return $"{bytes[2]}.{bytes[1]}.{bytes[0]}.in-addr.arpa";
    }

    private static string GeneratePtrName(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        return $"{bytes[3]}.{bytes[2]}.{bytes[1]}.{bytes[0]}.in-addr.arpa";
    }
}
