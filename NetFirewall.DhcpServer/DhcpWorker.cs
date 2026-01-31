using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Channels;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;

namespace NetFirewall.DhcpServer;

/// <summary>
/// High-performance DHCP worker using channels and ArrayPool for zero-allocation packet processing.
/// </summary>
public sealed class DhcpWorker : BackgroundService
{
    private const int MaxDhcpPacketSize = 576; // RFC 2131 minimum
    private const int MinDhcpPacketSize = 236; // Minimum valid DHCP packet
    private const int MagicCookieOffset = 236;
    private const int OptionsOffset = 240;

    private readonly ILogger<DhcpWorker> _logger;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly UdpClient _udpClient;
    private readonly Channel<DhcpPacketContext> _packetChannel;
    private readonly ArrayPool<byte> _bufferPool;

    // Pre-allocated for MAC address formatting
    private static readonly char[] HexChars = "0123456789ABCDEF".ToCharArray();

    public DhcpWorker(ILogger<DhcpWorker> logger, IServiceScopeFactory scopeFactory)
    {
        _logger = logger;
        _scopeFactory = scopeFactory;
        _bufferPool = ArrayPool<byte>.Shared;

        _udpClient = new UdpClient(67)
        {
            EnableBroadcast = true
        };

        // Bounded channel prevents memory growth under load
        _packetChannel = Channel.CreateBounded<DhcpPacketContext>(new BoundedChannelOptions(100)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = true
        });
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("DHCP Server starting on port 67");

        // Run receive and process concurrently
        await Task.WhenAll(
            ReceivePacketsAsync(stoppingToken),
            ProcessPacketsAsync(stoppingToken)
        ).ConfigureAwait(false);
    }

    private async Task ReceivePacketsAsync(CancellationToken stoppingToken)
    {
        var writer = _packetChannel.Writer;

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var result = await _udpClient.ReceiveAsync(stoppingToken).ConfigureAwait(false);

                    if (result.Buffer.Length < MinDhcpPacketSize)
                    {
                        _logger.LogDebug("Packet too short: {Length} bytes", result.Buffer.Length);
                        continue;
                    }

                    // Rent buffer from pool and copy data
                    var rentedBuffer = _bufferPool.Rent(result.Buffer.Length);
                    result.Buffer.AsSpan().CopyTo(rentedBuffer);

                    var context = new DhcpPacketContext(
                        rentedBuffer,
                        result.Buffer.Length,
                        result.RemoteEndPoint,
                        _bufferPool
                    );

                    // Try to write to channel, drop if full
                    if (!writer.TryWrite(context))
                    {
                        _logger.LogWarning("Packet channel full, dropping packet");
                        context.Dispose();
                    }
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
                {
                    // ICMP port unreachable - ignore
                    await Task.Delay(100, stoppingToken).ConfigureAwait(false);
                }
                catch (SocketException ex)
                {
                    _logger.LogError(ex, "Socket error: {ErrorCode}", ex.SocketErrorCode);
                }
            }
        }
        finally
        {
            writer.Complete();
            _logger.LogInformation("DHCP packet receiver stopped");
        }
    }

    private async Task ProcessPacketsAsync(CancellationToken stoppingToken)
    {
        var reader = _packetChannel.Reader;

        await foreach (var context in reader.ReadAllAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                await ProcessSinglePacketAsync(context, stoppingToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing DHCP packet");
            }
            finally
            {
                context.Dispose();
            }
        }

        _logger.LogInformation("DHCP packet processor stopped");
    }

    private async Task ProcessSinglePacketAsync(DhcpPacketContext context, CancellationToken stoppingToken)
    {
        var buffer = context.Buffer.AsSpan(0, context.Length);

        // Parse request using Span to avoid allocations
        if (!TryParseDhcpRequest(buffer, context.RemoteEndPoint, out var request))
        {
            return;
        }

        // Create scoped service for database operations
        await using var scope = _scopeFactory.CreateAsyncScope();
        var dhcpService = scope.ServiceProvider.GetRequiredService<IDhcpServerService>();

        var response = await dhcpService.CreateDhcpResponseAsync(request).ConfigureAwait(false);

        if (response.Length > 0)
        {
            var destination = DetermineDestinationEndPoint(request, context.RemoteEndPoint);
            await _udpClient.SendAsync(response, destination, stoppingToken).ConfigureAwait(false);

            if (_logger.IsEnabled(LogLevel.Debug))
            {
                _logger.LogDebug("Sent {MessageType} to {Destination}", request.MessageType, destination);
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static IPEndPoint DetermineDestinationEndPoint(DhcpRequest request, IPEndPoint originalEndPoint)
    {
        // RFC 2131: Broadcast if flag set or client has no IP
        bool broadcastFlagSet = (request.Flags & 0x8000) != 0;

        if (broadcastFlagSet || request.CiAddr == null || request.CiAddr.Equals(IPAddress.Any))
        {
            return new IPEndPoint(IPAddress.Broadcast, 68);
        }

        return new IPEndPoint(request.CiAddr, 68);
    }

    private bool TryParseDhcpRequest(ReadOnlySpan<byte> buffer, IPEndPoint remoteEndPoint, out DhcpRequest request)
    {
        request = default!;

        if (buffer.Length < MinDhcpPacketSize)
        {
            return false;
        }

        // Validate magic cookie
        if (buffer[236] != 99 || buffer[237] != 130 || buffer[238] != 83 || buffer[239] != 99)
        {
            _logger.LogDebug("Invalid DHCP magic cookie");
            return false;
        }

        request = new DhcpRequest
        {
            Op = buffer[0],
            HType = buffer[1],
            HLen = buffer[2],
            Hops = buffer[3],
            Xid = buffer.Slice(4, 4).ToArray(),
            Secs = (ushort)((buffer[8] << 8) | buffer[9]),
            Flags = (ushort)((buffer[10] << 8) | buffer[11]),
            CiAddr = new IPAddress(buffer.Slice(12, 4)),
            YiAddr = new IPAddress(buffer.Slice(16, 4)),
            SiAddr = new IPAddress(buffer.Slice(20, 4)),
            GiAddr = new IPAddress(buffer.Slice(24, 4)),
            ChAddr = buffer.Slice(28, 16).ToArray(),
            RemoteEndPoint = remoteEndPoint
        };

        // Format MAC address without allocations using stackalloc
        request.ClientMac = FormatMacAddress(buffer.Slice(28, 6));

        // Parse server name and boot file only if non-empty (avoid string allocations)
        var snameSpan = buffer.Slice(44, 64);
        if (snameSpan[0] != 0)
        {
            request.SName = ReadNullTerminatedString(snameSpan);
        }

        var fileSpan = buffer.Slice(108, 128);
        if (fileSpan[0] != 0)
        {
            request.File = ReadNullTerminatedString(fileSpan);
        }

        // Parse options
        ParseDhcpOptions(buffer.Slice(OptionsOffset), request);

        request.IsBootp = request.Op == 1;
        request.IsPxeRequest = request.VendorClassIdentifier?.Contains("PXEClient") == true;

        if (_logger.IsEnabled(LogLevel.Debug))
        {
            _logger.LogDebug("Parsed {MessageType} from {Mac}", request.MessageType, request.ClientMac);
        }

        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string FormatMacAddress(ReadOnlySpan<byte> bytes)
    {
        // Pre-sized string builder equivalent using stackalloc
        Span<char> chars = stackalloc char[17]; // XX:XX:XX:XX:XX:XX

        for (int i = 0; i < 6; i++)
        {
            int offset = i * 3;
            chars[offset] = HexChars[(bytes[i] >> 4) & 0xF];
            chars[offset + 1] = HexChars[bytes[i] & 0xF];
            if (i < 5) chars[offset + 2] = ':';
        }

        return new string(chars);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static string ReadNullTerminatedString(ReadOnlySpan<byte> span)
    {
        int nullIndex = span.IndexOf((byte)0);
        if (nullIndex == 0) return string.Empty;
        if (nullIndex < 0) nullIndex = span.Length;

        return Encoding.ASCII.GetString(span.Slice(0, nullIndex));
    }

    private void ParseDhcpOptions(ReadOnlySpan<byte> optionsSpan, DhcpRequest request)
    {
        int i = 0;

        while (i < optionsSpan.Length)
        {
            byte optionCode = optionsSpan[i++];

            if (optionCode == (byte)DhcpOptionCode.End)
                break;

            if (optionCode == (byte)DhcpOptionCode.Pad)
                continue;

            if (i >= optionsSpan.Length)
                break;

            int optionLength = optionsSpan[i++];

            if (i + optionLength > optionsSpan.Length)
                break;

            var optionData = optionsSpan.Slice(i, optionLength);
            i += optionLength;

            ParseSingleOption((DhcpOptionCode)optionCode, optionData, request);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private void ParseSingleOption(DhcpOptionCode code, ReadOnlySpan<byte> data, DhcpRequest request)
    {
        switch (code)
        {
            case DhcpOptionCode.MessageType when data.Length > 0:
                request.MessageType = (DhcpMessageType)data[0];
                break;

            case DhcpOptionCode.RequestedIPAddress when data.Length >= 4:
                request.RequestedIp = new IPAddress(data.Slice(0, 4));
                break;

            case DhcpOptionCode.ClientIdentifier:
                request.ClientIdentifier = data.ToArray();
                break;

            case DhcpOptionCode.HostName when data.Length > 0:
                request.Hostname = Encoding.ASCII.GetString(data);
                break;

            case DhcpOptionCode.ParameterRequestList:
                request.ParameterRequestList = data.ToArray();
                break;

            case DhcpOptionCode.VendorClassIdentifier when data.Length > 0:
                request.VendorClassIdentifier = Encoding.ASCII.GetString(data);
                break;

            case DhcpOptionCode.IPAddressLeaseTime when data.Length >= 4:
                request.LeaseTime = IPAddress.NetworkToHostOrder(BitConverter.ToInt32(data));
                break;
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("DHCP Server stopping");
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    public override void Dispose()
    {
        _udpClient.Dispose();
        base.Dispose();
    }
}

/// <summary>
/// Pooled packet context to avoid allocations.
/// </summary>
internal readonly struct DhcpPacketContext : IDisposable
{
    public byte[] Buffer { get; }
    public int Length { get; }
    public IPEndPoint RemoteEndPoint { get; }
    private readonly ArrayPool<byte> _pool;

    public DhcpPacketContext(byte[] buffer, int length, IPEndPoint remoteEndPoint, ArrayPool<byte> pool)
    {
        Buffer = buffer;
        Length = length;
        RemoteEndPoint = remoteEndPoint;
        _pool = pool;
    }

    public void Dispose()
    {
        _pool.Return(Buffer);
    }
}
