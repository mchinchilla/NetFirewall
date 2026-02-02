using System.Buffers;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Channels;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using Spectre.Console;

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

    // Linux socket options
    private const int SOL_SOCKET = 1;
    private const int SO_BINDTODEVICE = 25;
    private const int SO_ATTACH_FILTER = 26;

    // IP protocol level options
    private const int IPPROTO_IP = 0;
    private const int IPPROTO_UDP = 17;
    private const int IP_PKTINFO = 8;
    private const int IP_HDRINCL = 3;

    // Packet socket constants (AF_PACKET)
    private const int AF_PACKET = 17;
    private const int ETH_P_IP = 0x0800;
    private const int SOCK_DGRAM_PACKET = 2;

    private readonly ILogger<DhcpWorker> _logger;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IConfiguration _configuration;
    private readonly Socket _sendSocket;           // UDP socket for sending responses
    private readonly LinuxRawSocket? _rawSocket;   // Raw packet socket for receiving on Linux
    private readonly Channel<DhcpPacketContext> _packetChannel;
    private readonly ArrayPool<byte> _bufferPool;
    private readonly string _bindInterface;
    private readonly bool _useRawSocket;

    // Statistics
    private long _packetsReceived;
    private long _packetsProcessed;
    private long _discoverCount;
    private long _requestCount;
    private long _releaseCount;
    private long _offersCount;
    private long _acksCount;
    private long _naksCount;
    private long _errorsCount;

    // Pre-allocated for MAC address formatting
    private static readonly char[] HexChars = "0123456789ABCDEF".ToCharArray();

    public DhcpWorker(ILogger<DhcpWorker> logger, IServiceScopeFactory scopeFactory, IConfiguration configuration)
    {
        _logger = logger;
        _scopeFactory = scopeFactory;
        _configuration = configuration;
        _bufferPool = ArrayPool<byte>.Shared;

        // Get interface to bind to from configuration
        _bindInterface = configuration.GetValue<string>("DHCP:Interface") ?? "ens256";

        // Create UDP socket for sending responses
        _sendSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _sendSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, true);
        _sendSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);

        // On Linux, use raw packet socket (AF_PACKET) for receiving DHCP broadcasts
        // Standard UDP sockets don't reliably receive packets to 255.255.255.255
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            _useRawSocket = true;
            _rawSocket = new LinuxRawSocket(_bindInterface, logger);
            _logger.LogInformation("[SOCKET] Using AF_PACKET raw socket for receiving on Linux");

            // Bind send socket to interface for responses
            var interfaceBytes = Encoding.ASCII.GetBytes(_bindInterface + '\0');
            _sendSocket.SetRawSocketOption(SOL_SOCKET, SO_BINDTODEVICE, interfaceBytes);
            _sendSocket.Bind(new IPEndPoint(IPAddress.Any, 67));
            _logger.LogInformation("[SOCKET] Send socket bound to 0.0.0.0:67 on interface {Interface}", _bindInterface);
        }
        else
        {
            // On Windows, use standard UDP socket for both send and receive
            _useRawSocket = false;
            _rawSocket = null;
            _sendSocket.Bind(new IPEndPoint(IPAddress.Any, 67));
            _logger.LogInformation("[SOCKET] Using standard UDP socket on Windows");
        }

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
        PrintStartupBanner();

        _logger.LogInformation("DHCP Server starting on port 67");
        _logger.LogInformation("Listening for DHCP packets on all interfaces (0.0.0.0:67)");

        // Start statistics reporter
        _ = ReportStatisticsAsync(stoppingToken);

        // Run receive and process concurrently
        await Task.WhenAll(
            ReceivePacketsAsync(stoppingToken),
            ProcessPacketsAsync(stoppingToken)
        ).ConfigureAwait(false);
    }

    private void PrintStartupBanner()
    {
        AnsiConsole.Write(new FigletText("DHCP Server").Color(Color.Green));

        var table = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn("Setting")
            .AddColumn("Value");

        table.AddRow("Port", "67 (UDP)");
        table.AddRow("Bind Address", "0.0.0.0");
        table.AddRow("Interface", _bindInterface);
        table.AddRow("Buffer Size", $"{MaxDhcpPacketSize} bytes");
        table.AddRow("Channel Capacity", "100 packets");
        table.AddRow("OS", RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "Linux" : "Windows");

        AnsiConsole.Write(table);
        AnsiConsole.WriteLine();
    }

    private async Task ReportStatisticsAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken).ConfigureAwait(false);

            _logger.LogInformation(
                "DHCP Stats - Received: {Received}, Processed: {Processed}, " +
                "DISCOVER: {Discover}, REQUEST: {Request}, RELEASE: {Release}, " +
                "OFFER: {Offer}, ACK: {Ack}, NAK: {Nak}, Errors: {Errors}",
                _packetsReceived, _packetsProcessed,
                _discoverCount, _requestCount, _releaseCount,
                _offersCount, _acksCount, _naksCount, _errorsCount);
        }
    }

    private async Task ReceivePacketsAsync(CancellationToken stoppingToken)
    {
        var writer = _packetChannel.Writer;
        var receiveBuffer = new byte[1024]; // Buffer for receiving

        _logger.LogInformation("[RECV] Starting receive loop on interface: {Interface}, UseRawSocket: {UseRaw}",
            _bindInterface, _useRawSocket);

        try
        {
            // Use synchronous receive in a thread pool thread
            await Task.Run(() =>
            {
                while (!stoppingToken.IsCancellationRequested)
                {
                    try
                    {
                        int receivedBytes;
                        IPEndPoint? sourceEndPoint;

                        if (_useRawSocket && _rawSocket != null)
                        {
                            // Use raw packet socket on Linux
                            receivedBytes = _rawSocket.Receive(receiveBuffer, out sourceEndPoint);
                        }
                        else
                        {
                            // Use standard UDP socket on Windows
                            EndPoint remoteEp = new IPEndPoint(IPAddress.Any, 0);

                            if (!_sendSocket.Poll(1000000, SelectMode.SelectRead))
                            {
                                continue;
                            }

                            receivedBytes = _sendSocket.ReceiveFrom(receiveBuffer, ref remoteEp);
                            sourceEndPoint = (IPEndPoint)remoteEp;
                        }

                        if (receivedBytes <= 0) continue;

                        Interlocked.Increment(ref _packetsReceived);

                        _logger.LogInformation("[RECV] Packet received: {Length} bytes from {RemoteEndPoint}",
                            receivedBytes, sourceEndPoint);

                        ProcessReceivedPacket(writer, receiveBuffer, receivedBytes, sourceEndPoint!);
                    }
                    catch (SocketException ex) when (ex.SocketErrorCode == SocketError.Interrupted)
                    {
                        break;
                    }
                    catch (SocketException ex) when (ex.SocketErrorCode == SocketError.TimedOut)
                    {
                        continue;
                    }
                    catch (SocketException ex)
                    {
                        _logger.LogError(ex, "[RECV] Socket error: {ErrorCode} - {Message}",
                            ex.SocketErrorCode, ex.Message);
                        Interlocked.Increment(ref _errorsCount);
                    }
                    catch (ObjectDisposedException)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "[RECV] Unexpected error receiving packet");
                        Interlocked.Increment(ref _errorsCount);
                    }
                }
            }, stoppingToken).ConfigureAwait(false);
        }
        finally
        {
            writer.Complete();
            _logger.LogInformation("DHCP packet receiver stopped");
        }
    }

    private void ProcessReceivedPacket(ChannelWriter<DhcpPacketContext> writer, byte[] receiveBuffer, int receivedBytes, IPEndPoint sourceEndPoint)
    {
        _logger.LogDebug(
            "[RECV] Processing packet: {Length} bytes from {RemoteEndPoint}",
            receivedBytes, sourceEndPoint);

        if (receivedBytes < MinDhcpPacketSize)
        {
            _logger.LogWarning(
                "[RECV] Packet too short: {Length} bytes (minimum: {Min}) from {RemoteEndPoint}",
                receivedBytes, MinDhcpPacketSize, sourceEndPoint);
            return;
        }

        // Rent buffer from pool and copy data
        var rentedBuffer = _bufferPool.Rent(receivedBytes);
        receiveBuffer.AsSpan(0, receivedBytes).CopyTo(rentedBuffer);

        var context = new DhcpPacketContext(
            rentedBuffer,
            receivedBytes,
            sourceEndPoint,
            _bufferPool
        );

        // Try to write to channel, drop if full
        if (!writer.TryWrite(context))
        {
            _logger.LogWarning(
                "[RECV] Packet channel full, dropping packet from {RemoteEndPoint}",
                sourceEndPoint);
            context.Dispose();
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
                Interlocked.Increment(ref _packetsProcessed);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[PROC] Error processing DHCP packet from {RemoteEndPoint}",
                    context.RemoteEndPoint);
                Interlocked.Increment(ref _errorsCount);
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
            _logger.LogWarning("[PROC] Failed to parse DHCP packet from {RemoteEndPoint}",
                context.RemoteEndPoint);
            return;
        }

        // Log the parsed request details
        LogDhcpRequest(request);

        // Track message types
        switch (request.MessageType)
        {
            case DhcpMessageType.Discover:
                Interlocked.Increment(ref _discoverCount);
                break;
            case DhcpMessageType.Request:
                Interlocked.Increment(ref _requestCount);
                break;
            case DhcpMessageType.Release:
                Interlocked.Increment(ref _releaseCount);
                break;
        }

        // Create scoped service for database operations
        await using var scope = _scopeFactory.CreateAsyncScope();
        var dhcpService = scope.ServiceProvider.GetRequiredService<IDhcpServerService>();

        _logger.LogDebug("[PROC] Creating DHCP response for {MessageType} from {Mac}",
            request.MessageType, request.ClientMac);

        var response = await dhcpService.CreateDhcpResponseAsync(request).ConfigureAwait(false);

        if (response.Length > 0)
        {
            var destination = DetermineDestinationEndPoint(request, context.RemoteEndPoint);

            // Parse response to log what we're sending
            var responseType = ParseResponseMessageType(response);
            LogDhcpResponse(request, responseType, destination);

            // Track response types
            switch (responseType)
            {
                case DhcpMessageType.Offer:
                    Interlocked.Increment(ref _offersCount);
                    break;
                case DhcpMessageType.Ack:
                    Interlocked.Increment(ref _acksCount);
                    break;
                case DhcpMessageType.Nak:
                    Interlocked.Increment(ref _naksCount);
                    break;
            }

            await _sendSocket.SendToAsync(response, SocketFlags.None, destination, stoppingToken).ConfigureAwait(false);

            _logger.LogDebug("[SEND] Sent {Length} bytes to {Destination}",
                response.Length, destination);
        }
        else
        {
            _logger.LogWarning(
                "[PROC] No response generated for {MessageType} from {Mac} - check subnet/pool configuration",
                request.MessageType, request.ClientMac);
        }
    }

    private void LogDhcpRequest(DhcpRequest request)
    {
        // Always log requests at Info level for visibility
        _logger.LogInformation(
            "[REQUEST] {MessageType,-10} | MAC: {Mac} | Hostname: {Hostname} | " +
            "RequestedIP: {RequestedIp} | ClientIP: {CiAddr} | RelayIP: {GiAddr}",
            request.MessageType,
            request.ClientMac,
            request.Hostname ?? "(none)",
            request.RequestedIp?.ToString() ?? "(none)",
            request.CiAddr?.ToString() ?? "0.0.0.0",
            request.GiAddr?.ToString() ?? "0.0.0.0");

        // Log additional details at Debug level
        if (_logger.IsEnabled(LogLevel.Debug))
        {
            _logger.LogDebug(
                "[REQUEST DETAILS] XID: {Xid} | Flags: 0x{Flags:X4} | Secs: {Secs} | " +
                "VendorClass: {VendorClass} | IsPXE: {IsPxe} | IsBOOTP: {IsBootp}",
                BitConverter.ToString(request.Xid),
                request.Flags,
                request.Secs,
                request.VendorClassIdentifier ?? "(none)",
                request.IsPxeRequest,
                request.IsBootp);

            if (request.ParameterRequestList != null && request.ParameterRequestList.Length > 0)
            {
                var optionNames = string.Join(", ", request.ParameterRequestList.Select(o => $"{o}"));
                _logger.LogDebug("[REQUEST OPTIONS] Parameter Request List: {Options}", optionNames);
            }
        }
    }

    private void LogDhcpResponse(DhcpRequest request, DhcpMessageType responseType, IPEndPoint destination)
    {
        _logger.LogInformation(
            "[RESPONSE] {ResponseType,-10} | MAC: {Mac} | Destination: {Destination}",
            responseType,
            request.ClientMac,
            destination);
    }

    private static DhcpMessageType ParseResponseMessageType(byte[] response)
    {
        // DHCP message type is in options, after magic cookie (offset 240)
        // Look for option 53 (message type)
        if (response.Length < 243) return 0; // Unknown/default

        int i = 240; // Start after magic cookie
        while (i < response.Length)
        {
            byte optionCode = response[i++];

            if (optionCode == 255) break; // End option
            if (optionCode == 0) continue; // Pad option

            if (i >= response.Length) break;
            int optionLength = response[i++];

            if (optionCode == 53 && optionLength >= 1 && i < response.Length)
            {
                return (DhcpMessageType)response[i];
            }

            i += optionLength;
        }

        return 0; // Unknown/default
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
            _logger.LogWarning("[PARSE] Buffer too short: {Length} bytes", buffer.Length);
            return false;
        }

        // Validate magic cookie
        if (buffer[236] != 99 || buffer[237] != 130 || buffer[238] != 83 || buffer[239] != 99)
        {
            _logger.LogWarning("[PARSE] Invalid DHCP magic cookie: {B0:X2} {B1:X2} {B2:X2} {B3:X2}",
                buffer[236], buffer[237], buffer[238], buffer[239]);
            return false;
        }

        // Validate op code (1 = BOOTREQUEST, 2 = BOOTREPLY)
        if (buffer[0] != 1)
        {
            _logger.LogDebug("[PARSE] Ignoring non-request packet (op={Op})", buffer[0]);
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

        request.IsBootp = request.MessageType == 0 && request.Op == 1;
        request.IsPxeRequest = request.VendorClassIdentifier?.Contains("PXEClient") == true;

        _logger.LogDebug(
            "[PARSE] Successfully parsed {MessageType} from {Mac} (XID: {Xid})",
            request.MessageType, request.ClientMac, BitConverter.ToString(request.Xid));

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
        var parsedOptions = new List<string>();

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
            parsedOptions.Add($"{(DhcpOptionCode)optionCode}({optionCode})");
        }

        if (_logger.IsEnabled(LogLevel.Trace))
        {
            _logger.LogTrace("[PARSE OPTIONS] Found: {Options}", string.Join(", ", parsedOptions));
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

        // Print final statistics
        AnsiConsole.WriteLine();
        var table = new Table()
            .Border(TableBorder.Rounded)
            .Title("[yellow]Final Statistics[/]")
            .AddColumn("Metric")
            .AddColumn("Count");

        table.AddRow("Packets Received", _packetsReceived.ToString());
        table.AddRow("Packets Processed", _packetsProcessed.ToString());
        table.AddRow("DISCOVER", _discoverCount.ToString());
        table.AddRow("REQUEST", _requestCount.ToString());
        table.AddRow("RELEASE", _releaseCount.ToString());
        table.AddRow("OFFER sent", _offersCount.ToString());
        table.AddRow("ACK sent", _acksCount.ToString());
        table.AddRow("NAK sent", _naksCount.ToString());
        table.AddRow("Errors", _errorsCount.ToString());

        AnsiConsole.Write(table);

        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    public override void Dispose()
    {
        _rawSocket?.Dispose();
        _sendSocket.Close();
        _sendSocket.Dispose();
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
