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
/// DHCP Failover service implementation.
/// Implements ISC-DHCP compatible failover protocol for high availability.
/// </summary>
public sealed class FailoverService : IFailoverService, IDisposable
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly ILogger<FailoverService> _logger;
    private readonly ArrayPool<byte> _bufferPool = ArrayPool<byte>.Shared;

    private FailoverPeer? _peerConfig;
    private TcpClient? _client;
    private NetworkStream? _stream;
    private CancellationTokenSource? _cts;
    private Task? _receiveTask;
    private Task? _heartbeatTask;
    private Timer? _stateTimer;

    // Pending binding updates awaiting acknowledgment
    private readonly ConcurrentDictionary<uint, TaskCompletionSource<bool>> _pendingUpdates = new();
    private uint _transactionId;
    private readonly object _stateLock = new();

    public FailoverState CurrentState { get; private set; } = FailoverState.Startup;
    public bool IsEnabled => _peerConfig?.Enabled == true;
    public bool CanServe => CurrentState == FailoverState.Normal ||
                            CurrentState == FailoverState.PartnerDown ||
                            CurrentState == FailoverState.CommunicationsInterrupted;

    public event EventHandler<FailoverStateChangedEventArgs>? StateChanged;

    public FailoverService(NpgsqlDataSource dataSource, ILogger<FailoverService> logger)
    {
        _dataSource = dataSource;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        // Load configuration
        _peerConfig = await LoadPeerConfigAsync(cancellationToken).ConfigureAwait(false);

        if (_peerConfig == null || !_peerConfig.Enabled)
        {
            _logger.LogInformation("Failover not configured or disabled");
            return;
        }

        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        _logger.LogInformation("Starting failover service as {Role} with peer {Peer}:{Port}",
            _peerConfig.Role, _peerConfig.PeerAddress, _peerConfig.PeerPort);

        // Start connection task
        _ = Task.Run(() => MaintainConnectionAsync(_cts.Token), _cts.Token);

        // Start state monitoring timer
        _stateTimer = new Timer(
            CheckStateTimeout,
            null,
            TimeSpan.FromSeconds(10),
            TimeSpan.FromSeconds(10));

        await TransitionToStateAsync(FailoverState.Startup, cancellationToken).ConfigureAwait(false);
    }

    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        if (_peerConfig == null) return;

        _logger.LogInformation("Stopping failover service");

        // Send disconnect message
        if (_stream != null && _client?.Connected == true)
        {
            try
            {
                await SendMessageAsync(FailoverMessageType.Disconnect, [], cancellationToken)
                    .ConfigureAwait(false);
            }
            catch
            {
                // Ignore errors during shutdown
            }
        }

        await TransitionToStateAsync(FailoverState.Shutdown, cancellationToken).ConfigureAwait(false);

        _cts?.Cancel();
        _stateTimer?.Dispose();
        _client?.Dispose();
        _stream?.Dispose();
    }

    public bool ShouldHandleRequest(string macAddress, IPAddress? ipAddress)
    {
        if (_peerConfig == null || !IsEnabled)
            return true;

        // In partner-down state, handle all requests
        if (CurrentState == FailoverState.PartnerDown)
            return true;

        // In communications-interrupted, handle based on ownership
        if (CurrentState == FailoverState.CommunicationsInterrupted)
        {
            // Primary handles its split, secondary handles its split
            return IsAddressOurs(ipAddress);
        }

        // Normal operation: use load balancing hash
        if (CurrentState == FailoverState.Normal)
        {
            return IsClientOurs(macAddress);
        }

        // In other states, be conservative
        return _peerConfig.IsPrimary;
    }

    private bool IsClientOurs(string macAddress)
    {
        if (_peerConfig == null) return true;

        // Hash MAC address to determine which server handles it
        var hash = ComputeMacHash(macAddress);

        // Primary handles hash values 0 to split-1
        // Secondary handles hash values split to 255
        if (_peerConfig.IsPrimary)
        {
            return hash < _peerConfig.Split;
        }
        else
        {
            return hash >= _peerConfig.Split;
        }
    }

    private bool IsAddressOurs(IPAddress? ipAddress)
    {
        if (ipAddress == null || _peerConfig == null) return true;

        // Use last octet for simple split determination
        var lastOctet = ipAddress.GetAddressBytes()[3];

        if (_peerConfig.IsPrimary)
        {
            return lastOctet < _peerConfig.Split;
        }
        else
        {
            return lastOctet >= _peerConfig.Split;
        }
    }

    private static byte ComputeMacHash(string macAddress)
    {
        // Simple hash based on MAC address bytes
        var bytes = ParseMacToBytes(macAddress);
        uint hash = 0;
        foreach (var b in bytes)
        {
            hash = ((hash << 5) + hash) ^ b;
        }
        return (byte)(hash & 0xFF);
    }

    private static byte[] ParseMacToBytes(string macAddress)
    {
        var result = new byte[6];
        var parts = macAddress.Split(':', '-');
        for (int i = 0; i < Math.Min(6, parts.Length); i++)
        {
            if (byte.TryParse(parts[i], System.Globalization.NumberStyles.HexNumber, null, out var b))
            {
                result[i] = b;
            }
        }
        return result;
    }

    public async Task<bool> SendBindingUpdateAsync(
        FailoverBindingUpdate update,
        CancellationToken cancellationToken = default)
    {
        if (!IsEnabled || CurrentState == FailoverState.PartnerDown)
            return true; // No peer to update

        if (_stream == null || !_client?.Connected == true)
            return false;

        try
        {
            var txId = Interlocked.Increment(ref _transactionId);
            var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            _pendingUpdates[txId] = tcs;

            // Build BNDUPD message
            var payload = BuildBindingUpdatePayload(update, txId);
            await SendMessageAsync(FailoverMessageType.BndUpd, payload, cancellationToken)
                .ConfigureAwait(false);

            // Wait for acknowledgment with timeout
            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken, timeoutCts.Token);

            try
            {
                return await tcs.Task.WaitAsync(linkedCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                _pendingUpdates.TryRemove(txId, out _);
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to send binding update");
            return false;
        }
    }

    public async Task<bool> SendBindingReleaseAsync(
        IPAddress ipAddress,
        string macAddress,
        CancellationToken cancellationToken = default)
    {
        var update = new FailoverBindingUpdate
        {
            IpAddress = ipAddress,
            MacAddress = macAddress,
            BindingState = FailoverBindingState.Released,
            EndTime = DateTime.UtcNow
        };

        return await SendBindingUpdateAsync(update, cancellationToken).ConfigureAwait(false);
    }

    public async Task<bool> RequestPoolRebalanceAsync(
        Guid poolId,
        CancellationToken cancellationToken = default)
    {
        if (!IsEnabled || _stream == null)
            return false;

        try
        {
            var payload = poolId.ToByteArray();
            await SendMessageAsync(FailoverMessageType.PoolReq, payload, cancellationToken)
                .ConfigureAwait(false);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to request pool rebalance");
            return false;
        }
    }

    public async Task TransitionToStateAsync(
        FailoverState newState,
        CancellationToken cancellationToken = default)
    {
        FailoverState oldState;
        lock (_stateLock)
        {
            if (CurrentState == newState) return;
            oldState = CurrentState;
            CurrentState = newState;
            if (_peerConfig != null)
            {
                _peerConfig.CurrentState = newState;
                _peerConfig.StateTransitionTime = DateTime.UtcNow;
            }
        }

        _logger.LogInformation("Failover state transition: {Old} -> {New}", oldState, newState);

        // Persist state change
        await PersistStateAsync(newState, cancellationToken).ConfigureAwait(false);

        // Notify peer of state change
        if (_stream != null && _client?.Connected == true)
        {
            try
            {
                var payload = new[] { (byte)newState };
                await SendMessageAsync(FailoverMessageType.State, payload, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch
            {
                // Ignore - we're changing state anyway
            }
        }

        // Raise event
        StateChanged?.Invoke(this, new FailoverStateChangedEventArgs(oldState, newState));
    }

    public async Task ForcePartnerDownAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogWarning("Forcing partner-down state by administrator");
        await TransitionToStateAsync(FailoverState.PartnerDown, cancellationToken)
            .ConfigureAwait(false);
    }

    public FailoverPeer? GetPeerConfig() => _peerConfig;

    public async Task<IReadOnlyList<FailoverPoolStats>> GetPoolStatsAsync(
        CancellationToken cancellationToken = default)
    {
        var stats = new List<FailoverPoolStats>();

        try
        {
            await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken)
                .ConfigureAwait(false);

            const string sql = @"
                SELECT
                    p.id,
                    COUNT(DISTINCT ip) as total,
                    COUNT(DISTINCT ip) FILTER (WHERE l.id IS NULL) as free,
                    COUNT(DISTINCT l.id) FILTER (WHERE l.end_time > NOW()) as active
                FROM dhcp_pools p
                CROSS JOIN generate_series(p.range_start::inet, p.range_end::inet) AS ip
                LEFT JOIN dhcp_leases l ON l.ip_address = ip AND l.end_time > NOW()
                WHERE p.enabled = true
                GROUP BY p.id";

            await using var cmd = new NpgsqlCommand(sql, connection);
            await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                stats.Add(new FailoverPoolStats
                {
                    PoolId = reader.GetGuid(0),
                    TotalAddresses = reader.GetInt32(1),
                    FreeAddresses = reader.GetInt32(2),
                    ActiveLeases = reader.GetInt32(3)
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get pool stats");
        }

        return stats;
    }

    public async Task<int> SynchronizeLeasesAsync(CancellationToken cancellationToken = default)
    {
        if (!IsEnabled || _stream == null)
            return 0;

        _logger.LogInformation("Starting lease synchronization with peer");

        try
        {
            // Request all updates from peer
            await SendMessageAsync(FailoverMessageType.UpdReqAll, [], cancellationToken)
                .ConfigureAwait(false);

            // Peer will send BNDUPD messages for each lease
            // These are handled in the receive loop
            // Return approximate count of our leases as reference
            await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken)
                .ConfigureAwait(false);

            await using var cmd = new NpgsqlCommand(
                "SELECT COUNT(*) FROM dhcp_leases WHERE end_time > NOW()", connection);
            var count = await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);

            return Convert.ToInt32(count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to synchronize leases");
            return -1;
        }
    }

    private async Task MaintainConnectionAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                if (_peerConfig == null) break;

                if (_client == null || !_client.Connected)
                {
                    await ConnectToPeerAsync(cancellationToken).ConfigureAwait(false);
                }

                // Start receive loop if connected
                if (_client?.Connected == true && _stream != null)
                {
                    _receiveTask = ReceiveLoopAsync(cancellationToken);
                    _heartbeatTask = HeartbeatLoopAsync(cancellationToken);

                    await Task.WhenAny(_receiveTask, _heartbeatTask).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failover connection error, will retry");
                await HandleConnectionLostAsync(cancellationToken).ConfigureAwait(false);
            }

            // Wait before retry
            await Task.Delay(TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task ConnectToPeerAsync(CancellationToken cancellationToken)
    {
        if (_peerConfig == null) return;

        _logger.LogDebug("Connecting to failover peer {Peer}:{Port}",
            _peerConfig.PeerAddress, _peerConfig.PeerPort);

        _client?.Dispose();
        _client = new TcpClient();

        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken, timeoutCts.Token);

        await _client.ConnectAsync(_peerConfig.PeerAddress, _peerConfig.PeerPort, linkedCts.Token)
            .ConfigureAwait(false);

        _stream = _client.GetStream();
        _peerConfig.IsConnected = true;
        _peerConfig.LastContactTime = DateTime.UtcNow;

        _logger.LogInformation("Connected to failover peer");

        // Send CONNECT message
        await SendConnectMessageAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task SendConnectMessageAsync(CancellationToken cancellationToken)
    {
        if (_peerConfig == null) return;

        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        // Protocol version
        writer.Write((byte)1);
        writer.Write((byte)0);

        // Send time
        var sendTime = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        writer.Write(IPAddress.HostToNetworkOrder((int)sendTime));

        // MCLT
        writer.Write(IPAddress.HostToNetworkOrder(_peerConfig.Mclt));

        // Split
        writer.Write((byte)_peerConfig.Split);

        // Role
        writer.Write((byte)(_peerConfig.IsPrimary ? 0 : 1));

        // Current state
        writer.Write((byte)CurrentState);

        // Server identifier (local address)
        var localAddr = _peerConfig.LocalAddress ?? IPAddress.Loopback;
        writer.Write(localAddr.GetAddressBytes());

        await SendMessageAsync(FailoverMessageType.Connect, ms.ToArray(), cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task ReceiveLoopAsync(CancellationToken cancellationToken)
    {
        var headerBuffer = new byte[4];

        while (!cancellationToken.IsCancellationRequested && _stream != null)
        {
            try
            {
                // Read message header (length + type)
                var bytesRead = await _stream.ReadAsync(headerBuffer, cancellationToken)
                    .ConfigureAwait(false);

                if (bytesRead == 0)
                {
                    _logger.LogWarning("Peer disconnected");
                    break;
                }

                if (bytesRead < 4)
                {
                    continue;
                }

                var length = (headerBuffer[0] << 8) | headerBuffer[1];
                var messageType = (FailoverMessageType)headerBuffer[2];
                // headerBuffer[3] is flags/reserved

                // Read payload
                var payload = new byte[length - 4];
                if (payload.Length > 0)
                {
                    var payloadRead = await _stream.ReadAsync(payload, cancellationToken)
                        .ConfigureAwait(false);
                    if (payloadRead < payload.Length)
                    {
                        _logger.LogWarning("Incomplete message received");
                        continue;
                    }
                }

                if (_peerConfig != null)
                {
                    _peerConfig.LastContactTime = DateTime.UtcNow;
                }

                await HandleMessageAsync(messageType, payload, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (IOException ex)
            {
                _logger.LogWarning(ex, "Connection lost while receiving");
                break;
            }
        }
    }

    private async Task HandleMessageAsync(
        FailoverMessageType messageType,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        switch (messageType)
        {
            case FailoverMessageType.ConnectAck:
                await HandleConnectAckAsync(payload, cancellationToken).ConfigureAwait(false);
                break;

            case FailoverMessageType.State:
                HandleStateMessage(payload);
                break;

            case FailoverMessageType.BndUpd:
                await HandleBindingUpdateAsync(payload, cancellationToken).ConfigureAwait(false);
                break;

            case FailoverMessageType.BndAck:
                HandleBindingAck(payload);
                break;

            case FailoverMessageType.Contact:
                // Heartbeat received, update last contact time
                if (_peerConfig != null)
                {
                    _peerConfig.LastContactTime = DateTime.UtcNow;
                }
                break;

            case FailoverMessageType.Disconnect:
                _logger.LogInformation("Peer sent disconnect");
                await HandleConnectionLostAsync(cancellationToken).ConfigureAwait(false);
                break;

            case FailoverMessageType.UpdReqAll:
                await SendAllBindingsAsync(cancellationToken).ConfigureAwait(false);
                break;

            case FailoverMessageType.UpdDone:
                _logger.LogInformation("Peer completed update synchronization");
                break;

            default:
                _logger.LogDebug("Received message type {Type}", messageType);
                break;
        }
    }

    private async Task HandleConnectAckAsync(byte[] payload, CancellationToken cancellationToken)
    {
        if (payload.Length < 7) return;

        // Parse peer info
        var rejectReason = (FailoverRejectReason)payload[0];

        if (rejectReason != FailoverRejectReason.None)
        {
            _logger.LogWarning("Connection rejected by peer: {Reason}", rejectReason);
            await HandleConnectionLostAsync(cancellationToken).ConfigureAwait(false);
            return;
        }

        var peerState = (FailoverState)payload[1];

        if (_peerConfig != null)
        {
            _peerConfig.PeerState = peerState;
        }

        _logger.LogInformation("Peer connected, state: {State}", peerState);

        // Transition to appropriate state
        if (CurrentState == FailoverState.Startup || CurrentState == FailoverState.CommunicationsInterrupted)
        {
            if (peerState == FailoverState.Normal || peerState == FailoverState.Recover)
            {
                await TransitionToStateAsync(FailoverState.Normal, cancellationToken)
                    .ConfigureAwait(false);
            }
            else if (peerState == FailoverState.PartnerDown)
            {
                await TransitionToStateAsync(FailoverState.Recover, cancellationToken)
                    .ConfigureAwait(false);
            }
        }
    }

    private void HandleStateMessage(byte[] payload)
    {
        if (payload.Length < 1) return;

        var peerState = (FailoverState)payload[0];

        if (_peerConfig != null)
        {
            _peerConfig.PeerState = peerState;
        }

        _logger.LogInformation("Peer state changed to {State}", peerState);
    }

    private async Task HandleBindingUpdateAsync(byte[] payload, CancellationToken cancellationToken)
    {
        if (payload.Length < 20) return;

        try
        {
            var offset = 0;

            // Transaction ID
            var txId = (uint)IPAddress.NetworkToHostOrder(BitConverter.ToInt32(payload, offset));
            offset += 4;

            // IP address
            var ipBytes = new byte[4];
            Array.Copy(payload, offset, ipBytes, 0, 4);
            var ipAddress = new IPAddress(ipBytes);
            offset += 4;

            // MAC address
            var macBytes = new byte[6];
            Array.Copy(payload, offset, macBytes, 0, 6);
            var mac = BitConverter.ToString(macBytes).Replace("-", ":");
            offset += 6;

            // Binding state
            var bindingState = (FailoverBindingState)payload[offset++];

            // Start time
            var startTime = DateTimeOffset.FromUnixTimeSeconds(
                IPAddress.NetworkToHostOrder(BitConverter.ToInt32(payload, offset))).UtcDateTime;
            offset += 4;

            // End time
            var endTime = DateTimeOffset.FromUnixTimeSeconds(
                IPAddress.NetworkToHostOrder(BitConverter.ToInt32(payload, offset))).UtcDateTime;
            offset += 4;

            _logger.LogDebug("Received binding update: {Ip} -> {Mac}, state={State}",
                ipAddress, mac, bindingState);

            // Apply the binding update
            await ApplyBindingUpdateAsync(ipAddress, mac, bindingState, startTime, endTime, cancellationToken)
                .ConfigureAwait(false);

            // Send acknowledgment
            var ackPayload = new byte[5];
            var txIdBytes = BitConverter.GetBytes(IPAddress.HostToNetworkOrder((int)txId));
            Array.Copy(txIdBytes, 0, ackPayload, 0, 4);
            ackPayload[4] = 0; // Success

            await SendMessageAsync(FailoverMessageType.BndAck, ackPayload, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to handle binding update");
        }
    }

    private async Task ApplyBindingUpdateAsync(
        IPAddress ipAddress,
        string macAddress,
        FailoverBindingState bindingState,
        DateTime startTime,
        DateTime endTime,
        CancellationToken cancellationToken)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken)
            .ConfigureAwait(false);

        switch (bindingState)
        {
            case FailoverBindingState.Active:
                // Upsert lease
                const string upsertSql = @"
                    INSERT INTO dhcp_leases (id, mac_address, ip_address, start_time, end_time)
                    VALUES (@id, @mac::macaddr, @ip, @start, @end)
                    ON CONFLICT (mac_address)
                    DO UPDATE SET ip_address = @ip, start_time = @start, end_time = @end";

                await using (var cmd = new NpgsqlCommand(upsertSql, connection))
                {
                    cmd.Parameters.AddWithValue("id", Guid.NewGuid());
                    cmd.Parameters.AddWithValue("mac", macAddress);
                    cmd.Parameters.AddWithValue("ip", ipAddress);
                    cmd.Parameters.AddWithValue("start", startTime);
                    cmd.Parameters.AddWithValue("end", endTime);
                    await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                }
                break;

            case FailoverBindingState.Released:
            case FailoverBindingState.Free:
            case FailoverBindingState.Expired:
                // Delete lease
                const string deleteSql = "DELETE FROM dhcp_leases WHERE ip_address = @ip";
                await using (var cmd = new NpgsqlCommand(deleteSql, connection))
                {
                    cmd.Parameters.AddWithValue("ip", ipAddress);
                    await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
                }
                break;
        }
    }

    private void HandleBindingAck(byte[] payload)
    {
        if (payload.Length < 5) return;

        var txId = (uint)IPAddress.NetworkToHostOrder(BitConverter.ToInt32(payload, 0));
        var success = payload[4] == 0;

        if (_pendingUpdates.TryRemove(txId, out var tcs))
        {
            tcs.TrySetResult(success);
        }

        if (_peerConfig != null && _peerConfig.UnackedUpdates > 0)
        {
            _peerConfig.UnackedUpdates--;
        }
    }

    private async Task SendAllBindingsAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Sending all bindings to peer");

        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken)
            .ConfigureAwait(false);

        const string sql = @"
            SELECT mac_address, ip_address, start_time, end_time
            FROM dhcp_leases
            WHERE end_time > NOW()
            ORDER BY start_time";

        await using var cmd = new NpgsqlCommand(sql, connection);
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

        var count = 0;
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var mac = reader.GetValue(0).ToString() ?? "";
            var ip = (IPAddress)reader.GetValue(1);
            var startTime = reader.GetDateTime(2);
            var endTime = reader.GetDateTime(3);

            var update = new FailoverBindingUpdate
            {
                MacAddress = mac,
                IpAddress = ip,
                StartTime = startTime,
                EndTime = endTime,
                BindingState = FailoverBindingState.Active
            };

            await SendBindingUpdateAsync(update, cancellationToken).ConfigureAwait(false);
            count++;

            // Throttle to avoid overwhelming the connection
            if (count % 100 == 0)
            {
                await Task.Delay(10, cancellationToken).ConfigureAwait(false);
            }
        }

        // Send UPDDONE
        await SendMessageAsync(FailoverMessageType.UpdDone, [], cancellationToken)
            .ConfigureAwait(false);

        _logger.LogInformation("Sent {Count} bindings to peer", count);
    }

    private async Task HeartbeatLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && _stream != null)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(10), cancellationToken).ConfigureAwait(false);

                await SendMessageAsync(FailoverMessageType.Contact, [], cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                break;
            }
        }
    }

    private void CheckStateTimeout(object? state)
    {
        if (_peerConfig == null || !IsEnabled) return;

        var timeSinceContact = DateTime.UtcNow - _peerConfig.LastContactTime;

        if (timeSinceContact.TotalSeconds > _peerConfig.MaxResponseDelay)
        {
            if (CurrentState == FailoverState.Normal)
            {
                _logger.LogWarning("Lost contact with peer, transitioning to COMMUNICATIONS-INTERRUPTED");
                _ = TransitionToStateAsync(FailoverState.CommunicationsInterrupted);
            }
            else if (CurrentState == FailoverState.CommunicationsInterrupted &&
                     _peerConfig.AutoPartnerDown > 0)
            {
                var timeInState = DateTime.UtcNow - _peerConfig.StateTransitionTime;
                if (timeInState.TotalSeconds > _peerConfig.AutoPartnerDown)
                {
                    _logger.LogWarning("Auto partner-down triggered after {Seconds}s",
                        _peerConfig.AutoPartnerDown);
                    _ = TransitionToStateAsync(FailoverState.PartnerDown);
                }
            }
        }
    }

    private async Task HandleConnectionLostAsync(CancellationToken cancellationToken)
    {
        if (_peerConfig != null)
        {
            _peerConfig.IsConnected = false;
        }

        _stream?.Dispose();
        _stream = null;
        _client?.Dispose();
        _client = null;

        if (CurrentState == FailoverState.Normal)
        {
            await TransitionToStateAsync(FailoverState.CommunicationsInterrupted, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private byte[] BuildBindingUpdatePayload(FailoverBindingUpdate update, uint txId)
    {
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        // Transaction ID
        writer.Write(IPAddress.HostToNetworkOrder((int)txId));

        // IP address
        writer.Write(update.IpAddress.GetAddressBytes());

        // MAC address
        var macBytes = ParseMacToBytes(update.MacAddress);
        writer.Write(macBytes);

        // Binding state
        writer.Write((byte)update.BindingState);

        // Start time
        var startUnix = new DateTimeOffset(update.StartTime).ToUnixTimeSeconds();
        writer.Write(IPAddress.HostToNetworkOrder((int)startUnix));

        // End time
        var endUnix = new DateTimeOffset(update.EndTime).ToUnixTimeSeconds();
        writer.Write(IPAddress.HostToNetworkOrder((int)endUnix));

        return ms.ToArray();
    }

    private async Task SendMessageAsync(
        FailoverMessageType messageType,
        byte[] payload,
        CancellationToken cancellationToken)
    {
        if (_stream == null) return;

        var totalLength = 4 + payload.Length; // header + payload
        var buffer = _bufferPool.Rent(totalLength);

        try
        {
            // Length (2 bytes)
            buffer[0] = (byte)(totalLength >> 8);
            buffer[1] = (byte)(totalLength & 0xFF);

            // Message type
            buffer[2] = (byte)messageType;

            // Flags (reserved)
            buffer[3] = 0;

            // Payload
            Array.Copy(payload, 0, buffer, 4, payload.Length);

            await _stream.WriteAsync(buffer.AsMemory(0, totalLength), cancellationToken)
                .ConfigureAwait(false);
            await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _bufferPool.Return(buffer);
        }
    }

    private async Task<FailoverPeer?> LoadPeerConfigAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken)
                .ConfigureAwait(false);

            const string sql = @"
                SELECT id, name, role, peer_address, peer_port, local_address, local_port,
                       max_response_delay, max_unacked_updates, mclt, split, load_balance_max,
                       auto_partner_down, shared_secret, enabled
                FROM dhcp_failover_peers
                WHERE enabled = true
                LIMIT 1";

            await using var cmd = new NpgsqlCommand(sql, connection);
            await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

            if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                return new FailoverPeer
                {
                    Id = reader.GetGuid(0),
                    Name = reader.GetString(1),
                    Role = reader.GetString(2),
                    PeerAddress = (IPAddress)reader.GetValue(3),
                    PeerPort = reader.GetInt32(4),
                    LocalAddress = reader.IsDBNull(5) ? null : (IPAddress)reader.GetValue(5),
                    LocalPort = reader.GetInt32(6),
                    MaxResponseDelay = reader.GetInt32(7),
                    MaxUnackedUpdates = reader.GetInt32(8),
                    Mclt = reader.GetInt32(9),
                    Split = reader.GetInt32(10),
                    LoadBalanceMax = reader.GetInt32(11),
                    AutoPartnerDown = reader.IsDBNull(12) ? 0 : reader.GetInt32(12),
                    SharedSecret = reader.IsDBNull(13) ? null : reader.GetString(13),
                    Enabled = reader.GetBoolean(14)
                };
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load failover peer config");
            return null;
        }
    }

    private async Task PersistStateAsync(FailoverState state, CancellationToken cancellationToken)
    {
        if (_peerConfig == null) return;

        try
        {
            await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken)
                .ConfigureAwait(false);

            // Store state in a status table or update existing
            const string sql = @"
                INSERT INTO dhcp_failover_state (peer_id, state, updated_at)
                VALUES (@peerId, @state, NOW())
                ON CONFLICT (peer_id)
                DO UPDATE SET state = @state, updated_at = NOW()";

            await using var cmd = new NpgsqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("peerId", _peerConfig.Id);
            cmd.Parameters.AddWithValue("state", (int)state);

            await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to persist failover state");
        }
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _stateTimer?.Dispose();
        _client?.Dispose();
        _stream?.Dispose();
    }
}
