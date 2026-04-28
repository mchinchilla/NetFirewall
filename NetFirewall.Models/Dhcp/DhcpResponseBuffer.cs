using System;
using System.Buffers;

namespace NetFirewall.Models.Dhcp;

/// <summary>
/// Pool-aware container for an outbound DHCP response packet.
///
/// The previous <c>Task&lt;byte[]&gt;</c> contract on
/// <c>IDhcpServerService.CreateDhcpResponseAsync</c> forced the service to
/// rent from <see cref="ArrayPool{T}"/>, build the packet, then
/// <c>new byte[offset]</c>-copy to a right-sized array before returning the
/// rental — paying ~250-300B of GC pressure per response (≈ 1.5 MB/s at 5k
/// req/s sustained). This struct lets the rented buffer travel from service
/// to wire untouched: the consumer reads via <see cref="Span"/>/<see cref="Memory"/>
/// and calls <see cref="Dispose"/> (or uses <c>using</c>) once the send
/// completes to return it.
///
/// <para><b>Ownership rules:</b></para>
/// <list type="bullet">
///   <item>Producer rents from a pool, builds the packet, returns this struct
///   referencing the rental and the pool. Producer must NOT touch the buffer
///   after the struct is returned.</item>
///   <item>Consumer must call <see cref="Dispose"/> exactly once. After
///   disposal, <see cref="Span"/>/<see cref="Memory"/> must not be touched
///   (the buffer may already be re-rented by another caller).</item>
///   <item><see cref="IsEmpty"/> means "no response to send" (e.g. failover
///   declined, decline message, release). Disposing an empty buffer is a no-op.</item>
/// </list>
/// </summary>
public readonly struct DhcpResponseBuffer : IDisposable
{
    private readonly byte[]? _buffer;
    private readonly ArrayPool<byte>? _pool;

    public int Length { get; }

    public DhcpResponseBuffer(byte[] buffer, int length, ArrayPool<byte>? pool)
    {
        _buffer = buffer;
        Length = length;
        _pool = pool;
    }

    /// <summary>Sentinel meaning "no response to send".</summary>
    public static DhcpResponseBuffer Empty => default;

    public bool IsEmpty => Length == 0;

    public ReadOnlyMemory<byte> Memory =>
        _buffer is null ? ReadOnlyMemory<byte>.Empty : _buffer.AsMemory(0, Length);

    public ReadOnlySpan<byte> Span =>
        _buffer is null ? ReadOnlySpan<byte>.Empty : _buffer.AsSpan(0, Length);

    public void Dispose()
    {
        if (_pool is not null && _buffer is not null)
            _pool.Return(_buffer);
    }
}
