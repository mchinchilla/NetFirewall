using System.Buffers;
using NetFirewall.Models.Dhcp;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Pin the ownership contract of <see cref="DhcpResponseBuffer"/> — the struct
/// that replaced the old <c>Task&lt;byte[]&gt;</c> contract on
/// <c>IDhcpServerService.CreateDhcpResponseAsync</c> to skip the per-packet
/// new byte[N] copy. Bugs here would either leak rented buffers (silently
/// growing the pool) or double-return them (corrupting subsequent rentals).
/// </summary>
public class DhcpResponseBufferTests
{
    [Fact]
    public void Empty_HasZeroLength_IsEmptyTrue()
    {
        var buf = DhcpResponseBuffer.Empty;
        Assert.True(buf.IsEmpty);
        Assert.Equal(0, buf.Length);
        Assert.True(buf.Span.IsEmpty);
        Assert.True(buf.Memory.IsEmpty);
    }

    [Fact]
    public void Empty_DisposeIsNoOp_NoThrow()
    {
        // Worker uses `using var response = ...` regardless of whether the
        // service had something to say. Disposing an Empty buffer must NOT
        // throw — there's no rental to return.
        var buf = DhcpResponseBuffer.Empty;
        buf.Dispose();
        buf.Dispose(); // and again, just to be sure idempotency holds
    }

    [Fact]
    public void Span_LengthMatchesConstructorLength_NotBufferLength()
    {
        // Critical: ArrayPool may hand back a buffer larger than requested
        // (bucketed sizes). DhcpResponseBuffer must expose Length, not the
        // raw rental size — otherwise the worker would send 1024 bytes when
        // the response is only 280 bytes long.
        var buffer = new byte[1024];
        for (int i = 0; i < buffer.Length; i++) buffer[i] = (byte)(i & 0xFF);

        var buf = new DhcpResponseBuffer(buffer, length: 280, pool: null);

        Assert.Equal(280, buf.Length);
        Assert.Equal(280, buf.Span.Length);
        Assert.Equal(280, buf.Memory.Length);
        // Spot-check that the visible window is the prefix (not, say, the tail).
        Assert.Equal((byte)0, buf.Span[0]);
        Assert.Equal(unchecked((byte)279), buf.Span[279]); // 279 & 0xFF = 23
    }

    [Fact]
    public void Dispose_WithPool_ReturnsBufferToThatPool()
    {
        // Hooks a TrackingArrayPool so we can assert exactly one Return call
        // landed with the same buffer instance the constructor received.
        var pool = new TrackingPool();
        var buffer = pool.Rent(512);

        var buf = new DhcpResponseBuffer(buffer, length: 100, pool: pool);
        buf.Dispose();

        Assert.Single(pool.Returned);
        Assert.Same(buffer, pool.Returned[0]);
    }

    [Fact]
    public void Dispose_WithNullPool_DoesNotThrow()
    {
        // Tests construct buffers with pool=null (no real rental). Dispose
        // must skip the return path quietly so the test pattern stays simple.
        var buf = new DhcpResponseBuffer(new byte[10], length: 5, pool: null);
        buf.Dispose();
    }

    [Fact]
    public void IsEmpty_FalseWhenLengthGreaterThanZero()
    {
        var buf = new DhcpResponseBuffer(new byte[10], length: 1, pool: null);
        Assert.False(buf.IsEmpty);
    }

    private sealed class TrackingPool : ArrayPool<byte>
    {
        public List<byte[]> Returned { get; } = new();
        public override byte[] Rent(int minimumLength) => new byte[minimumLength];
        public override void Return(byte[] array, bool clearArray = false) => Returned.Add(array);
    }
}
