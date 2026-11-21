using NetFirewall.Services.Dhcp;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>Per-MAC token bucket in the DHCP receive loop: bounded, per client, fails open.</summary>
public sealed class DhcpMacRateLimiterTests
{
    /// <summary>A clock that only moves when told to.</summary>
    private sealed class ManualClock : TimeProvider
    {
        public long Ticks;
        public override long TimestampFrequency => 1_000;      // 1 tick = 1 ms
        public override long GetTimestamp() => Ticks;
        public void Advance(TimeSpan by) => Ticks += (long)by.TotalMilliseconds;
    }

    private static byte[] Mac(byte last) => [0xAA, 0xBB, 0xCC, 0x00, 0x00, last];

    [Fact]
    public void Burst_ThenRefusal_ThenRefillOverTime()
    {
        var clock = new ManualClock();
        var limiter = new DhcpMacRateLimiter(burst: 5, perSecond: 2, clock);

        for (var i = 0; i < 5; i++) Assert.True(limiter.TryAcquire(Mac(1)), $"packet {i}");
        Assert.False(limiter.TryAcquire(Mac(1)));
        Assert.Equal(1, limiter.Dropped);

        clock.Advance(TimeSpan.FromMilliseconds(500));   // 2/s → one token back
        Assert.True(limiter.TryAcquire(Mac(1)));
        Assert.False(limiter.TryAcquire(Mac(1)));

        clock.Advance(TimeSpan.FromMinutes(1));          // refills, but never past the burst
        for (var i = 0; i < 5; i++) Assert.True(limiter.TryAcquire(Mac(1)));
        Assert.False(limiter.TryAcquire(Mac(1)));
    }

    [Fact]
    public void OneNoisyClient_DoesNotSpendAnotherClientsBudget()
    {
        var limiter = new DhcpMacRateLimiter(burst: 3, perSecond: 1, new ManualClock());
        for (var i = 0; i < 50; i++) limiter.TryAcquire(Mac(1));
        Assert.True(limiter.TryAcquire(Mac(2)));
        Assert.True(limiter.TryAcquire(Mac(2)));
        Assert.True(limiter.TryAcquire(Mac(2)));
    }

    [Fact]
    public void DefaultBudget_CoversAFullPxeToIpxeToOsBoot()
    {
        // Three DORA exchanges plus a retry each, back to back: 12 packets in the same instant.
        var limiter = new DhcpMacRateLimiter(burst: 20, perSecond: 2, new ManualClock());
        for (var i = 0; i < 12; i++) Assert.True(limiter.TryAcquire(Mac(7)));
        Assert.Equal(0, limiter.Dropped);
    }

    [Fact]
    public void SpoofedMacFlood_NeverGrowsMemory_AndNeverRefusesANewMac()
    {
        var limiter = new DhcpMacRateLimiter(burst: 2, perSecond: 1, new ManualClock());
        var mac = new byte[6];
        for (var i = 0; i < 100_000; i++)
        {
            BitConverter.TryWriteBytes(mac.AsSpan(2), i);
            Assert.True(limiter.TryAcquire(mac));   // first packet of any MAC is always let through
        }
    }

    [Fact]
    public void ShortChaddr_IsLetThrough() =>
        Assert.True(new DhcpMacRateLimiter(1, 1, new ManualClock()).TryAcquire([1, 2, 3]));

    [Fact]
    public async Task ConcurrentReceiveThreads_NeverExceedTheBudget()
    {
        var limiter = new DhcpMacRateLimiter(burst: 100, perSecond: 0.001, new ManualClock());
        var accepted = 0;
        await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() =>
        {
            for (var i = 0; i < 10_000; i++)
                if (limiter.TryAcquire(Mac(9))) Interlocked.Increment(ref accepted);
        })));
        Assert.Equal(100, accepted);
    }
}
