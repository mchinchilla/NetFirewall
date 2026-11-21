using System.Buffers.Binary;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Configuration;

namespace NetFirewall.Services.Dhcp;

/// <summary>
/// Token bucket per MAC in a fixed, direct-mapped table: <see cref="Slots"/> entries, picked by
/// a hash of the MAC. No allocation per packet, no global lock — several receive threads (one per
/// interface) share it, each slot guarded by a tiny spin flag. A slot owned by another MAC never
/// refuses anyone: the newcomer takes it over with a full bucket (fail open). The table can only
/// forget a client, never refuse one wrongly.
/// <para>
/// Defaults allow a burst of 20 packets, then 2 a second. That is generous: a full PXE → iPXE → OS
/// boot is three DORA exchanges (about 6 client packets) in a few seconds, and a normal client sends
/// one REQUEST per renewal.
/// </para>
/// </summary>
public sealed class DhcpMacRateLimiter : IDhcpRateLimiter
{
    public const int Slots = 4096;   // power of two; ~128 KB
    private const int SlotBits = 12;

    [StructLayout(LayoutKind.Sequential)]
    private struct Slot
    {
        public int Busy;        // 0 free, 1 a thread is updating it
        public ulong Key;       // MAC + 1 (0 = empty)
        public double Tokens;
        public long Stamp;      // TimeProvider timestamp of the last refill
    }

    private readonly Slot[] _slots = new Slot[Slots];
    private readonly TimeProvider _time;
    private readonly double _burst;
    private readonly double _perTick;   // tokens per timestamp tick
    private long _dropped;

    public DhcpMacRateLimiter(IConfiguration configuration, TimeProvider? time = null)
        : this(configuration.GetValue("Dhcp:RateLimit:Burst", 20), configuration.GetValue("Dhcp:RateLimit:PerSecond", 2.0), time)
    {
    }

    public DhcpMacRateLimiter(int burst, double perSecond, TimeProvider? time = null)
    {
        if (burst < 1) throw new ArgumentOutOfRangeException(nameof(burst), "Burst must be at least 1.");
        if (perSecond <= 0) throw new ArgumentOutOfRangeException(nameof(perSecond), "PerSecond must be positive.");
        _time = time ?? TimeProvider.System;
        _burst = burst;
        _perTick = perSecond / _time.TimestampFrequency;
    }

    public long Dropped => Interlocked.Read(ref _dropped);

    public bool TryAcquire(ReadOnlySpan<byte> mac)
    {
        if (mac.Length < 6) return true;
        var key = (((ulong)BinaryPrimitives.ReadUInt32BigEndian(mac) << 16) | BinaryPrimitives.ReadUInt16BigEndian(mac[4..])) + 1;
        ref var slot = ref _slots[(int)((key * 0x9E3779B97F4A7C15UL) >> (64 - SlotBits))];

        // The critical section is a handful of arithmetic ops: spin rather than fail open — under a
        // flood from one MAC on several interfaces, "busy = let it through" let most packets pass.
        var spin = new SpinWait();
        while (Interlocked.CompareExchange(ref slot.Busy, 1, 0) != 0) spin.SpinOnce(sleep1Threshold: -1);
        try
        {
            var now = _time.GetTimestamp();
            if (slot.Key != key)
            {
                // New client in this slot (or a hash neighbour): it starts with a full bucket.
                slot.Key = key;
                slot.Tokens = _burst - 1;
                slot.Stamp = now;
                return true;
            }

            slot.Tokens = Math.Min(_burst, slot.Tokens + (now - slot.Stamp) * _perTick);
            slot.Stamp = now;
            if (slot.Tokens >= 1)
            {
                slot.Tokens -= 1;
                return true;
            }
            Interlocked.Increment(ref _dropped);
            return false;
        }
        finally
        {
            Volatile.Write(ref slot.Busy, 0);
        }
    }
}
